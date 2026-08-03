"""Codex CLI harness adapter for the BoundaryBench hardening pipeline.

Runs OpenAI's Codex CLI entirely inside the Daytona sandbox boundary, calling
OpenRouter's OpenAI-compatible endpoint directly (no host-side model bridge).
Codex is configured via a ``config.toml`` custom ``model_provider`` pointing at
OpenRouter with ``wire_api = "responses"`` — recent Codex removed the older
``chat`` wire protocol, and OpenRouter serves the OpenAI Responses API.

Transcript interpretation is intentionally minimal: the benchmark score comes
from the Harbor verifier, and policy blocks are captured by the harness-agnostic
policy event log, so this adapter only needs to avoid the solver's
zero-progress retry heuristic and surface the raw run for debugging.
"""

from __future__ import annotations

import json
import shlex
from functools import lru_cache
from importlib.resources import files
from typing import Any

from boundarybench.harness.adapter import normalize_effort_level
from boundarybench.harness.openrouter import (
    OPENROUTER_BASE_URL,
    validate_openrouter_model_id,
)

DAYTONA_CODEX_BIN = "/home/daytona/.local/bin/codex"
ROOT_CODEX_BIN = "/root/.local/bin/codex"
DAYTONA_CODEX_HOME = "/home/daytona/.codex"
ROOT_CODEX_HOME = "/root/.codex"

CODEX_VERSION = "rust-v0.142.5"

OPENROUTER_OPENAI_BASE_URL = f"{OPENROUTER_BASE_URL}/v1"

_CONFIG_TOML = f"""\
model_provider = "openrouter"
preferred_auth_method = "apikey"

[analytics]
enabled = false

# Codex's collaboration (sub-agent) tools are declared as a Responses-native
# "namespace" tool that OpenRouter's deepseek endpoints reject with 400
# ("No endpoints found that support the native `namespace` tool type",
# first seen 2026-07-12 — every turn failed before a single model call).
# Feature::Collab (TOML key: multi_agent) is Stable and default-ON at the
# pinned CODEX_VERSION, so it must be disabled explicitly. Sub-agent tools
# are also undesirable inside hardened benchmark sandboxes.
[features]
multi_agent = false

[model_providers.openrouter]
name = "OpenRouter"
base_url = "{OPENROUTER_OPENAI_BASE_URL}"
env_key = "CODEX_OPENROUTER_API_KEY"
wire_api = "responses"
"""


@lru_cache(maxsize=1)
def _install_script() -> str:
    return (
        files("boundarybench.harness")
        .joinpath("scripts", "install_codex.sh")
        .read_text(encoding="utf-8")
    )


class CodexAdapter:
    """Codex CLI via OpenRouter — runs the agent inside the sandbox boundary."""

    @property
    def name(self) -> str:
        return "codex"

    @property
    def api_key_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    @property
    def health_egress_domains(self) -> tuple[str, ...]:
        return ("chatgpt.com",)

    @property
    def home_runtime_subdirs(self) -> tuple[str, ...]:
        return (".codex",)

    @property
    def default_effort_level(self) -> str:
        return "high"

    @property
    def supported_effort_levels(self) -> tuple[str, ...]:
        return ("low", "medium", "high", "xhigh")

    @property
    def effort_level_applied(self) -> bool:
        return True

    def _codex_home(self, *, run_as_root: bool) -> str:
        return ROOT_CODEX_HOME if run_as_root else DAYTONA_CODEX_HOME

    def runtime_layer_script(self, *, workdir: str, run_as_root: bool) -> str:
        codex_bin = self.agent_binary_path(run_as_root=run_as_root)
        codex_home = self._codex_home(run_as_root=run_as_root)
        return (
            _install_script()
            .replace("__CODEX_BIN__", shlex.quote(codex_bin))
            .replace("__CODEX_HOME__", shlex.quote(codex_home))
            .replace("__CODEX_VERSION__", shlex.quote(CODEX_VERSION))
            .replace("__RUN_AGENT_AS_ROOT__", "1" if run_as_root else "0")
            .replace("__CODEX_CONFIG_TOML__", _CONFIG_TOML)
        )

    def agent_binary_path(self, *, run_as_root: bool) -> str:
        return ROOT_CODEX_BIN if run_as_root else DAYTONA_CODEX_BIN

    def agent_command(
        self,
        *,
        model: str,
        prompt_path: str,
        run_as_root: bool,
        effort_level: str | None = None,
    ) -> str:
        model = validate_openrouter_model_id(model)
        effort = normalize_effort_level(self, effort_level)
        codex_bin = self.agent_binary_path(run_as_root=run_as_root)
        effort_config = f'model_reasoning_effort="{effort}"'
        reasoning_capability_config = "model_supports_reasoning_summaries=true"
        return (
            f"{codex_bin} exec --color never --skip-git-repo-check --json "
            f"--model {shlex.quote(model)} "
            f"--config {shlex.quote(effort_config)} "
            f"--config {shlex.quote(reasoning_capability_config)} "
            "--enable unified_exec "
            "--dangerously-bypass-approvals-and-sandbox "
            f"- < {shlex.quote(prompt_path)}"
        )

    def agent_env(self, *, provider_api_key: str, run_as_root: bool) -> dict[str, str]:
        return {
            "CODEX_OPENROUTER_API_KEY": provider_api_key,
            "CODEX_HOME": self._codex_home(run_as_root=run_as_root),
            "RUST_LOG": "error",
        }

    def session_artifact_dirs(self, *, run_as_root: bool) -> tuple[str, ...]:
        return (f"{self._codex_home(run_as_root=run_as_root)}/sessions",)

    @property
    def agent_metadata_name(self) -> str:
        return "codex_openrouter"


    def activity_summary(self, agent_stdout: str) -> dict[str, int]:
        events = _parse_codex_events(agent_stdout)
        assistant_turns = sum(
            1 for e in events if _event_type(e) in _AGENT_MESSAGE_TYPES
        )
        tool_calls = sum(1 for e in events if _counts_as_tool_call(e))
        if assistant_turns == 0 and agent_stdout.strip():
            assistant_turns = 1
        return {"assistant_turns": assistant_turns, "tool_calls": tool_calls}

    def recovery_skill_invocation_count(self, agent_stdout: str) -> int:
        from boundarybench.terminalbench.recovery_skill import (
            RECOVERY_DOC_FILE,
            RECOVERY_SKILL_NAME,
        )

        needles = (RECOVERY_DOC_FILE, RECOVERY_SKILL_NAME)
        count = 0
        for event in _parse_codex_events(agent_stdout):
            if not _counts_as_tool_call(event):
                continue
            container = _event_container(event)
            command = container.get("command") or container.get("aggregated_command")
            if isinstance(command, str) and any(n in command for n in needles):
                count += 1
        return count

    def blocked_surfaces(self, agent_stdout: str, *, policy: Any) -> list[Any]:
        return []

    def provider_auth_error(self, agent_stdout: str) -> Any | None:
        from boundarybench.terminalbench.provider_error_markers import (
            PROVIDER_ERROR_MAX_TURNS,
        )

        if self.activity_summary(agent_stdout)["assistant_turns"] > PROVIDER_ERROR_MAX_TURNS:
            return None
        low = agent_stdout.lower()
        markers = (
            "invalid_api_key",
            "invalid api key",
            "insufficient_quota",
            "unauthorized",
            "http 401",
            "401 unauthorized",
            "missing environment variable",
        )
        marker = next((m for m in markers if m in low), None)
        if marker is None:
            return None
        from boundarybench.terminalbench.daytona_transcript import (
            ProviderErrorInfo,
        )

        return ProviderErrorInfo(
            marker=marker.strip(), detail="codex provider/auth error in stdout"
        )

    def parse_transcript(
        self,
        *,
        prompt: str,
        agent_stdout: str,
        model: str,
        pricing_model: str,
        session_artifacts: dict[str, Any] | None = None,
    ) -> tuple[list[Any], Any]:
        del session_artifacts
        from inspect_ai.model import ChatMessageAssistant, ChatMessageUser, ModelOutput

        from boundarybench.terminalbench.daytona_transcript import (
            _usage_model_usage,
        )

        final = _codex_final_message(agent_stdout) or agent_stdout.strip()
        messages = [
            ChatMessageUser(content=prompt),
            ChatMessageAssistant(content=final or "(no output)"),
        ]
        output = ModelOutput.from_content(model=model, content=final or "(no output)")
        output.usage = _usage_model_usage(
            pricing_model or model, codex_stream_usage(agent_stdout)
        )
        return messages, output

    def transcript_markdown(
        self,
        *,
        task_id: str,
        prompt: str,
        model: str,
        reward: Any,
        answer: Any,
        agent_stdout: str,
        timed_out: bool,
        policy: Any,
        pricing_model: str,
        benchmark_status: Any,
        policy_events: list[dict[str, Any]] | None,
        session_artifacts: dict[str, Any] | None = None,
    ) -> str:
        del session_artifacts
        block_count = sum(
            1
            for event in (policy_events or [])
            if event.get("event_type") == "policy_block"
        )
        lines = [
            f"# Codex transcript — {task_id}",
            "",
            f"- model: `{model}`",
            f"- reward: `{reward}`  answer: `{answer}`  timed_out: `{timed_out}`",
            f"- policy blocks: `{block_count}`",
            "",
            "## Prompt",
            "",
            "```",
            prompt.strip(),
            "```",
            "",
            "## Codex output",
            "",
            "```",
            agent_stdout.strip()[:20000],
            "```",
        ]
        return "\n".join(lines)

    def canonical_trace(
        self,
        *,
        agent_stdout: str,
        model: str,
        session_artifacts: dict[str, Any] | None,
        policy_events: list[dict[str, Any]] | None = None,
    ) -> Any:
        from boundarybench.harness.canonical_trace import trace_from_codex_events

        return trace_from_codex_events(
            agent_stdout=agent_stdout, model=model, policy_events=policy_events
        )


_AGENT_MESSAGE_TYPES = {"agent_message", "assistant_message", "message"}


def _parse_codex_events(stdout: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _event_container(event: dict[str, Any]) -> dict[str, Any]:
    """The sub-object carrying the semantic type/text.

    Codex's ``exec --json`` stream has drifted across releases between a flat
    shape (``{"type": ..., "message": ...}``), a ``msg``-wrapped shape
    (``{"msg": {"type": ..., "message": ...}}``), and an ``item``-wrapped shape
    (``{"type": "item.completed", "item": {"type": ..., "text": ...}}``). Pick
    the innermost dict so type and text are always read from the same object.
    """

    for key in ("item", "msg"):
        inner = event.get(key)
        if isinstance(inner, dict):
            return inner
    return event


def _event_type(event: dict[str, Any]) -> str:
    container = _event_container(event)
    for key in ("type", "msg_type"):
        value = container.get(key)
        if isinstance(value, str):
            return value
    return ""


def _event_text(event: dict[str, Any]) -> str | None:
    container = _event_container(event)
    text = container.get("message") or container.get("text")
    if isinstance(text, dict):
        text = text.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return None


def _counts_as_tool_call(event: dict[str, Any]) -> bool:
    """True once per command execution, across Codex's event shapes.

    Current Codex (item-wrapped) emits a ``command_execution`` item as a
    started/completed pair — count only the completion. Older builds emitted a
    flat ``exec_command_begin`` (+ ``_end`` / ``_output_delta``) — count only
    the begin (or a lone ``exec_command``).
    """

    container = _event_container(event)
    if container.get("type") == "command_execution":
        return event.get("type") == "item.completed" or container.get(
            "status"
        ) in {"completed", "failed"}
    event_type = _event_type(event)
    return event_type == "exec_command" or event_type.endswith("command_begin")


def _codex_final_message(stdout: str) -> str | None:
    final: str | None = None
    for event in _parse_codex_events(stdout):
        if _event_type(event) in _AGENT_MESSAGE_TYPES:
            text = _event_text(event)
            if text:
                final = text
    return final


USAGE_SOURCE_TURN_EVENTS = "turn_events"
USAGE_SOURCE_NONE = "none"

_CODEX_TERMINAL_TURN_TYPES = frozenset({"turn.completed", "turn.failed"})
_CODEX_TOKEN_COUNT_TYPE = "token_count"
_ZERO_USAGE = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}


def _codex_usage_from_obj(usage: Any) -> dict[str, int]:
    """Normalize a codex usage object to the shared {input,output,cache_*} shape.

    Codex names differ from Claude's: ``turn.*`` events and
    ``info.total_token_usage`` use ``input_tokens``/``output_tokens``/
    ``cached_input_tokens`` (plus ``reasoning_output_tokens``, which OpenAI
    already folds into ``output_tokens`` — so it is NOT re-added, matching
    harbor). Falls back to the OpenAI ``prompt_tokens``/``completion_tokens`` and
    the Claude cache names defensively.
    """

    if not isinstance(usage, dict):
        return dict(_ZERO_USAGE)

    def _int(*keys: str) -> int:
        for key in keys:
            try:
                value = int(usage.get(key) or 0)
            except (TypeError, ValueError):
                value = 0
            if value:
                return value
        return 0

    return {
        "input": _int("input_tokens", "prompt_tokens"),
        "output": _int("output_tokens", "completion_tokens"),
        "cache_read": _int(
            "cached_input_tokens", "cache_read_input_tokens", "cached_tokens"
        ),
        "cache_write": _int("cache_creation_input_tokens", "cache_write_tokens"),
    }


def _token_count_total_usage(event: dict[str, Any]) -> dict[str, Any] | None:
    info = _event_container(event).get("info")
    if isinstance(info, dict):
        total = info.get("total_token_usage")
        if isinstance(total, dict):
            return total
    return None


def _codex_usage_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    """Best-effort per-run token usage from a codex `--json` event list.

    Prefers the cumulative ``token_count.info.total_token_usage`` total (the
    harbor-authoritative source; last one wins because it is a running total),
    else the last ``turn.*`` event's ``usage``. Zero when neither is present.
    """

    token_count_usage: dict[str, int] | None = None
    turn_usage: dict[str, int] | None = None
    for event in events:
        etype = _event_type(event)
        if etype == _CODEX_TOKEN_COUNT_TYPE:
            counts = _codex_usage_from_obj(_token_count_total_usage(event))
            if any(counts.values()):
                token_count_usage = counts
        elif etype in _CODEX_TERMINAL_TURN_TYPES:
            counts = _codex_usage_from_obj(_event_container(event).get("usage"))
            if any(counts.values()):
                turn_usage = counts
    return token_count_usage or turn_usage or dict(_ZERO_USAGE)


def codex_stream_usage(agent_stdout: str) -> dict[str, int]:
    """Normalized per-run token usage parsed from codex `--json` stdout."""

    return _codex_usage_counts(_parse_codex_events(agent_stdout))


def codex_stream_diagnostics(agent_stdout: str) -> dict[str, Any]:
    """Codex-dialect counterpart of ``claude_stream_diagnostics``.

    Same metadata keys (same BigQuery columns), honest codex semantics: the
    "result event" is codex's terminal turn event (``turn.completed``); usage is
    read from ``turn.*`` / ``token_count`` events; and the harness-agnostic
    line-scan fields (``parse_error_count``, ``non_json_line_count``,
    ``last_complete_event_type``, ``truncated_or_malformed``) come from the
    shared scanner so they match the Claude path exactly.
    """

    from boundarybench.terminalbench.daytona_transcript import _scan_json_stream

    scan = _scan_json_stream(agent_stdout)
    events = scan.events
    turn_completed = [
        event for event in events if _event_type(event) == "turn.completed"
    ]
    result_event_present = bool(turn_completed)
    result_event_usage_present = any(
        any(_codex_usage_from_obj(_event_container(event).get("usage")).values())
        for event in turn_completed
    )
    usage_counts = _codex_usage_counts(events)
    usage_present = any(usage_counts.values())
    usage_source = USAGE_SOURCE_TURN_EVENTS if usage_present else USAGE_SOURCE_NONE
    return {
        "agent_stdout_parse_error_count": scan.parse_error_count,
        "agent_stdout_non_json_line_count": scan.non_json_line_count,
        "agent_stdout_last_complete_event_type": scan.last_complete_event_type,
        "agent_stdout_truncated_or_malformed": scan.parse_error_count > 0,
        "agent_stdout_result_event_present": result_event_present,
        "agent_stdout_final_result_event_present": result_event_present,
        "agent_stdout_result_event_missing": not result_event_present,
        "agent_stdout_result_event_usage_present": result_event_usage_present,
        "agent_model_usage_present": usage_present,
        "agent_model_usage_source": usage_source,
        "agent_model_usage_recovered": usage_present and not result_event_present,
    }
