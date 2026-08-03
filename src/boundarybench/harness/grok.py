"""Grok Build CLI harness adapter for the BoundaryBench hardening pipeline.

Runs xAI's Grok Build CLI entirely inside the Daytona sandbox boundary, calling
OpenRouter's OpenAI-compatible endpoint directly (no host-side model bridge).
Grok is pointed at OpenRouter the same way the Codex adapter is: a provider
block in ``config.toml`` with ``base_url`` -> OpenRouter, ``api_backend =
"chat_completions"``, and ``env_key`` reading the injected OpenRouter key — not
the ``GROK_MODELS_BASE_URL``/``XAI_API_KEY`` catalog-endpoint route. Because
grok's provider block is model-specific, ``agent_command`` writes the block for
the run's model, and ``GROK_HOME`` pins the config directory.

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

DAYTONA_GROK_BIN = "/home/daytona/.local/bin/grok"
ROOT_GROK_BIN = "/root/.local/bin/grok"
DAYTONA_GROK_HOME = "/home/daytona/.grok"
ROOT_GROK_HOME = "/root/.grok"

GROK_VERSION = "0.2.87"

OPENROUTER_OPENAI_BASE_URL = f"{OPENROUTER_BASE_URL}/v1"

GROK_API_KEY_ENV = "GROK_OPENROUTER_API_KEY"

_BASE_CONFIG_TOML = """\
[cli]
auto_update = false

[features]
telemetry = false
feedback = false
"""


@lru_cache(maxsize=1)
def _install_script() -> str:
    return (
        files("boundarybench.harness")
        .joinpath("scripts", "install_grok.sh")
        .read_text(encoding="utf-8")
    )


class GrokAdapter:
    """Grok Build CLI via OpenRouter — runs the agent inside the sandbox boundary."""

    @property
    def name(self) -> str:
        return "grok"

    @property
    def api_key_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    @property
    def health_egress_domains(self) -> tuple[str, ...]:
        return ()

    @property
    def home_runtime_subdirs(self) -> tuple[str, ...]:
        return (".grok",)

    @property
    def default_effort_level(self) -> str:
        return "high"

    @property
    def supported_effort_levels(self) -> tuple[str, ...]:
        return ("low", "medium", "high")

    @property
    def effort_level_applied(self) -> bool:
        return True

    def _grok_home(self, *, run_as_root: bool) -> str:
        return ROOT_GROK_HOME if run_as_root else DAYTONA_GROK_HOME

    def runtime_layer_script(self, *, workdir: str, run_as_root: bool) -> str:
        grok_bin = self.agent_binary_path(run_as_root=run_as_root)
        grok_home = self._grok_home(run_as_root=run_as_root)
        return (
            _install_script()
            .replace("__GROK_BIN__", shlex.quote(grok_bin))
            .replace("__GROK_HOME__", shlex.quote(grok_home))
            .replace("__GROK_VERSION__", shlex.quote(GROK_VERSION))
            .replace("__RUN_AGENT_AS_ROOT__", "1" if run_as_root else "0")
            .replace("__GROK_CONFIG_TOML__", _BASE_CONFIG_TOML)
        )

    def agent_binary_path(self, *, run_as_root: bool) -> str:
        return ROOT_GROK_BIN if run_as_root else DAYTONA_GROK_BIN

    def _run_config_toml(self, model: str, *, effort_level: str) -> str:
        return (
            _BASE_CONFIG_TOML
            + f'\n[models]\ndefault = "{model}"\n'
            + f'\n[model."{model}"]\n'
            + f'model = "{model}"\n'
            + f'base_url = "{OPENROUTER_OPENAI_BASE_URL}"\n'
            + 'name = "Grok via OpenRouter"\n'
            + f'env_key = "{GROK_API_KEY_ENV}"\n'
            + 'api_backend = "responses"\n'
            + "context_window = 256000\n"
            + "supports_reasoning_effort = true\n"
            + f'reasoning_effort = "{effort_level}"\n'
        )

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
        grok_bin = self.agent_binary_path(run_as_root=run_as_root)
        grok_home = self._grok_home(run_as_root=run_as_root)
        config_path = f"{grok_home}/config.toml"
        config = self._run_config_toml(model, effort_level=effort)
        return (
            f"mkdir -p {shlex.quote(grok_home)} && "
            f"printf '%s' {shlex.quote(config)} > {shlex.quote(config_path)} && "
            f"{grok_bin} --prompt-file {shlex.quote(prompt_path)} "
            f"--model {shlex.quote(model)} "
            "--output-format json --always-approve < /dev/null"
        )

    def agent_env(self, *, provider_api_key: str, run_as_root: bool) -> dict[str, str]:
        return {
            GROK_API_KEY_ENV: provider_api_key,
            "GROK_HOME": self._grok_home(run_as_root=run_as_root),
            "RUST_LOG": "error",
        }

    def session_artifact_dirs(self, *, run_as_root: bool) -> tuple[str, ...]:
        return (f"{self._grok_home(run_as_root=run_as_root)}/sessions",)

    @property
    def agent_metadata_name(self) -> str:
        return "grok_openrouter"


    def activity_summary(self, agent_stdout: str) -> dict[str, int]:
        assistant_turns = 1 if agent_stdout.strip() else 0
        return {"assistant_turns": assistant_turns, "tool_calls": 0}

    def recovery_skill_invocation_count(self, agent_stdout: str) -> int:
        return 0

    def blocked_surfaces(self, agent_stdout: str, *, policy: Any) -> list[Any]:
        return []

    def provider_auth_error(self, agent_stdout: str) -> Any | None:
        if _grok_final_text(agent_stdout):
            return None
        obj = _parse_grok_json(agent_stdout)
        is_error_obj = isinstance(obj, dict) and obj.get("type") == "error"
        low = agent_stdout.lower()
        markers = (
            "invalid_api_key",
            "invalid api key",
            "insufficient_quota",
            "unauthorized",
            "http 401",
            "401 unauthorized",
            "no auth credentials",
        )
        marker = next((m for m in markers if m in low), None)
        if not is_error_obj and marker is None:
            return None
        from boundarybench.terminalbench.daytona_transcript import (
            ProviderErrorInfo,
        )

        return ProviderErrorInfo(
            marker=(marker or "error").strip(),
            detail="grok provider/auth error in stdout",
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

        final = _grok_final_text(agent_stdout) or agent_stdout.strip()
        messages = [
            ChatMessageUser(content=prompt),
            ChatMessageAssistant(content=final or "(no output)"),
        ]
        output = ModelOutput.from_content(model=model, content=final or "(no output)")
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
            f"# Grok transcript — {task_id}",
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
            "## Grok output",
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
        from boundarybench.harness.canonical_trace import trace_from_grok

        return trace_from_grok(
            agent_stdout=agent_stdout,
            model=model,
            session_artifacts=session_artifacts,
            policy_events=policy_events,
        )


def _parse_grok_json(stdout: str) -> dict[str, Any] | None:
    """Parse grok's single ``--output-format json`` object.

    Tolerates leading/trailing noise (e.g. a stray log line) by falling back to
    the substring between the first ``{`` and the last ``}`` when a plain
    ``json.loads`` fails. Returns ``None`` when no object can be recovered.
    """

    text = stdout.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        obj = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _grok_final_text(stdout: str) -> str | None:
    """The final assistant message: the top-level ``text`` field, if present."""

    obj = _parse_grok_json(stdout)
    if isinstance(obj, dict):
        text = obj.get("text")
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None
