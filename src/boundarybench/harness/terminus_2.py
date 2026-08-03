"""Harbor Terminus-2 harness adapter for hardened Daytona execution."""

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

DAYTONA_TERMINUS_BIN = "/home/daytona/.local/bin/terminus-2-runner"
ROOT_TERMINUS_BIN = "/root/.local/bin/terminus-2-runner"
DAYTONA_TERMINUS_HOME = "/home/daytona/.terminus-2"
ROOT_TERMINUS_HOME = "/root/.terminus-2"
TERMINUS_API_KEY_ENV = "TERMINUS_OPENROUTER_API_KEY"
HARBOR_VERSION = "0.13.1"
TERMINUS_VERSION = "2.0.0"
PYTHON_VERSION = "3.12.11"
UV_VERSION = "0.11.16"
UV_SHA256_X86_64 = "1bc4be1be0a000f893b0d1db97906cf392b63fa22fda9a0ecf33d0d4bbb4bc9a"
UV_SHA256_AARCH64 = "ac022d96411143b9a2dd75ea711fa8dd4cd14538bf248f2e5df3c10a80f7f6a4"
RESULT_PREFIX = "TERMINUS2_RESULT "
TERMINUS_SESSION_NAME = "terminus-2"
OPENROUTER_ACCOUNTING_PROXY_URL = f"{OPENROUTER_BASE_URL}/v1"
TERMINUS_REQUIREMENTS_LOCK_PATH = "/tmp/boundarybench-terminus-2-requirements.lock"


_RUNTIME_PACKAGE = "boundarybench.harness.runtime.harbor_terminus_2"


@lru_cache(maxsize=1)
def _install_script() -> str:
    return files(_RUNTIME_PACKAGE).joinpath("install.sh").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _runner_script() -> str:
    return files(_RUNTIME_PACKAGE).joinpath("bridge.py").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _patches_script() -> str:
    return files(_RUNTIME_PACKAGE).joinpath("patches.py").read_text(encoding="utf-8")


def _render_runner_script() -> str:
    values = {
        "__TERMINUS_RESULT_PREFIX_PY__": RESULT_PREFIX,
        "__TERMINUS_API_KEY_ENV_PY__": TERMINUS_API_KEY_ENV,
        "__TERMINUS_OPENROUTER_API_BASE_PY__": OPENROUTER_ACCOUNTING_PROXY_URL,
        "__TERMINUS_SESSION_NAME_PY__": TERMINUS_SESSION_NAME,
        "__TERMINUS_VERSION_TEXT_PY__": (
            f"terminus-2 {TERMINUS_VERSION} (harbor {HARBOR_VERSION})"
        ),
    }
    rendered = _runner_script()
    for placeholder, value in values.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


@lru_cache(maxsize=1)
def _requirements_lock() -> str:
    return (
        files(_RUNTIME_PACKAGE).joinpath("requirements.lock").read_text(encoding="utf-8")
    )


def _result_records(stdout: str) -> tuple[list[dict[str, Any]], int]:
    valid: list[dict[str, Any]] = []
    malformed = 0
    for line in stdout.splitlines():
        if not line.startswith(RESULT_PREFIX):
            continue
        try:
            value = json.loads(line[len(RESULT_PREFIX) :])
        except json.JSONDecodeError:
            malformed += 1
            continue
        if isinstance(value, dict):
            valid.append(value)
        else:
            malformed += 1
    return valid, malformed


def _result_object(stdout: str) -> dict[str, Any] | None:
    """Return the last structured runner result, ignoring Harbor log noise."""

    valid, _ = _result_records(stdout)
    return valid[-1] if valid else None


def terminus_2_stream_diagnostics(stdout: str) -> dict[str, Any]:
    """Project the runner sentinel into the shared stdout diagnostics shape."""

    valid_results, malformed_result_lines = _result_records(stdout)
    result = valid_results[-1] if valid_results else None
    non_json_lines = sum(
        1
        for line in stdout.splitlines()
        if line.strip() and not line.startswith(RESULT_PREFIX)
    )
    usage = result.get("usage") if isinstance(result, dict) else None
    usage_present = isinstance(usage, dict) and any(
        int(usage.get(key) or 0)
        for key in ("input_tokens", "output_tokens", "cached_input_tokens")
    )
    result_present = result is not None
    return {
        "agent_stdout_parse_error_count": malformed_result_lines,
        "agent_stdout_non_json_line_count": non_json_lines,
        "agent_stdout_last_complete_event_type": (
            "terminus_2.result" if result_present else None
        ),
        "agent_stdout_truncated_or_malformed": malformed_result_lines > 0,
        "agent_stdout_result_event_present": result_present,
        "agent_stdout_final_result_event_present": result_present,
        "agent_stdout_result_event_missing": not result_present,
        "agent_stdout_result_event_usage_present": usage_present,
        "agent_model_usage_present": usage_present,
        "agent_model_usage_source": "result_event" if usage_present else "none",
        "agent_model_usage_recovered": False,
    }


class Terminus2Adapter:
    """Official Harbor Terminus-2 loop, executed wholly in the task sandbox."""

    @property
    def name(self) -> str:
        return "terminus_2"

    @property
    def api_key_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    @property
    def health_egress_domains(self) -> tuple[str, ...]:
        return ()

    @property
    def home_runtime_subdirs(self) -> tuple[str, ...]:
        return (".terminus-2",)

    @property
    def default_effort_level(self) -> str:
        return "high"

    @property
    def supported_effort_levels(self) -> tuple[str, ...]:
        return (
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        )

    @property
    def effort_level_applied(self) -> bool:
        return True

    def _home(self, *, run_as_root: bool) -> str:
        return ROOT_TERMINUS_HOME if run_as_root else DAYTONA_TERMINUS_HOME

    def runtime_layer_script(self, *, workdir: str, run_as_root: bool) -> str:
        del workdir
        terminus_bin = self.agent_binary_path(run_as_root=run_as_root)
        terminus_home = self._home(run_as_root=run_as_root)
        return (
            _install_script()
            .replace("__TERMINUS_BIN__", shlex.quote(terminus_bin))
            .replace("__TERMINUS_HOME__", shlex.quote(terminus_home))
            .replace("__RUN_AGENT_AS_ROOT__", "1" if run_as_root else "0")
            .replace("__HARBOR_VERSION__", HARBOR_VERSION)
            .replace("__PYTHON_VERSION__", PYTHON_VERSION)
            .replace("__UV_VERSION__", UV_VERSION)
            .replace("__UV_SHA256_X86_64__", UV_SHA256_X86_64)
            .replace("__UV_SHA256_AARCH64__", UV_SHA256_AARCH64)
            .replace("__TERMINUS_RUNNER_PY__", _render_runner_script().rstrip())
            .replace("__TERMINUS_PATCHES_PY__", _patches_script().rstrip())
        )

    def runtime_layer_assets(self, *, run_as_root: bool) -> dict[str, bytes]:
        del run_as_root
        return {TERMINUS_REQUIREMENTS_LOCK_PATH: _requirements_lock().encode("utf-8")}

    def agent_binary_path(self, *, run_as_root: bool) -> str:
        return ROOT_TERMINUS_BIN if run_as_root else DAYTONA_TERMINUS_BIN

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
        binary = self.agent_binary_path(run_as_root=run_as_root)
        logs_dir = f"{self._home(run_as_root=run_as_root)}/sessions/current"
        return (
            f"mkdir -p {shlex.quote(logs_dir)} && "
            f"{binary} --model {shlex.quote(model)} "
            f"--prompt-file {shlex.quote(prompt_path)} "
            f"--logs-dir {shlex.quote(logs_dir)} "
            f"--effort {shlex.quote(effort)} < /dev/null"
        )

    def agent_env(self, *, provider_api_key: str, run_as_root: bool) -> dict[str, str]:
        del run_as_root
        return {
            TERMINUS_API_KEY_ENV: provider_api_key,
            "PYTHONUNBUFFERED": "1",
        }

    def session_artifact_dirs(self, *, run_as_root: bool) -> tuple[str, ...]:
        return (f"{self._home(run_as_root=run_as_root)}/sessions",)

    def post_agent_cleanup_command(self, *, run_as_root: bool) -> str:
        """Controller-side fallback for a runner killed before its ``finally``."""

        tmux_cleanup = (
            f"tmux kill-session -t {shlex.quote(TERMINUS_SESSION_NAME)}"
            if run_as_root
            else (
                "sudo -H -u daytona -- tmux kill-session -t "
                f"{shlex.quote(TERMINUS_SESSION_NAME)}"
            )
        )
        return f"{tmux_cleanup} >/dev/null 2>&1 || true"

    @property
    def agent_metadata_name(self) -> str:
        return "terminus_2_openrouter"

    def activity_summary(self, agent_stdout: str) -> dict[str, int]:
        result = _result_object(agent_stdout) or {}
        turns = int(result.get("assistant_turns") or 0)
        tools = int(result.get("tool_calls") or 0)
        if turns == 0 and agent_stdout.strip() and result.get("status") != "error":
            turns = 1
        return {"assistant_turns": turns, "tool_calls": tools}

    def recovery_skill_invocation_count(self, agent_stdout: str) -> int:
        del agent_stdout
        return 0

    def blocked_surfaces(self, agent_stdout: str, *, policy: Any) -> list[Any]:
        del agent_stdout, policy
        return []

    def provider_auth_error(self, agent_stdout: str) -> Any | None:
        result = _result_object(agent_stdout) or {}
        if result.get("status") != "error":
            return None
        detail = str(result.get("error") or "")
        low = detail.casefold()
        markers = (
            "invalid_api_key",
            "invalid api key",
            "insufficient_quota",
            "unauthorized",
            "http 401",
            "401 unauthorized",
            "missing environment variable",
        )
        marker = next((value for value in markers if value in low), None)
        if marker is None:
            return None
        from boundarybench.terminalbench.daytona_transcript import (
            ProviderErrorInfo,
        )

        return ProviderErrorInfo(
            marker=marker,
            detail="terminus-2 provider/auth error in runner result",
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
        trace = self.canonical_trace(
            agent_stdout=agent_stdout,
            model=pricing_model or model,
            session_artifacts=session_artifacts,
        )
        return _terminus_trace_to_inspect(
            prompt=prompt,
            agent_stdout=agent_stdout,
            model=model,
            pricing_model=pricing_model,
            trace=trace,
        )

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
        del policy
        trace = self.canonical_trace(
            agent_stdout=agent_stdout,
            model=pricing_model or model,
            session_artifacts=session_artifacts,
            policy_events=policy_events,
        )
        return _render_terminus_trace_markdown(
            task_id=task_id,
            prompt=prompt,
            model=model,
            reward=reward,
            answer=answer,
            agent_stdout=agent_stdout,
            timed_out=timed_out,
            benchmark_status=benchmark_status,
            trace=trace,
        )

    def canonical_trace(
        self,
        *,
        agent_stdout: str,
        model: str,
        session_artifacts: dict[str, Any] | None,
        policy_events: list[dict[str, Any]] | None = None,
    ) -> Any:
        from boundarybench.harness.runtime.harbor_terminus_2.trace import (
            trace_from_terminus_2,
        )

        return trace_from_terminus_2(
            agent_stdout=agent_stdout,
            model=model,
            session_artifacts=session_artifacts,
            policy_events=policy_events,
        )


def _terminus_trace_to_inspect(
    *,
    prompt: str,
    agent_stdout: str,
    model: str,
    pricing_model: str,
    trace: Any,
) -> tuple[list[Any], Any]:
    """Render the ATIF trajectory as normal Inspect conversation messages."""

    from inspect_ai.model import (
        ChatMessageAssistant,
        ChatMessageTool,
        ChatMessageUser,
        ContentReasoning,
        ContentText,
        ModelOutput,
    )
    from inspect_ai.tool import ToolCall
    from boundarybench.terminalbench.daytona_transcript import (
        _usage_model_usage,
    )

    messages: list[Any] = [ChatMessageUser(content=prompt)]
    pending_reasoning: list[str] = []
    pending_text: list[str] = []
    pending_calls: list[Any] = []
    pending_timestamp: str | None = None
    tool_names: dict[str, str] = {}
    last_assistant_text = ""

    def flush_assistant() -> None:
        nonlocal pending_reasoning, pending_text, pending_calls, pending_timestamp
        if not (pending_reasoning or pending_text or pending_calls):
            return
        content: Any
        if pending_reasoning:
            content = [
                *(ContentReasoning(reasoning=value) for value in pending_reasoning),
                *(ContentText(text=value) for value in pending_text),
            ]
        else:
            content = "\n".join(pending_text)
        metadata = {"timestamp": pending_timestamp} if pending_timestamp else None
        messages.append(
            ChatMessageAssistant(
                content=content,
                tool_calls=pending_calls or None,
                model=model,
                metadata=metadata,
            )
        )
        pending_reasoning = []
        pending_text = []
        pending_calls = []
        pending_timestamp = None

    for event in trace.events:
        if event.type == "reasoning":
            if pending_reasoning or pending_text or pending_calls:
                flush_assistant()
            pending_timestamp = event.timestamp
        elif event.type == "assistant_message":
            if pending_text or pending_calls:
                flush_assistant()
            pending_timestamp = pending_timestamp or event.timestamp
        elif event.type == "tool_call":
            pending_timestamp = pending_timestamp or event.timestamp
        if event.type == "reasoning" and event.text:
            pending_reasoning.append(event.text)
        elif event.type == "assistant_message" and event.text:
            pending_text.append(event.text)
            last_assistant_text = event.text
        elif event.type == "tool_call":
            call_id = event.tool_call_id or f"terminus-tool-{event.seq}"
            tool_name = event.tool_name or "bash_command"
            tool_names[call_id] = tool_name
            pending_calls.append(
                ToolCall(
                    id=call_id,
                    function=tool_name,
                    arguments=(
                        event.arguments if isinstance(event.arguments, dict) else {}
                    ),
                )
            )
        elif event.type == "tool_result":
            flush_assistant()
            call_id = event.tool_call_id or f"terminus-tool-{event.seq}"
            metadata = {
                key: value
                for key, value in {
                    "timestamp": event.timestamp,
                    "status": event.status,
                    "exit_code": event.exit_code,
                    "is_error": event.is_error,
                }.items()
                if value is not None
            }
            messages.append(
                ChatMessageTool(
                    content=event.output or "",
                    tool_call_id=call_id,
                    function=tool_names.get(call_id),
                    metadata=metadata or None,
                )
            )
        elif event.type == "error":
            flush_assistant()
            error_text = event.message or "Terminus-2 runner failed"
            last_assistant_text = error_text
            metadata = {"timestamp": event.timestamp} if event.timestamp else None
            messages.append(
                ChatMessageAssistant(
                    content=error_text,
                    model=model,
                    metadata=metadata,
                )
            )
    flush_assistant()

    result = _result_object(agent_stdout) or {}
    final = str(result.get("final_message") or "").strip()
    if not final:
        final = trace.final_result or last_assistant_text
    if not final:
        final = str(result.get("error") or "").strip() or "(no output)"
    output = ModelOutput.from_content(model=model, content=final)
    usage = trace.usage if isinstance(trace.usage, dict) else {}
    output.usage = _usage_model_usage(
        pricing_model or model,
        {
            "input": int(usage.get("input_tokens") or 0),
            "output": int(usage.get("output_tokens") or 0),
            "cache_read": int(usage.get("cache_read_tokens") or 0),
            "cache_write": int(usage.get("cache_write_tokens") or 0),
        },
        input_includes_cache=True,
    )
    native_cost = usage.get("total_cost")
    if output.usage is not None and isinstance(native_cost, (int, float)):
        output.usage.total_cost = float(native_cost)
    return messages, output


def _render_terminus_trace_markdown(
    *,
    task_id: str,
    prompt: str,
    model: str,
    reward: Any,
    answer: Any,
    agent_stdout: str,
    timed_out: bool,
    benchmark_status: Any,
    trace: Any,
) -> str:
    """Render every captured ATIF turn, tool call, and result for review."""

    from boundarybench.harness.canonical_trace import _redact_secret_text
    from boundarybench.terminalbench.daytona_transcript import (
        _benchmark_status_fields,
        _fence,
        _status_from_benchmark_status,
        _truncate,
    )

    status_fields = _benchmark_status_fields(benchmark_status)
    status = _status_from_benchmark_status(status_fields)
    if status is None:
        if reward > 0:
            status = "✅ PASS"
        elif timed_out:
            status = "⏱️ TIMEOUT (agent cut at deadline)"
        elif answer == "ERROR":
            status = "⚠️ ERROR"
        else:
            status = "❌ FAIL"

    usage = trace.usage if isinstance(trace.usage, dict) else {}
    observability = trace.observability
    lines = [f"# Terminal-Bench — {task_id}", ""]
    lines.append("- **Harness:** Terminus-2")
    lines.append(f"- **Result:** {status} (reward={reward}, answer={answer})")
    if status_fields:
        lines.append(
            "- **Benchmark status:** "
            f"task_outcome={status_fields['task_outcome']} "
            f"failure_class={status_fields['failure_class']} "
            f"valid_for_analysis={status_fields['valid_for_analysis']}"
        )
    lines.append(f"- **Model (labelled):** {model}")
    if usage:
        cost = usage.get("total_cost")
        cost_text = f"${cost:.8f}" if isinstance(cost, (int, float)) else "unpriced"
        lines.append(
            "- **Usage:** "
            f"in={usage.get('input_tokens', 0)} "
            f"out={usage.get('output_tokens', 0)} "
            f"cache_read={usage.get('cache_read_tokens', 0)} "
            f"cache_write={usage.get('cache_write_tokens', 0)} cost={cost_text}"
        )
    lines.append(
        "- **Activity:** "
        f"{sum(event.type == 'assistant_message' for event in trace.events)} "
        "assistant turns, "
        f"{sum(event.type == 'tool_call' for event in trace.events)} tool calls"
    )
    lines.append(
        "- **Trace observability:** "
        f"source={observability.source} complete={str(observability.complete).lower()} "
        f"truncated={str(observability.truncated).lower()} "
        f"parse_errors={observability.parse_error_count} "
        f"redaction_applied={str(observability.redaction_applied).lower()}"
    )
    if observability.unobservable_fields:
        lines.append(
            "- **Unobservable fields:** "
            + ", ".join(f"`{value}`" for value in observability.unobservable_fields)
        )
    for note in observability.notes:
        lines.append(f"  - _{note}_")
    lines.append(
        "- **Native artifacts:** `trajectory.json` and `terminus_2.pane` are "
        "stored beside this transcript when captured."
    )

    blocks = [
        event
        for event in trace.policy_events
        if event.get("event_type") == "policy_block"
    ]
    lines += ["", f"## Policy blocks ({len(blocks)})", ""]
    if not blocks:
        lines.append("_No hardening-policy blocks were triggered._")
    else:
        for event in blocks:
            target = event.get("target") or event.get("command") or event.get("path")
            lines.append(
                f"- `{event.get('surface') or 'unknown'}` → "
                + (f"`{target}`" if target else "(no target)")
            )
            if event.get("snippet"):
                lines.append(f"  - {_truncate(str(event['snippet']))}")

    lines += ["", "## Prompt", "", _fence(prompt), "", "## Trace", ""]
    turn = 0
    pending_reasoning: list[str] = []

    def render_pending_reasoning() -> None:
        for reasoning in pending_reasoning:
            lines.extend(["**🧠 reasoning**", "", _fence(reasoning), ""])
        pending_reasoning.clear()

    for event in trace.events:
        if event.type == "reasoning":
            pending_reasoning.append(event.text or "")
        elif event.type == "assistant_message":
            turn += 1
            lines += [f"### Turn {turn} — assistant", ""]
            render_pending_reasoning()
            lines += [_truncate(event.text or ""), ""]
        elif event.type == "tool_call":
            render_pending_reasoning()
            arguments = event.arguments if isinstance(event.arguments, dict) else {}
            command = arguments.get("keystrokes")
            lines += [f"**🔧 tool call → `{event.tool_name or 'unknown'}`**", ""]
            lines.append(
                _fence(str(command), "bash")
                if command is not None
                else _fence(json.dumps(arguments, indent=2, ensure_ascii=False), "json")
            )
            lines.append("")
        elif event.type == "tool_result":
            render_pending_reasoning()
            label = "⛔ tool result (error)" if event.is_error else "↩︎ tool result"
            lines += [f"**{label}**", "", _fence(event.output or ""), ""]
        elif event.type == "error":
            render_pending_reasoning()
            lines += ["**⚠️ harness error**", "", _fence(event.message or ""), ""]

    render_pending_reasoning()
    if trace.final_result:
        lines += ["## Final result", "", _truncate(trace.final_result), ""]
    lines += [
        "## Terminus-2 runner result",
        "",
        _fence(_redact_secret_text(agent_stdout.strip())),
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"
