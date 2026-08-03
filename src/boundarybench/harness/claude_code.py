"""Claude Code harness adapter for the BoundaryBench hardening pipeline.

Extracts Claude Code-specific behavior from the Terminal-Bench Daytona runner
into the ``HarnessAdapter`` protocol so the same hardening pipeline can wrap
any supported agent harness.
"""

from __future__ import annotations

import re
import shlex
from functools import lru_cache
from importlib.resources import files
from typing import Any

from boundarybench.harness.adapter import normalize_effort_level
from boundarybench.harness.openrouter import (
    OPENROUTER_BASE_URL,
    validate_openrouter_model_id,
)

DAYTONA_CLAUDE_BIN = "/home/daytona/.local/bin/claude"
ROOT_CLAUDE_BIN = "/root/.local/bin/claude"

CLAUDE_CODE_VERSION = "2.1.206"

_CLAUDE_CODE_VERSION_RE = re.compile(
    r"^(?:stable|latest|\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)$"
)


def _validated_claude_code_version() -> str:
    if not _CLAUDE_CODE_VERSION_RE.fullmatch(CLAUDE_CODE_VERSION):
        raise ValueError(
            "CLAUDE_CODE_VERSION must be 'stable', 'latest', or a semver with "
            f"a [A-Za-z0-9._-] suffix; got {CLAUDE_CODE_VERSION!r}"
        )
    return CLAUDE_CODE_VERSION


@lru_cache(maxsize=1)
def _install_script() -> str:
    return (
        files("boundarybench.harness")
        .joinpath("scripts", "install_claude_code.sh")
        .read_text(encoding="utf-8")
    )


class ClaudeCodeAdapter:
    """Claude Code via OpenRouter — production harness adapter.

    Runs Claude Code entirely inside the Daytona sandbox boundary, as every
    registered harness must.
    """

    @property
    def name(self) -> str:
        return "claude_code"

    @property
    def api_key_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    @property
    def health_egress_domains(self) -> tuple[str, ...]:
        return ("api.anthropic.com",)

    @property
    def home_runtime_subdirs(self) -> tuple[str, ...]:
        return (".claude",)

    @property
    def default_effort_level(self) -> str:
        return "high"

    @property
    def supported_effort_levels(self) -> tuple[str, ...]:
        return ("low", "medium", "high", "xhigh", "max")

    @property
    def effort_level_applied(self) -> bool:
        return True

    def runtime_layer_script(
        self,
        *,
        workdir: str,
        run_as_root: bool,
    ) -> str:
        claude_bin = ROOT_CLAUDE_BIN if run_as_root else DAYTONA_CLAUDE_BIN
        return (
            _install_script()
            .replace("__CLAUDE_BIN__", shlex.quote(claude_bin))
            .replace("__RUN_AGENT_AS_ROOT__", "1" if run_as_root else "0")
            .replace("__CLAUDE_CODE_VERSION__", _validated_claude_code_version())
        )

    def agent_binary_path(self, *, run_as_root: bool) -> str:
        return ROOT_CLAUDE_BIN if run_as_root else DAYTONA_CLAUDE_BIN

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
        claude_bin = self.agent_binary_path(run_as_root=run_as_root)
        permission_args = (
            "--dangerously-skip-permissions"
            if run_as_root
            else "--permission-mode bypassPermissions"
        )
        return (
            f"{claude_bin} --model {shlex.quote(model)} {permission_args} "
            f"--effort {shlex.quote(effort)} "
            "--verbose --output-format stream-json "
            f'-p -- "$(cat {shlex.quote(prompt_path)})" < /dev/null'
        )

    def agent_env(self, *, provider_api_key: str, run_as_root: bool) -> dict[str, str]:
        env = {
            "ANTHROPIC_BASE_URL": OPENROUTER_BASE_URL,
            "ANTHROPIC_AUTH_TOKEN": provider_api_key,
        }
        if run_as_root:
            env["IS_SANDBOX"] = "1"
        return env

    def session_artifact_dirs(self, *, run_as_root: bool) -> tuple[str, ...]:
        return ()

    @property
    def agent_metadata_name(self) -> str:
        return "claude_code_openrouter"


    def activity_summary(self, agent_stdout: str) -> dict[str, int]:
        from boundarybench.terminalbench.daytona_transcript import (
            stream_activity_summary,
        )

        return stream_activity_summary(agent_stdout)

    def recovery_skill_invocation_count(self, agent_stdout: str) -> int:
        from boundarybench.terminalbench.daytona_transcript import (
            count_recovery_skill_invocations,
        )

        return count_recovery_skill_invocations(agent_stdout)

    def blocked_surfaces(self, agent_stdout: str, *, policy: Any) -> list[Any]:
        from boundarybench.terminalbench.daytona_transcript import (
            extract_blocked_surfaces,
        )

        return extract_blocked_surfaces(agent_stdout, policy=policy)

    def provider_auth_error(self, agent_stdout: str) -> Any | None:
        from boundarybench.terminalbench.daytona_transcript import (
            detect_provider_auth_error,
        )

        return detect_provider_auth_error(agent_stdout)

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
        from boundarybench.terminalbench.daytona_transcript import (
            claude_transcript_to_inspect,
        )

        return claude_transcript_to_inspect(
            prompt=prompt,
            agent_stdout=agent_stdout,
            model=model,
            pricing_model=pricing_model,
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
        del session_artifacts
        from boundarybench.terminalbench.daytona_transcript import (
            render_task_transcript_markdown,
        )

        return render_task_transcript_markdown(
            task_id=task_id,
            prompt=prompt,
            model=model,
            reward=reward,
            answer=answer,
            agent_stdout=agent_stdout,
            timed_out=timed_out,
            policy=policy,
            pricing_model=pricing_model,
            benchmark_status=benchmark_status,
            policy_events=policy_events,
        )

    def canonical_trace(
        self,
        *,
        agent_stdout: str,
        model: str,
        session_artifacts: dict[str, Any] | None,
        policy_events: list[dict[str, Any]] | None = None,
    ) -> Any:
        from boundarybench.harness.canonical_trace import trace_from_claude_stream

        return trace_from_claude_stream(
            agent_stdout=agent_stdout, model=model, policy_events=policy_events
        )
