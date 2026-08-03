#!/usr/bin/env python3
"""Run Harbor's Terminus-2 loop inside the already-hardened task sandbox.

The outer boundarybench runner owns Daytona provisioning and policy setup.
This process owns only Terminus-2's in-sandbox model/terminal loop.  A tiny
local environment adapter keeps every tmux command in this process tree so the
native mount, network, privilege, and environment boundary applies unchanged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import shutil
import tempfile
from pathlib import Path

from harbor.agents.terminus_2 import Terminus2
from harbor.environments.base import ExecResult
from harbor.models.agent.context import AgentContext

from patches import ResilientTmuxSession


RESULT_PREFIX = "__TERMINUS_RESULT_PREFIX_PY__"
API_KEY_ENV = "__TERMINUS_API_KEY_ENV_PY__"
OPENROUTER_API_BASE = "__TERMINUS_OPENROUTER_API_BASE_PY__"
TERMINUS_SESSION_NAME = "__TERMINUS_SESSION_NAME_PY__"
VERSION_TEXT = "__TERMINUS_VERSION_TEXT_PY__"
PRESERVE_AGENT_SESSION_ENV = "BOUNDARYBENCH_PRESERVE_AGENT_SESSION"


class LocalSandboxEnvironment:
    """Subset of Harbor's environment API backed by local subprocesses."""

    def __init__(self, *, cwd: Path) -> None:
        self.cwd = cwd
        self.default_user = None
        self.session_id = "boundarybench-terminus-2"

    async def exec(
        self,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_sec: int | float | None = None,
        user: str | int | None = None,
    ) -> ExecResult:
        del user
        process_env = os.environ.copy()
        if env:
            process_env.update({str(k): str(v) for k, v in env.items()})
        proc = await asyncio.create_subprocess_exec(
            "/bin/bash.real",
            "-c",
            command,
            cwd=cwd or str(self.cwd),
            env=process_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout_sec) if timeout_sec else None
            )
        except TimeoutError:
            os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
            return ExecResult(stdout="", stderr="command timed out", return_code=124)
        return ExecResult(
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            return_code=int(proc.returncode or 0),
        )

    async def is_dir(self, path: str, user: str | int | None = None) -> bool:
        del user
        return Path(path).is_dir()

    async def upload_file(self, source_path: Path | str, target_path: str) -> None:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)

    async def download_file(self, source_path: str, target_path: Path | str) -> None:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)


class InSandboxTerminus2(Terminus2):
    """Terminus-2 with pane logs inside the writable harness carveout."""

    async def setup(self, environment: LocalSandboxEnvironment) -> None:
        self._session = ResilientTmuxSession(
            session_name=TERMINUS_SESSION_NAME,
            environment=environment,  # type: ignore[arg-type]
            logging_path=self.logs_dir / "terminus_2.pane",
            local_asciinema_recording_path=None,
            remote_asciinema_recording_path=None,
            pane_width=self._tmux_pane_width,
            pane_height=self._tmux_pane_height,
            extra_env=self._extra_env,
            user=environment.default_user,
        )
        await self._session.start()


def _preserve_agent_session() -> bool:
    return os.environ.get(PRESERVE_AGENT_SESSION_ENV, "").strip() == "1"


def _skills_dir() -> str:
    """Harbor Agent-Skills root: ``<skills_dir>/<name>/SKILL.md`` is discovered
    natively by Terminus2 and surfaced to the model as <available_skills>. The
    controller's recovery_bundle renderer writes the policy-error-recovery
    skill here; passing the directory is what makes recovery_bundle=on real
    for this harness."""

    return str(Path.home() / ".terminus-2" / "skills")


def _build_agent(*, logs_dir: Path, model_name: str, effort: str | None, api_key: str) -> InSandboxTerminus2:
    return InSandboxTerminus2(
        logs_dir=logs_dir,
        model_name=model_name,
        parser_name="json",
        api_base=OPENROUTER_API_BASE,
        reasoning_effort=effort,
        model_info={
            "litellm_provider": "openrouter",
            "mode": "chat",
            "supports_reasoning": True,
        },
        record_terminal_session=False,
        store_all_messages=False,
        skills_dir=_skills_dir(),
        llm_call_kwargs={
            "api_key": api_key,
            "extra_body": {"usage": {"include": True}},
        },
    )


async def _cleanup_tmux(environment: LocalSandboxEnvironment) -> None:
    try:
        await environment.exec(
            f"tmux kill-session -t {TERMINUS_SESSION_NAME} 2>/dev/null || true"
        )
    except OSError:
        pass


def _summary(logs_dir: Path, context: AgentContext) -> dict[str, object]:
    trajectory_path = logs_dir / "trajectory.json"
    assistant_turns = 0
    tool_calls = 0
    task_tool_calls = 0
    final_message = ""
    completion_pending = False
    task_complete = False
    if trajectory_path.is_file():
        try:
            trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            trajectory = {}
        for step in trajectory.get("steps") or []:
            if not isinstance(step, dict) or step.get("source") != "agent":
                continue
            assistant_turns += 1
            message = step.get("message")
            if isinstance(message, str) and message.strip():
                final_message = message.strip()
            calls = step.get("tool_calls")
            requested_completion = False
            if isinstance(calls, list):
                requested_completion = any(
                    isinstance(call, dict)
                    and call.get("function_name") == "mark_task_complete"
                    for call in calls
                )
                valid_calls = [call for call in calls if isinstance(call, dict)]
                tool_calls += len(valid_calls)
                task_tool_calls += sum(
                    call.get("function_name") != "mark_task_complete"
                    for call in valid_calls
                )
            task_complete = task_complete or (
                completion_pending and requested_completion
            )
            if requested_completion:
                completion_pending = True
            elif not _is_parse_feedback_step(step):
                completion_pending = False
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    return {
        "type": "terminus_2.result",
        "status": "ok",
        "assistant_turns": assistant_turns,
        "tool_calls": tool_calls,
        "task_tool_calls": task_tool_calls,
        "final_message": final_message,
        "task_complete": task_complete,
        "usage": {
            "input_tokens": int(context.n_input_tokens or 0),
            "output_tokens": int(context.n_output_tokens or 0),
            "cached_input_tokens": int(context.n_cache_tokens or 0),
            "cost_usd": context.cost_usd,
        },
        "n_episodes": int(metadata.get("n_episodes") or assistant_turns),
        "trajectory": str(trajectory_path),
    }


def _is_parse_feedback_step(step: dict[str, object]) -> bool:
    observation = step.get("observation")
    results = observation.get("results") if isinstance(observation, dict) else None
    if not isinstance(results, list):
        return False
    return any(
        isinstance(result, dict)
        and isinstance(result.get("content"), str)
        and result["content"].startswith("Previous response had parsing errors:")
        for result in results
    )


async def _run(args: argparse.Namespace) -> int:
    key = os.environ.pop(API_KEY_ENV, "")
    if not key:
        print(
            RESULT_PREFIX
            + json.dumps(
                {
                    "type": "terminus_2.result",
                    "status": "error",
                    "error_type": "RuntimeError",
                    "error": f"missing environment variable {API_KEY_ENV}",
                },
                sort_keys=True,
            )
        )
        return 1

    environment: LocalSandboxEnvironment | None = None
    try:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8")
        logs_dir = Path(args.logs_dir)
        logs_dir.mkdir(parents=True, exist_ok=True)
        environment = LocalSandboxEnvironment(cwd=Path.cwd())
        context = AgentContext()
        model_name = (
            args.model
            if args.model.startswith("openrouter/")
            else f"openrouter/{args.model}"
        )
        effort = "high" if args.effort == "default" else args.effort
        agent = _build_agent(
            logs_dir=logs_dir, model_name=model_name, effort=effort, api_key=key
        )

        await agent.setup(environment)  # type: ignore[arg-type]
        await agent.run(prompt, environment, context)  # type: ignore[arg-type]
        print(RESULT_PREFIX + json.dumps(_summary(logs_dir, context), sort_keys=True))
        return 0
    except BaseException as exc:
        detail = str(exc).replace(key, "[REDACTED]")
        result = {
            "type": "terminus_2.result",
            "status": "error",
            "error_type": type(exc).__name__,
            "error": detail[:4000],
        }
        print(RESULT_PREFIX + json.dumps(result, sort_keys=True))
        return 1
    finally:
        if environment is not None and not _preserve_agent_session():
            await _cleanup_tmux(environment)


async def _self_check(logs_dir: Path) -> int:
    logs_dir.mkdir(parents=True, exist_ok=True)
    environment = LocalSandboxEnvironment(cwd=Path.cwd())
    agent = InSandboxTerminus2(
        logs_dir=logs_dir,
        model_name="openrouter/openai/gpt-4o-mini",
        api_base=OPENROUTER_API_BASE,
        record_terminal_session=False,
        llm_call_kwargs={"api_key": "self-check-not-a-secret"},
    )
    try:
        await agent.setup(environment)  # type: ignore[arg-type]
        return 0
    finally:
        await _cleanup_tmux(environment)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version", action="version", version=VERSION_TEXT
    )
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--prompt-file")
    parser.add_argument("--logs-dir")
    parser.add_argument("--effort", default="high")
    args = parser.parse_args()
    if args.self_check:
        logs_dir = Path(args.logs_dir) if args.logs_dir else Path(
            tempfile.mkdtemp(prefix="terminus-2-self-check-")
        )
        return asyncio.run(_self_check(logs_dir))
    if not args.model or not args.prompt_file or not args.logs_dir:
        parser.error("--model, --prompt-file, and --logs-dir are required")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
