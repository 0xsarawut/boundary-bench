from __future__ import annotations

import json
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boundarybench.daytona.script_assets import render_daytona_script
from boundarybench.enforcement import (
    EnforcementConfig,
    compile_agentsh_policy,
    materialize_agentsh_policy,
)


REMOTE_AGENTSH_POLICY_ROOT = "/home/daytona/.boundarybench-agentsh"
REMOTE_AGENTSH_WORKSPACE_ROOT = "/home/daytona/boundarybench-runs"
AGENTSH_VERSION = "0.20.5"


class DaytonaAgentSHSessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class DaytonaAgentSHSession:
    session_id: str
    run_id: str
    config_id: str
    policy_name: str
    policy_digest: str
    remote_policy_dir: str
    remote_policy_path: str
    remote_config_path: str
    remote_workspace: str

    def to_metadata(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "config_id": self.config_id,
            "policy_name": self.policy_name,
            "policy_digest": self.policy_digest,
            "remote_policy_dir": self.remote_policy_dir,
            "remote_policy_path": self.remote_policy_path,
            "remote_config_path": self.remote_config_path,
            "remote_workspace": self.remote_workspace,
        }


@dataclass(frozen=True)
class _DaytonaCommandResult:
    exit_code: int | None
    stdout: str


def prepare_daytona_agentsh_session(
    sandbox: Any,
    *,
    config: EnforcementConfig,
    run_id: str,
    remote_policy_root: str = REMOTE_AGENTSH_POLICY_ROOT,
    remote_workspace_root: str = REMOTE_AGENTSH_WORKSPACE_ROOT,
) -> DaytonaAgentSHSession:
    """Upload an AgentSH policy/config into Daytona and create a session."""

    with tempfile.TemporaryDirectory(
        prefix="boundarybench-agentsh-policy-"
    ) as policy_dir:
        policy = materialize_agentsh_policy(
            compile_agentsh_policy(config, policy_dir=policy_dir)
        )
        remote_policy_dir = f"{remote_policy_root.rstrip('/')}/{run_id}"
        remote_workspace = f"{remote_workspace_root.rstrip('/')}/{run_id}"
        _controller_exec(
            sandbox,
            f"mkdir -p {shlex.quote(remote_policy_dir)} {shlex.quote(remote_workspace)}",
        )
        _ensure_agentsh_binary(sandbox)

        remote_policy_path = f"{remote_policy_dir}/{Path(policy.policy_path).name}"
        _upload_file(sandbox, policy.policy_path, remote_policy_path)

        remote_config_file = _remote_config_file(policy.config_path, remote_policy_dir)
        remote_config_path = f"{remote_policy_dir}/{Path(policy.config_path).name}"
        _upload_file(sandbox, str(remote_config_file), remote_config_path)

        _validate_policy(sandbox, remote_config_path, remote_policy_path)
        _ensure_agentsh_server(sandbox, remote_config_path)
        session_id = _create_session(
            sandbox,
            workspace=remote_workspace,
            policy_name=policy.policy_name,
        )

        return DaytonaAgentSHSession(
            session_id=session_id,
            run_id=run_id,
            config_id=config.config_id,
            policy_name=policy.policy_name,
            policy_digest=policy.policy_digest,
            remote_policy_dir=remote_policy_dir,
            remote_policy_path=remote_policy_path,
            remote_config_path=remote_config_path,
            remote_workspace=remote_workspace,
        )


def _upload_file(sandbox: Any, local_path: str, remote_path: str) -> None:
    sandbox.fs.upload_file(local_path, remote_path)


def _remote_config_file(local_config_path: str, remote_policy_dir: str) -> Path:
    local_config = Path(local_config_path)
    local_policy_dir = str(local_config.parent)
    text = local_config.read_text(encoding="utf-8").replace(
        local_policy_dir,
        remote_policy_dir.rstrip("/"),
    )
    remote_config = local_config.parent / f"remote-{local_config.name}"
    remote_config.write_text(text, encoding="utf-8")
    return remote_config


def _controller_exec(
    sandbox: Any,
    command: str,
    *,
    timeout: int = 30,
) -> _DaytonaCommandResult:
    result = sandbox.process.exec(command, timeout=timeout)
    return _DaytonaCommandResult(
        exit_code=getattr(result, "exit_code", None),
        stdout=getattr(result, "result", "") or "",
    )


def _validate_policy(sandbox: Any, config_path: str, policy_path: str) -> None:
    result = _controller_exec(
        sandbox,
        "/usr/bin/agentsh policy --config "
        f"{shlex.quote(config_path)} validate {shlex.quote(policy_path)} 2>&1",
        timeout=30,
    )
    if result.exit_code != 0:
        raise DaytonaAgentSHSessionError(
            f"AgentSH policy validation failed: {result.stdout}"
        )


def _ensure_agentsh_binary(sandbox: Any) -> None:
    command = render_daytona_script(
        "ensure_agentsh_binary.sh",
        {"AGENTSH_VERSION": shlex.quote(AGENTSH_VERSION)},
    )
    result = _controller_exec(sandbox, command, timeout=300)
    if result.exit_code != 0:
        raise DaytonaAgentSHSessionError(
            f"AgentSH binary was not available: {result.stdout}"
        )


def _ensure_agentsh_server(sandbox: Any, config_path: str) -> None:
    command = render_daytona_script(
        "ensure_agentsh_server.sh",
        {"CONFIG_PATH": shlex.quote(config_path)},
    )
    result = _controller_exec(sandbox, command, timeout=75)
    if result.exit_code != 0:
        raise DaytonaAgentSHSessionError(
            f"AgentSH server did not become ready: {result.stdout}"
        )


def _create_session(sandbox: Any, *, workspace: str, policy_name: str) -> str:
    command = (
        "/usr/bin/agentsh session create --json "
        f"--workspace {shlex.quote(workspace)} "
        f"--policy {shlex.quote(policy_name)}"
    )
    result = _controller_exec(sandbox, command, timeout=30)
    if result.exit_code != 0:
        raise DaytonaAgentSHSessionError(
            f"AgentSH session create failed: {result.stdout}"
        )
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise DaytonaAgentSHSessionError(
            f"AgentSH session output was not JSON: {result.stdout}"
        ) from exc
    session_id = payload.get("id")
    if not session_id:
        raise DaytonaAgentSHSessionError(
            f"AgentSH session output had no id: {result.stdout}"
        )
    return str(session_id)
