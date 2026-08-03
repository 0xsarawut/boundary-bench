from __future__ import annotations

import argparse
import json
import shlex
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boundarybench.daytona.config import (
    daytona_policy_block_message_from_env,
    daytona_resource_profile_from_env,
    daytona_snapshot_from_env,
    read_daytona_policy_block_message_file,
    require_minimal_profile,
)
from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    install_daytona_policy_hardening,
    run_with_daytona_policy_hardening,
)
from boundarybench.daytona.hardening_config import (
    DEFAULT_DAYTONA_HARDENING_CONFIG,
    DaytonaHardeningConfig,
    load_daytona_hardening_config,
)
from boundarybench.daytona.script_assets import (
    read_daytona_script,
    render_daytona_script,
)
from boundarybench.enforcement import (
    compile_agentsh_policy,
    get_enforcement_config,
    materialize_agentsh_policy,
)
from boundarybench.policy_surfaces import (
    REQUIRED_POLICY_SURFACE_PROBES,
    ProbeExecution,
    ProbeResult,
    evaluate_probe,
    policy_surface_suite_passed,
)
try:
    from boundarybench.policy_surfaces.markers import (
        contains_policy_blocked_output_marker as _contains_policy_marker,
    )
except ImportError:  # pragma: no cover - compatibility with marker export changes
    from boundarybench.policy_surfaces.markers import (
        contains_blocked_output_marker as _contains_policy_marker,
    )
from boundarybench.policy_surfaces.report import write_policy_surface_report


REMOTE_POLICY_DIR = "/home/daytona/.boundarybench-agentsh"
REMOTE_WORKSPACE_ROOT = "/home/daytona/boundarybench-runs"
DEFAULT_CONFIG_ID = "agentsh_sev1_fixture"
DAYTONA_READY_MAX_ATTEMPTS = 36
DAYTONA_READY_POLL_SECONDS = 5
DAYTONA_READY_EXEC_TIMEOUT_SECONDS = 5


class DaytonaPolicySuiteError(RuntimeError):
    pass


@dataclass(frozen=True)
class DaytonaCommandResult:
    exit_code: int | None
    stdout: str
    stderr: str = ""


@dataclass(frozen=True)
class DaytonaPolicySuiteResult:
    sandbox_id: str
    snapshot: str
    session_id: str
    run_id: str
    passed: bool
    results: tuple[ProbeResult, ...]
    artifact_path: Path | None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "snapshot": self.snapshot,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "passed": self.passed,
            "artifact_path": str(self.artifact_path) if self.artifact_path else None,
            "results": [result.to_metadata() for result in self.results],
        }


def run_daytona_policy_surface_suite(
    *,
    snapshot: str | None = None,
    config_id: str = DEFAULT_CONFIG_ID,
    policy_block_message: str | None = None,
    hardening_config: DaytonaHardeningConfig | None = None,
    artifact_dir: Path | None = None,
    keep_sandbox: bool = False,
    allow_resource_override: bool = False,
    create_timeout_seconds: int = 300,
    create_retries: int = 2,
) -> DaytonaPolicySuiteResult:
    """Run the full policy-surface gate in a live Daytona sandbox."""

    selected_snapshot = snapshot or daytona_snapshot_from_env()
    resources = daytona_resource_profile_from_env()
    require_minimal_profile(
        selected_snapshot,
        resources,
        allow_override=allow_resource_override,
    )
    selected_hardening_config = hardening_config or DEFAULT_DAYTONA_HARDENING_CONFIG
    if policy_block_message is not None:
        selected_hardening_config = selected_hardening_config.with_block_message(
            policy_block_message
        )
    elif hardening_config is None:
        selected_hardening_config = selected_hardening_config.with_block_message(
            daytona_policy_block_message_from_env()
        )
    daytona = _daytona_client()
    sandbox = None
    run_id = _run_id()
    artifact_path = None
    try:
        sandbox = _create_sandbox(
            daytona,
            selected_snapshot,
            timeout_seconds=create_timeout_seconds,
            retries=create_retries,
        )
        sandbox_id = str(getattr(sandbox, "id", "unknown"))
        _wait_ready(daytona, sandbox)
        config = get_enforcement_config(config_id)
        policy_dir = Path(tempfile.mkdtemp(prefix="boundarybench-policy-"))
        policy = materialize_agentsh_policy(
            compile_agentsh_policy(config, policy_dir=str(policy_dir))
        )
        remote_policy_dir = f"{REMOTE_POLICY_DIR}/{run_id}"
        remote_workspace = f"{REMOTE_WORKSPACE_ROOT}/{run_id}"
        _controller_exec(sandbox, f"mkdir -p {shlex.quote(remote_policy_dir)} {shlex.quote(remote_workspace)}")
        _upload_file(sandbox, policy.policy_path, f"{remote_policy_dir}/{Path(policy.policy_path).name}")
        remote_config_file = _remote_config_file(policy.config_path, remote_policy_dir)
        _upload_file(sandbox, str(remote_config_file), f"{remote_policy_dir}/{Path(policy.config_path).name}")
        remote_config_path = f"{remote_policy_dir}/{Path(policy.config_path).name}"
        remote_policy_name = policy.policy_name
        _validate_policy(sandbox, remote_config_path, f"{remote_policy_dir}/{Path(policy.policy_path).name}")
        _ensure_agentsh_server(sandbox, remote_config_path)
        session_id = _create_session(sandbox, remote_workspace, remote_policy_name)
        _prepare_surface_fixtures(sandbox)
        daytona_policy_hardening = install_daytona_policy_hardening(
            sandbox,
            f"{remote_policy_dir}/daytona-policy-hardening",
            hardening_config=selected_hardening_config,
        )

        results = tuple(
            _run_probe(
                sandbox=sandbox,
                session_id=session_id,
                workspace=remote_workspace,
                daytona_policy_hardening=daytona_policy_hardening,
                probe=probe,
            )
            for probe in REQUIRED_POLICY_SURFACE_PROBES
        )
        passed = policy_surface_suite_passed(results)
        if artifact_dir is not None:
            artifact_path = artifact_dir / f"{run_id}-policy-surface-report.json"
            write_policy_surface_report(
                artifact_path,
                metadata={
                    "run_id": run_id,
                    "sandbox_id": sandbox_id,
                    "snapshot": selected_snapshot,
                    "resources": resources.to_metadata(),
                    "config_id": config_id,
                    "policy": policy.to_metadata(),
                    "daytona_policy_hardening": daytona_policy_hardening.to_metadata(),
                },
                results=results,
            )
        return DaytonaPolicySuiteResult(
            sandbox_id=sandbox_id,
            snapshot=selected_snapshot,
            session_id=session_id,
            run_id=run_id,
            passed=passed,
            results=results,
            artifact_path=artifact_path,
        )
    finally:
        if sandbox is not None and not keep_sandbox:
            _delete_sandbox(daytona, sandbox)


def _run_probe(
    *,
    sandbox: Any,
    session_id: str,
    workspace: str,
    daytona_policy_hardening: DaytonaPolicyHardening,
    probe,
) -> ProbeResult:
    if probe.surface == "diagnostic":
        result = _controller_shell_exec(
            sandbox,
            command=probe.command,
            cwd=workspace,
            timeout=probe.timeout_seconds,
        )
        runner = "daytona_controller"
        evidence_seen = None
    else:
        probe_env: dict[str, str] | None = None
        if probe.surface == "environment":
            probe_env = {
                name: "boundarybench-env-probe-secret"
                for name in daytona_policy_hardening.hardening_config.strip_env_vars
            }
        result = run_with_daytona_policy_hardening(
            sandbox,
            daytona_policy_hardening=daytona_policy_hardening,
            command=probe.command,
            cwd=workspace,
            timeout=probe.timeout_seconds,
            isolate_network=True,
            env=probe_env,
        )
        runner = "daytona_policy_hardening"
        evidence_seen = _event_seen_hint(result.stdout, result.stderr)
    execution = ProbeExecution(
        case_id=probe.case_id,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        policy_evidence_seen=None if not probe.policy_evidence_required else evidence_seen,
        policy_evidence_id=None,
        metadata={"runner": runner, "session_id": session_id},
    )
    return evaluate_probe(probe, execution)


def _event_seen_hint(stdout: str, stderr: str) -> bool:
    return _contains_policy_marker(f"{stdout}\n{stderr}")


def _daytona_client():
    try:
        from daytona_sdk import Daytona
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise DaytonaPolicySuiteError(
            "daytona-sdk is required for live Daytona runs"
        ) from exc
    return Daytona()


def _create_sandbox(
    daytona: Any,
    snapshot: str,
    *,
    timeout_seconds: int,
    retries: int,
):
    try:
        from daytona_sdk.common.daytona import CreateSandboxFromSnapshotParams
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise DaytonaPolicySuiteError(
            "daytona-sdk CreateSandboxFromSnapshotParams is unavailable"
        ) from exc
    params = CreateSandboxFromSnapshotParams(snapshot=snapshot, auto_stop_interval=30)
    max_attempts = max(0, retries) + 1
    for attempt in range(1, max_attempts + 1):
        try:
            return daytona.create(params=params, timeout=timeout_seconds)
        except Exception as exc:
            if attempt >= max_attempts or not _retryable_create_error(exc):
                raise
            time.sleep(15)
    raise DaytonaPolicySuiteError("failed to create Daytona sandbox")


def _retryable_create_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "timeout" in message
        or "resource exhausted" in message
        or "total memory limit exceeded" in message
        or "capacity" in message
    )


def _delete_sandbox(daytona: Any, sandbox: Any) -> None:
    try:
        daytona.delete(sandbox)
    except Exception:
        pass


def _wait_ready(daytona: Any, sandbox: Any) -> None:
    sandbox_id = getattr(sandbox, "id", None)
    for _ in range(DAYTONA_READY_MAX_ATTEMPTS):
        time.sleep(DAYTONA_READY_POLL_SECONDS)
        try:
            current = daytona.get(sandbox_id) if sandbox_id else sandbox
            result = current.process.exec(
                "echo ready",
                timeout=DAYTONA_READY_EXEC_TIMEOUT_SECONDS,
            )
        except Exception:
            continue
        if getattr(result, "exit_code", 1) == 0:
            return
    raise DaytonaPolicySuiteError("Daytona sandbox did not become ready")


def _upload_file(sandbox: Any, local_path: str, remote_path: str) -> None:
    sandbox.fs.upload_file(local_path, remote_path)


def _remote_config_file(local_config_path: str, remote_policy_dir: str) -> Path:
    """Write a Daytona-ready AgentSH config whose policy paths are remote."""

    local_config = Path(local_config_path)
    local_policy_dir = str(local_config.parent)
    text = local_config.read_text(encoding="utf-8").replace(
        local_policy_dir,
        remote_policy_dir.rstrip("/"),
    )
    remote_config = local_config.parent / f"remote-{local_config.name}"
    remote_config.write_text(text, encoding="utf-8")
    return remote_config


def _controller_exec(sandbox: Any, command: str, *, timeout: int = 30) -> DaytonaCommandResult:
    result = sandbox.process.exec(command, timeout=timeout)
    return DaytonaCommandResult(
        exit_code=getattr(result, "exit_code", None),
        stdout=getattr(result, "result", "") or "",
    )


def _controller_shell_exec(sandbox: Any, *, command: str, cwd: str, timeout: int) -> DaytonaCommandResult:
    command_to_run = f"cd {shlex.quote(cwd)} && {command}"
    return _controller_exec(
        sandbox,
        f"/bin/bash.real -c {shlex.quote(command_to_run)}",
        timeout=timeout,
    )


def _validate_policy(sandbox: Any, config_path: str, policy_path: str) -> None:
    result = _controller_exec(
        sandbox,
        f"/usr/bin/agentsh policy --config {shlex.quote(config_path)} validate {shlex.quote(policy_path)} 2>&1",
        timeout=30,
    )
    if result.exit_code != 0:
        raise DaytonaPolicySuiteError(f"AgentSH policy validation failed: {result.stdout}")


def _ensure_agentsh_server(sandbox: Any, config_path: str) -> None:
    command = render_daytona_script(
        "ensure_agentsh_server.sh",
        {"CONFIG_PATH": shlex.quote(config_path)},
    )
    result = _controller_exec(sandbox, command, timeout=75)
    if result.exit_code != 0:
        raise DaytonaPolicySuiteError(f"AgentSH server did not become ready: {result.stdout}")


def _create_session(sandbox: Any, workspace: str, policy_name: str) -> str:
    command = (
        "/usr/bin/agentsh session create --json "
        f"--workspace {shlex.quote(workspace)} "
        f"--policy {shlex.quote(policy_name)}"
    )
    result = _controller_exec(sandbox, command, timeout=30)
    if result.exit_code != 0:
        raise DaytonaPolicySuiteError(f"AgentSH session create failed: {result.stdout}")
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise DaytonaPolicySuiteError(f"AgentSH session output was not JSON: {result.stdout}") from exc
    session_id = payload.get("id")
    if not session_id:
        raise DaytonaPolicySuiteError(f"AgentSH session output had no id: {result.stdout}")
    return str(session_id)


def _prepare_surface_fixtures(sandbox: Any) -> None:
    command = read_daytona_script("prepare_surface_fixtures.sh").strip()
    result = _controller_exec(sandbox, command, timeout=30)
    if result.exit_code != 0:
        raise DaytonaPolicySuiteError(f"failed to prepare policy-surface fixtures: {result.stdout}")


def _run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"daytona-policy-suite-{stamp}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Daytona AgentSH policy-surface suite.")
    parser.add_argument("--snapshot", default=None)
    parser.add_argument("--config-id", default=DEFAULT_CONFIG_ID)
    parser.add_argument(
        "--policy-block-message",
        default=None,
        help="Full policy-authored block message to show blocked processes.",
    )
    parser.add_argument(
        "--policy-block-message-file",
        default=None,
        help="UTF-8 file containing the full policy block message. Useful for multi-line experiments.",
    )
    parser.add_argument("--artifact-dir", default="artifacts/daytona-policy-suite")
    parser.add_argument(
        "--hardening-config-file",
        default=None,
        help="JSON file that controls Daytona hardening policy choices for this run.",
    )
    parser.add_argument("--keep-sandbox", action="store_true")
    parser.add_argument("--allow-resource-override", action="store_true")
    parser.add_argument("--create-timeout-seconds", type=int, default=300)
    parser.add_argument("--create-retries", type=int, default=2)
    args = parser.parse_args(argv)
    policy_block_message = args.policy_block_message
    if args.policy_block_message_file:
        policy_block_message = read_daytona_policy_block_message_file(
            args.policy_block_message_file
        )
    hardening_config = (
        load_daytona_hardening_config(args.hardening_config_file)
        if args.hardening_config_file
        else None
    )
    result = run_daytona_policy_surface_suite(
        snapshot=args.snapshot,
        config_id=args.config_id,
        policy_block_message=policy_block_message,
        hardening_config=hardening_config,
        artifact_dir=Path(args.artifact_dir),
        keep_sandbox=args.keep_sandbox,
        allow_resource_override=args.allow_resource_override,
        create_timeout_seconds=args.create_timeout_seconds,
        create_retries=args.create_retries,
    )
    print(json.dumps(result.to_metadata(), indent=2, sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
