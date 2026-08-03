"""Run one Terminal-Bench task end-to-end inside a hardened Daytona sandbox.

Terminal-Bench tasks are per-task Docker images (e.g.
``alexgshaw/log-summary-date-ranges:20251031``) whose environment (``/app``) is
pre-built into the image. We run the task by creating a Daytona sandbox **from
that image** (pulled server-side, no local Docker), layering in the agent +
policy-hardening tooling at runtime, running the agent under the hardening
boundary, then scoring with Harbor's official verifier.

Flow (proven live on ``log-summary-date-ranges``: reward 1.0 PASS):

1. ``provision_hardened_task_sandbox`` — create sandbox from the task image,
   install runtime tooling (curl/gcc/sudo, ``/bin/bash.real``, Claude Code for
   the selected agent user, and any user needed by the selected overlays), then
   install the policy-hardening assets.
2. ``run_terminalbench_task_in_daytona`` — run the agent (Claude Code driving an
   OpenRouter model) in the task workspace under the hardening boundary, then run
   ``run_daytona_harbor_verifier`` and return the official reward.

The agent's OpenRouter auth travels via the hardening env channel as
``ANTHROPIC_AUTH_TOKEN`` + ``ANTHROPIC_BASE_URL`` (never the command line); Claude
Code is invoked by full path because ``~/.local/bin`` is not on the hardened
PATH.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import stat
import tempfile
import time
from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from math import ceil
from pathlib import Path
from threading import Lock
from typing import Any

from boundarybench.daytona.apparmor_capability import (
    DEFAULT_APPARMOR_DENIED_PATH,
    DEFAULT_APPARMOR_PROBE_WORKSPACE,
)
from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    _run_command_with_deadline,
    install_daytona_policy_hardening,
    run_with_daytona_policy_hardening,
    wrap_command_for_agentsh_session,
)
from boundarybench.daytona.policy_telemetry import (
    clear_policy_event_log,
    harvest_passive_telemetry,
    summarize_inferred_blocks,
)
from boundarybench.daytona.runtime_policy_probes import (
    RUNTIME_POLICY_PROBE_WORKSPACE,
)
from boundarybench.daytona.openrouter_accounting import (
    read_openrouter_accounting,
    start_openrouter_accounting_proxy,
)
from boundarybench.daytona.transport import retry_daytona_transport
from boundarybench.terminalbench.daytona import (
    DaytonaVerifierResult,
    TerminalBenchTaskBundle,
    run_daytona_harbor_verifier,
)
from boundarybench.terminalbench.task_config import (
    task_toml_environment,
    terminalbench_resource_demand_from_bundle,
)
from boundarybench.terminalbench.daytona_constants import (
    DEFAULT_AGENT_WORKDIR,
    DEFAULT_HARDENING_ASSET_DIR,
    DEFAULT_OPENROUTER_MODEL,
    MAX_SESSION_ARTIFACT_FILE_BYTES,
    MAX_SESSION_ARTIFACT_FILES,
    MAX_SESSION_ARTIFACT_TOTAL_BYTES,
    REMOTE_ALLOWED_DOMAINS_PATH,
    REMOTE_PROMPT_PATH,
    REMOTE_TESTS_DIR,
    SANDBOX_AUTO_DELETE_MIN,
    SANDBOX_AUTO_STOP_BUFFER_SEC,
    SANDBOX_AUTO_STOP_MIN,
    SANDBOX_LABELS,
    SANDBOX_MANAGED_BY_LABEL,
    SANDBOX_MANAGED_BY_VALUE,
    SANDBOX_NAMESPACE_LABEL,
    SANDBOX_RUN_ID_ENV,
    SANDBOX_RUN_ID_LABEL,
)
from boundarybench.harness.adapter import (
    HarnessAdapter,
    HarnessPostAgentCleanup,
    HarnessRuntimeAssets,
    effort_level_source,
    normalize_effort_level,
)
from boundarybench.harness.openrouter import (  # noqa: F401  (re-export)
    validate_openrouter_model_id,
)
from boundarybench.terminalbench.daytona_runtime_layer import (
    VERIFIER_ARTIFACT_CAPTURE_SCRIPT,
    render_clean_verifier_runtime_layer_script,
    render_sandbox_setup_script,
)
from boundarybench.terminalbench.policy_prompt import compose_prompt
from boundarybench.terminalbench.daytona_transcript import (
    policy_interaction_metrics,
    stream_diagnostics,
)

PRESERVE_AGENT_SESSION_ENV = "BOUNDARYBENCH_PRESERVE_AGENT_SESSION"

MINIMAL_DAYTONA_RESOURCE_PROFILE = (1, 2, 3, None)
MAX_VERIFIER_ARTIFACT_FILES = 16
MAX_VERIFIER_ARTIFACT_FILE_BYTES = 2 * 1024**3
MAX_VERIFIER_ARTIFACT_TOTAL_BYTES = 3 * 1024**3
_PRE_AGENT_PROBE_SCRATCH_DIRS = (
    RUNTIME_POLICY_PROBE_WORKSPACE,
    DEFAULT_APPARMOR_PROBE_WORKSPACE,
    posixpath.dirname(DEFAULT_APPARMOR_DENIED_PATH),
    "/var/boundarybench-mac-denied",
)
_PRE_AGENT_PROBE_SCRATCH_GLOBS = (
    "/tmp/boundarybench-secret-link*",
    "/tmp/boundarybench-write-link*",
    "/tmp/boundarybench-mac-*",
)

MODEL_AGENT_SESSION_PREFIX = "ia-model-agent-"
AGENT_LISTENER_PROBE_COMMAND = (
    "ss -tulpen 2>/dev/null "
    "|| netstat -tulpen 2>/dev/null "
    "|| python3 -c '"
    "import glob\n"
    "for p in sorted(glob.glob(\"/proc/net/tcp*\") + glob.glob(\"/proc/net/udp*\")):\n"
    "    proto = p.rsplit(\"/\", 1)[1]\n"
    "    for i, line in enumerate(open(p)):\n"
    "        f = line.split()\n"
    "        if i == 0 or len(f) < 4:\n"
    "            continue\n"
    "        if proto.startswith(\"tcp\") and f[3] != \"0A\":\n"
    "            continue\n"
    "        addr, _, port = f[1].rpartition(\":\")\n"
    "        print(proto, \"port\", int(port, 16), \"addr\", addr, \"state\", f[3])\n"
    "' 2>/dev/null "
    "|| cat /proc/net/tcp /proc/net/tcp6 2>/dev/null "
    "|| echo listener-probe-unavailable"
)


def _upload_harness_runtime_assets(
    sandbox: Any,
    harness: HarnessAdapter,
    *,
    run_as_root: bool,
) -> None:
    """Upload optional large harness assets outside the shell command argv."""

    if not isinstance(harness, HarnessRuntimeAssets):
        return
    for remote_path, content in harness.runtime_layer_assets(
        run_as_root=run_as_root
    ).items():
        if (
            not remote_path.startswith("/")
            or "\n" in remote_path
            or "\x00" in remote_path
        ):
            raise ValueError(f"invalid harness runtime asset path: {remote_path!r}")
        if not isinstance(content, bytes):
            raise TypeError(f"harness runtime asset must be bytes: {remote_path!r}")
        with tempfile.NamedTemporaryFile() as local_asset:
            local_asset.write(content)
            local_asset.flush()
            sandbox.fs.upload_file(local_asset.name, remote_path)


class _PhaseTimingRecorder:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def record(self, entry: dict[str, Any]) -> None:
        self._entries.append(dict(entry))

    def phase_timings_ms(self) -> dict[str, int]:
        timings: dict[str, int] = {}
        for entry in self._entries:
            phase = entry.get("phase")
            elapsed_ms = entry.get("elapsed_ms")
            if isinstance(phase, str) and isinstance(elapsed_ms, int):
                timings[_phase_timing_metadata_key(phase)] = elapsed_ms
        return timings

    def details(self) -> list[dict[str, Any]]:
        return [dict(entry) for entry in self._entries]


_PHASE_TIMING_RECORDER: ContextVar[_PhaseTimingRecorder | None] = ContextVar(
    "boundarybench_phase_timing_recorder",
    default=None,
)


def _sandbox_id(sandbox: Any) -> str | None:
    """Return a stable Daytona sandbox ID without affecting task execution."""

    if sandbox is None:
        return None
    try:
        value = getattr(sandbox, "id", None)
    except Exception:  # noqa: BLE001 - observability must not change the result
        return None
    return str(value) if value not in (None, "") else None


@dataclass(frozen=True)
class TerminalBenchRunResult:
    """Outcome of one hardened Terminal-Bench task run."""

    sample_id: str
    task_name: str
    prompt: str
    reward: float
    answer: str
    agent_exit_code: int | None
    agent_stdout: str
    verifier: DaytonaVerifierResult
    agent_stderr: str = ""
    agent_timed_out: bool = False
    requested_agent_timeout_sec: int | None = None
    task_config_agent_timeout_sec: int | None = None
    effective_agent_timeout_sec: int | None = None
    sandbox_id: str | None = None
    hardening_config: dict[str, Any] = field(default_factory=dict)
    policy_prompt_provenance: dict[str, Any] = field(default_factory=dict)
    recovery_bundle_provenance: dict[str, Any] = field(default_factory=dict)
    policy_events: list[dict[str, Any]] = field(default_factory=list)
    preflight: dict[str, Any] | None = None
    runtime_policy_probe_report: dict[str, Any] | None = None
    openrouter_accounting: dict[str, Any] | None = None
    agentsh_agent_wrapped: bool = False
    agentsh_session_id: str | None = None
    agentsh_policy_session: dict[str, Any] | None = None
    submission_snapshot: dict[str, Any] | None = None
    postflight_verification: dict[str, Any] | None = None
    phase_timings_ms: dict[str, int] = field(default_factory=dict)
    phase_timing_details: list[dict[str, Any]] = field(default_factory=list)
    task_net_runtime_ms: int | None = None
    agent_version: str | None = None
    agent_workdir: str = DEFAULT_AGENT_WORKDIR
    agent_workdir_source: str = "default"
    workspace_root: str = DEFAULT_AGENT_WORKDIR
    harness_session_artifacts: dict[str, Any] | None = None
    harness: str = field(kw_only=True)
    effort_level: str = field(kw_only=True)
    effort_level_source: str = field(kw_only=True)
    effort_level_applied: bool = field(kw_only=True)

    @property
    def passed(self) -> bool:
        return self.reward > 0

    def to_metadata(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "task_name": self.task_name,
            "reward": self.reward,
            "answer": self.answer,
            "agent_exit_code": self.agent_exit_code,
            "agent_timed_out": self.agent_timed_out,
            "agent_stdout": self.agent_stdout,
            "agent_stderr": self.agent_stderr,
            **stream_diagnostics(self.agent_stdout, harness=self.harness),
            **policy_interaction_metrics(
                self.agent_stdout,
                policy_events=self.policy_events,
                task_net_runtime_ms=self.task_net_runtime_ms,
            ),
            "requested_agent_timeout_sec": self.requested_agent_timeout_sec,
            "task_config_agent_timeout_sec": self.task_config_agent_timeout_sec,
            "effective_agent_timeout_sec": self.effective_agent_timeout_sec,
            "sandbox_id": self.sandbox_id,
            "verifier": self.verifier.to_metadata(),
            "hardening_config": self.hardening_config,
            "policy_prompt_provenance": self.policy_prompt_provenance,
            "recovery_bundle_provenance": self.recovery_bundle_provenance,
            "policy_events": self.policy_events,
            "policy_event_count": len(self.policy_events),
            "policy_block_count": _policy_block_count(self.policy_events),
            **summarize_inferred_blocks(self.policy_events),
            "honeytoken_exfil_count": _honeytoken_exfil_count(self.policy_events),
            "preflight": self.preflight,
            "runtime_policy_probe_report": self.runtime_policy_probe_report,
            "openrouter_accounting": self.openrouter_accounting,
            "agentsh_agent_wrapped": self.agentsh_agent_wrapped,
            "agentsh_session_id": self.agentsh_session_id,
            "agentsh_policy_session": self.agentsh_policy_session,
            "submission_snapshot": self.submission_snapshot,
            "postflight_verification": self.postflight_verification,
            "phase_timings_ms": self.phase_timings_ms,
            "phase_timing_details": self.phase_timing_details,
            "task_net_runtime_ms": self.task_net_runtime_ms,
            "agent_version": self.agent_version,
            "agent_workdir": self.agent_workdir,
            "agent_workdir_source": self.agent_workdir_source,
            "workspace_root": self.workspace_root,
            "harness_session_artifacts": self.harness_session_artifacts,
            "harness": self.harness,
            "effort_level": self.effort_level,
            "effort_level_source": self.effort_level_source,
            "effort_level_applied": self.effort_level_applied,
        }


def _run_with_phase_timing_capture(fn: Any, *args: Any, **kwargs: Any) -> Any:
    recorder = _PHASE_TIMING_RECORDER.get()
    token = None
    if recorder is None:
        recorder = _PhaseTimingRecorder()
        token = _PHASE_TIMING_RECORDER.set(recorder)
    try:
        result = fn(*args, **kwargs)
        if isinstance(result, TerminalBenchRunResult):
            return _attach_phase_timing_metadata(result, recorder)
        return result
    except Exception as exc:
        _attach_phase_timing_exception_metadata(exc, recorder)
        raise
    finally:
        if token is not None:
            _PHASE_TIMING_RECORDER.reset(token)


def _policy_block_count(events: list[dict[str, Any]]) -> int:
    return sum(1 for event in events if event.get("event_type") == "policy_block")


def _honeytoken_exfil_count(events: list[dict[str, Any]]) -> int:
    """Count honeytoken-exfil signals (event_type == honeytoken_exfil).

    A surfaced fake credential is an exfil signal, never a policy block.
    """

    return sum(1 for event in events if event.get("event_type") == "honeytoken_exfil")


def _attach_phase_timing_metadata(
    result: TerminalBenchRunResult,
    recorder: _PhaseTimingRecorder,
) -> TerminalBenchRunResult:
    phase_timings_ms = recorder.phase_timings_ms()
    return replace(
        result,
        phase_timings_ms=phase_timings_ms,
        phase_timing_details=recorder.details(),
        task_net_runtime_ms=_task_net_runtime_ms(phase_timings_ms),
    )


def _attach_phase_timing_exception_metadata(
    exc: Exception,
    recorder: _PhaseTimingRecorder,
) -> None:
    phase_timings_ms = recorder.phase_timings_ms()
    setattr(exc, "phase_timings_ms", phase_timings_ms)
    setattr(exc, "phase_timing_details", recorder.details())
    setattr(exc, "task_net_runtime_ms", _task_net_runtime_ms(phase_timings_ms))


def _task_net_runtime_ms(phase_timings_ms: dict[str, int]) -> int | None:
    parts = [
        phase_timings_ms.get("prompt_upload_ms"),
        phase_timings_ms.get("agent_run_ms"),
        phase_timings_ms.get("policy_event_read_ms"),
        phase_timings_ms.get("harbor_verifier_ms"),
    ]
    numeric = [value for value in parts if isinstance(value, int)]
    if (
        "agent_run_ms" in phase_timings_ms
        and "harbor_verifier_ms" in phase_timings_ms
        and numeric
    ):
        return sum(numeric)
    for key in ("task_execute_and_verify_ms", "task_run_total_ms"):
        value = phase_timings_ms.get(key)
        if isinstance(value, int):
            return value
    if numeric:
        return sum(numeric)
    return None


def _phase_timing_metadata_key(phase: str) -> str:
    return phase if phase.endswith("_ms") else f"{phase}_ms"


def task_docker_image(bundle: TerminalBenchTaskBundle) -> str:
    """Read the task's Docker image from its ``task.toml`` ``[environment]``."""

    image = _task_environment(bundle).get("docker_image")
    if not image:
        raise ValueError(f"task {bundle.task_name} has no environment.docker_image")
    return str(image)


def daytona_task_resources(bundle: TerminalBenchTaskBundle) -> Any | None:
    """Return the initial Daytona resources for a Terminal-Bench task.

    Terminal-Bench resources are read from ``task.toml`` and passed through
    without local defaults or enlargement.
    """

    return daytona_task_resource_attempts(bundle)[0]


def daytona_task_resource_attempts(bundle: TerminalBenchTaskBundle) -> list[Any]:
    """Return the single Daytona resource profile declared by the task.

    Terminal-Bench records memory/storage in MiB; Daytona resources use GiB.
    """

    required = _terminalbench_required_resources(bundle)
    return [_resources_from_profile(required)]


def _resources_from_profile(profile: tuple[int, int, int, int | None]) -> Any:
    from daytona_sdk.common.sandbox import Resources

    cpu, memory, disk, gpu = profile
    resources_kwargs = {
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
    }
    if gpu:
        resources_kwargs["gpu"] = gpu
    return Resources(**resources_kwargs)


def _sandbox_auto_stop_min(*timeout_seconds: int | None) -> int:
    """Return a Daytona auto-stop interval that cannot undercut task timeouts."""

    positive_timeouts = [int(value) for value in timeout_seconds if value and value > 0]
    if not positive_timeouts:
        return SANDBOX_AUTO_STOP_MIN
    required = ceil((max(positive_timeouts) + SANDBOX_AUTO_STOP_BUFFER_SEC) / 60)
    return max(SANDBOX_AUTO_STOP_MIN, required)


def _terminalbench_required_resources(
    bundle: TerminalBenchTaskBundle,
) -> tuple[int, int, int, int | None] | None:
    demand = terminalbench_resource_demand_from_bundle(bundle)
    return (
        demand["cpu"],
        demand["memory_gib"],
        demand["disk_gib"],
        demand["gpu"] or None,
    )


def _task_environment(bundle: TerminalBenchTaskBundle) -> dict[str, Any]:
    environment = _task_toml_environment(bundle)
    metadata_environment = bundle.metadata.get("environment")
    if isinstance(metadata_environment, dict) and metadata_environment:
        return {**environment, **metadata_environment}
    if metadata_environment is not None and not isinstance(metadata_environment, dict):
        raise ValueError(f"task {bundle.task_name} has invalid metadata.environment")
    return environment


def _task_toml_environment(bundle: TerminalBenchTaskBundle) -> dict[str, Any]:
    return task_toml_environment(bundle.task_dir, task_name=bundle.task_name)


def provision_hardened_task_sandbox(
    daytona: Any,
    *,
    image: str,
    resources: Any | None = None,
    workdir: str = DEFAULT_AGENT_WORKDIR,
    hardening_asset_dir: str = DEFAULT_HARDENING_ASSET_DIR,
    hardening_config: Any = None,
    run_agent_as_root: bool = False,
    install_policy_hardening: bool = True,
    install_landlock_mac_runner: bool = False,
    create_timeout_sec: int = 600,
    enforcement_mode: str = "legacy",
    command_timeout_sec: int | None = None,
    task_id: str | None = None,
    harness: HarnessAdapter,
    effort_level: str = "high",
    recovery_bundle_files: Sequence[tuple[str, str, str]] | None = None,
) -> tuple[Any, DaytonaPolicyHardening | None]:
    """Create a sandbox from the task image and install agent + hardening tooling.

    ``hardening_config`` selects which blocked-surface overlay is installed.
    Passing the blank config keeps the Daytona/task-image baseline and still
    uses the same harness plumbing for env injection and transcript capture.
    ``harness`` is required; there is no adapter-free or implicit-default code
    path at the hardening boundary.
    """

    from daytona_sdk.common.daytona import CreateSandboxFromImageParams

    provision_started = time.perf_counter()
    phase_started = time.perf_counter()
    try:
        sandbox = daytona.create(
            CreateSandboxFromImageParams(
                image=image,
                resources=resources,
                auto_stop_interval=_sandbox_auto_stop_min(command_timeout_sec),
                auto_delete_interval=SANDBOX_AUTO_DELETE_MIN,
                labels=_sandbox_create_labels(),
            ),
            timeout=create_timeout_sec,
        )
    except Exception:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=image,
            phase="sandbox_create",
            started_at=phase_started,
            status="error",
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=image,
            phase="sandbox_provision_total",
            started_at=provision_started,
            status="error",
        )
        raise
    _print_phase_timing(
        component="terminalbench_daytona",
        identifier=getattr(sandbox, "id", image),
        phase="sandbox_create",
        started_at=phase_started,
        status="success",
        image=image,
    )
    try:
        phase_started = time.perf_counter()
        phase_status = "success"
        _upload_harness_runtime_assets(
            sandbox,
            harness,
            run_as_root=run_agent_as_root,
        )
        layer_script = render_sandbox_setup_script(
            workdir=workdir,
            run_agent_as_root=run_agent_as_root,
            harness=harness,
            task_id=task_id,
        )
        result = sandbox.process.exec(layer_script, timeout=600)
        if getattr(result, "exit_code", 1) != 0:
            phase_status = "error"
            raise RuntimeError(
                f"runtime layering failed: {getattr(result, 'result', '') or ''}"
            )
        agent_bin = harness.agent_binary_path(run_as_root=run_agent_as_root)
        verify_result = sandbox.process.exec(
            f"test -x {shlex.quote(agent_bin)}", timeout=30
        )
        if getattr(verify_result, "exit_code", 1) != 0:
            phase_status = "error"
            raise RuntimeError(f"harness binary is not executable: {agent_bin}")
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="runtime_layer_install",
            started_at=phase_started,
            status=phase_status,
        )
        if recovery_bundle_files:
            phase_started = time.perf_counter()
            phase_status = "success"
            try:
                agent_user = "root" if run_agent_as_root else "daytona"
                for remote_path, content, mode in recovery_bundle_files:
                    parent = posixpath.dirname(remote_path)
                    sandbox.process.exec(f"mkdir -p {shlex.quote(parent)}", timeout=30)
                    _upload_text_to_sandbox(
                        sandbox, content=content, remote_path=remote_path
                    )
                    sandbox.process.exec(
                        f"chmod {shlex.quote(mode)} {shlex.quote(remote_path)}",
                        timeout=30,
                    )
                    sandbox.process.exec(
                        f"chown {shlex.quote(agent_user)}: {shlex.quote(remote_path)}",
                        timeout=30,
                    )
            except Exception:
                phase_status = "error"
                raise
            finally:
                _print_phase_timing(
                    component="terminalbench_daytona",
                    identifier=getattr(sandbox, "id", image),
                    phase="recovery_bundle_write",
                    started_at=phase_started,
                    status=phase_status,
                )
        phase_started = time.perf_counter()
        phase_status = "success"
        try:
            start_openrouter_accounting_proxy(sandbox, effort_level=effort_level)
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=getattr(sandbox, "id", image),
                phase="openrouter_accounting_proxy_start",
                started_at=phase_started,
                status=phase_status,
            )
        phase_started = time.perf_counter()
        phase_status = "success"
        hardening = (
            install_daytona_policy_hardening(
                sandbox,
                hardening_asset_dir,
                hardening_config=hardening_config,
                install_landlock_mac_runner=install_landlock_mac_runner,
                enforcement_mode=enforcement_mode,
            )
            if install_policy_hardening
            else None
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="policy_hardening_install",
            started_at=phase_started,
            status=phase_status,
            installed=install_policy_hardening,
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="sandbox_provision_total",
            started_at=provision_started,
            status="success",
        )
        return sandbox, hardening
    except Exception:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="sandbox_provision_total",
            started_at=provision_started,
            status="error",
        )
        try:
            daytona.delete(sandbox)
        except Exception:
            pass
        raise


@dataclass(frozen=True)
class VerifierArtifact:
    """One regular file copied between the agent and verifier sandboxes."""

    remote_path: str
    relative_path: str
    local_path: Path
    sha256: str
    size_bytes: int

    def to_metadata(self) -> dict[str, Any]:
        return {
            "remote_path": self.remote_path,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class VerifierArtifactSnapshot:
    """Temporary local copy of explicit verifier handoff files."""

    root: Path
    workspace_root: str
    artifacts: tuple[VerifierArtifact, ...]
    owner_token: str = field(repr=False)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "transport": "explicit_regular_files",
            "workspace_root": self.workspace_root,
            "artifacts": [artifact.to_metadata() for artifact in self.artifacts],
        }


_VERIFIER_SNAPSHOT_MARKER = ".boundarybench-verifier-owner"
_VERIFIER_SNAPSHOT_PROVENANCE: dict[str, Path] = {}
_VERIFIER_SNAPSHOT_PROVENANCE_LOCK = Lock()


def provision_clean_verifier_sandbox(
    daytona: Any,
    *,
    image: str,
    resources: Any | None = None,
    workdir: str = DEFAULT_AGENT_WORKDIR,
    verifier_user: str | None = None,
    create_timeout_sec: int = 600,
    command_timeout_sec: int | None = None,
) -> Any:
    """Create a clean task-image sandbox for post-agent verification only."""

    from daytona_sdk.common.daytona import CreateSandboxFromImageParams

    if verifier_user not in (None, "", "root", "0"):
        raise ValueError(f"clean verifier requires a root verifier: {verifier_user!r}")
    started = time.perf_counter()
    phase_started = time.perf_counter()
    try:
        sandbox = daytona.create(
            CreateSandboxFromImageParams(
                image=image,
                resources=resources,
                auto_stop_interval=_sandbox_auto_stop_min(command_timeout_sec),
                auto_delete_interval=SANDBOX_AUTO_DELETE_MIN,
                labels=_sandbox_create_labels(),
            ),
            timeout=create_timeout_sec,
        )
    except Exception:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=image,
            phase="postflight_verifier_sandbox_create",
            started_at=phase_started,
            status="error",
        )
        raise
    _print_phase_timing(
        component="terminalbench_daytona",
        identifier=getattr(sandbox, "id", image),
        phase="postflight_verifier_sandbox_create",
        started_at=phase_started,
        status="success",
        image=image,
    )
    try:
        phase_started = time.perf_counter()
        script = render_clean_verifier_runtime_layer_script(workdir=workdir)
        result = sandbox.process.exec(script, timeout=600)
        if getattr(result, "exit_code", 1) != 0:
            raise RuntimeError(
                "clean verifier runtime layering failed: "
                f"{getattr(result, 'result', '') or ''}"
            )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="postflight_verifier_runtime_layer",
            started_at=phase_started,
            status="success",
            hardening=False,
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="postflight_verifier_provision_total",
            started_at=started,
            status="success",
        )
        return sandbox
    except Exception as setup_error:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", image),
            phase="postflight_verifier_provision_total",
            started_at=started,
            status="error",
        )
        try:
            daytona.delete(sandbox)
        except Exception as cleanup_error:
            raise ExceptionGroup(
                "clean verifier setup and cleanup failed",
                [setup_error, cleanup_error],
            ) from setup_error
        raise


def export_verifier_artifacts(
    sandbox: Any,
    handoff_paths: list[str] | tuple[str, ...],
    *,
    workspace_root: str,
) -> VerifierArtifactSnapshot:
    """Atomically capture and download explicit regular verifier files."""

    normalized_root = _validate_workspace_root(workspace_root)
    remote_paths = [
        _validate_handoff_path(path, workspace_root=normalized_root)
        for path in handoff_paths
    ]
    if len(remote_paths) != len(set(remote_paths)):
        raise ValueError("verifier handoff paths must be unique")
    if len(remote_paths) > MAX_VERIFIER_ARTIFACT_FILES:
        raise ValueError(
            "verifier artifact count exceeds cap "
            f"{MAX_VERIFIER_ARTIFACT_FILES}: {len(remote_paths)}"
        )

    snapshot_root = Path(
        tempfile.mkdtemp(prefix="boundarybench-verifier-")
    ).resolve()
    snapshot_root.chmod(0o700)
    owner_token = secrets.token_hex(32)
    _write_snapshot_marker(snapshot_root, owner_token)
    remote_token = secrets.token_hex(16)
    remote_staging = f"/tmp/boundarybench-verifier-capture-{remote_token}"
    remote_script = (
        f"/tmp/boundarybench-{remote_token}-capture_verifier_artifacts.py"
    )
    artifacts: list[VerifierArtifact] = []
    try:
        _upload_verifier_capture_script(sandbox, remote_script)
        capture_command = " ".join(
            (
                f"chmod 0700 {shlex.quote(remote_script)} &&",
                "python3",
                shlex.quote(remote_script),
                "--workspace-root",
                shlex.quote(normalized_root),
                "--staging-root",
                shlex.quote(remote_staging),
                "--max-files",
                str(MAX_VERIFIER_ARTIFACT_FILES),
                "--max-file-bytes",
                str(MAX_VERIFIER_ARTIFACT_FILE_BYTES),
                "--max-total-bytes",
                str(MAX_VERIFIER_ARTIFACT_TOTAL_BYTES),
                *(f"--path {shlex.quote(path)}" for path in remote_paths),
            )
        )
        capture_result = sandbox.process.exec(capture_command, timeout=1800)
        if getattr(capture_result, "exit_code", 1) != 0:
            raise ValueError(
                "verifier handoff capture rejected: "
                f"{getattr(capture_result, 'result', '') or ''}"
            )
        manifest_artifacts = _parse_verifier_capture_manifest(
            getattr(capture_result, "result", "") or "",
            expected_count=len(remote_paths),
        )
        downloaded_total = 0
        for index, (remote_path, manifest_artifact) in enumerate(
            zip(remote_paths, manifest_artifacts, strict=True)
        ):
            relative_path = posixpath.relpath(remote_path, normalized_root)
            if relative_path == _VERIFIER_SNAPSHOT_MARKER:
                raise ValueError("verifier handoff path uses a reserved name")
            local_path = snapshot_root.joinpath(*relative_path.split("/"))
            local_path.parent.mkdir(parents=True, exist_ok=True)
            sandbox.fs.download_file(
                f"{remote_staging}/{index:06d}", str(local_path), 1800
            )
            local_stat = local_path.lstat()
            if not stat.S_ISREG(local_stat.st_mode):
                raise ValueError(
                    f"verifier handoff download is not a regular file: {remote_path}"
                )
            if local_stat.st_size > MAX_VERIFIER_ARTIFACT_FILE_BYTES:
                raise ValueError(
                    f"verifier artifact download exceeds per-file cap: {remote_path}"
                )
            downloaded_total += local_stat.st_size
            if downloaded_total > MAX_VERIFIER_ARTIFACT_TOTAL_BYTES:
                raise ValueError("verifier artifact downloads exceed total byte cap")
            if local_stat.st_size != manifest_artifact["size_bytes"]:
                raise ValueError(
                    f"verifier artifact download size mismatch: {remote_path}"
                )
            local_sha256 = _sha256_path(local_path)
            if local_sha256 != manifest_artifact["sha256"]:
                raise ValueError(
                    f"verifier artifact download hash mismatch: {remote_path}"
                )
            artifacts.append(
                VerifierArtifact(
                    remote_path=remote_path,
                    relative_path=relative_path,
                    local_path=local_path,
                    sha256=local_sha256,
                    size_bytes=local_stat.st_size,
                )
            )
        snapshot = VerifierArtifactSnapshot(
            root=snapshot_root,
            workspace_root=normalized_root,
            artifacts=tuple(artifacts),
            owner_token=owner_token,
        )
    except Exception as capture_error:
        cleanup_errors: list[Exception] = []
        host_cleanup_error = _cleanup_local_verifier_snapshot(snapshot_root)
        if host_cleanup_error is not None:
            cleanup_errors.append(host_cleanup_error)
        try:
            _cleanup_remote_verifier_capture(
                sandbox,
                remote_staging=remote_staging,
                remote_script=remote_script,
            )
        except Exception as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            raise ExceptionGroup(
                "verifier artifact capture and cleanup failed",
                [capture_error, *cleanup_errors],
            ) from capture_error
        raise
    try:
        _cleanup_remote_verifier_capture(
            sandbox,
            remote_staging=remote_staging,
            remote_script=remote_script,
        )
    except Exception as remote_cleanup_error:
        host_cleanup_error = _cleanup_local_verifier_snapshot(snapshot_root)
        if host_cleanup_error is not None:
            raise ExceptionGroup(
                "verifier artifact cleanup failed",
                [remote_cleanup_error, host_cleanup_error],
            ) from remote_cleanup_error
        raise
    _register_verifier_snapshot(snapshot)
    return snapshot


def import_verifier_artifacts(
    sandbox: Any,
    snapshot: VerifierArtifactSnapshot,
    *,
    workspace_root: str,
) -> None:
    """Upload a validated explicit-file snapshot into a clean verifier VM."""

    normalized_root = _validate_workspace_root(workspace_root)
    artifacts = _validate_verifier_snapshot(snapshot, workspace_root=normalized_root)
    for artifact in artifacts:
        remote_path = artifact.remote_path
        result = sandbox.process.exec(
            _destination_path_preparation_command(
                remote_path, workspace_root=normalized_root
            ),
            timeout=30,
        )
        if getattr(result, "exit_code", 1) != 0:
            raise ValueError(
                "verifier destination path contains a symlink or non-directory "
                f"component: {remote_path}"
            )
        sandbox.fs.upload_file(str(artifact.local_path), remote_path)


def cleanup_verifier_artifacts(snapshot: VerifierArtifactSnapshot | None) -> None:
    """Remove an exporter-owned temporary snapshot without trusting its root."""

    if snapshot is None:
        return
    root = snapshot.root
    with _VERIFIER_SNAPSHOT_PROVENANCE_LOCK:
        registered_root = _VERIFIER_SNAPSHOT_PROVENANCE.get(snapshot.owner_token)
    if registered_root is None:
        if isinstance(root, Path) and not root.exists():
            return
        raise ValueError("verifier snapshot provenance is not registered")
    if root != registered_root:
        raise ValueError("verifier snapshot provenance root does not match")
    _validate_snapshot_provenance(snapshot)
    shutil.rmtree(root)
    with _VERIFIER_SNAPSHOT_PROVENANCE_LOCK:
        _VERIFIER_SNAPSHOT_PROVENANCE.pop(snapshot.owner_token, None)


def _validate_workspace_root(workspace_root: str) -> str:
    if not posixpath.isabs(workspace_root):
        raise ValueError("verifier workspace root must be absolute")
    normalized = posixpath.normpath(workspace_root)
    if normalized != workspace_root:
        raise ValueError("verifier workspace root must be normalized")
    return normalized


def _validate_handoff_path(path: str, *, workspace_root: str) -> str:
    if not posixpath.isabs(path):
        raise ValueError(f"verifier handoff path must be absolute: {path}")
    normalized = posixpath.normpath(path)
    if normalized != path:
        raise ValueError(f"verifier handoff path must be normalized: {path}")
    try:
        common = posixpath.commonpath((workspace_root, normalized))
    except ValueError as exc:
        raise ValueError(f"invalid verifier handoff path: {path}") from exc
    if common != workspace_root or normalized == workspace_root:
        raise ValueError(
            f"verifier handoff path escapes workspace root {workspace_root}: {path}"
        )
    return normalized


def _write_snapshot_marker(root: Path, owner_token: str) -> None:
    marker = root / _VERIFIER_SNAPSHOT_MARKER
    descriptor = os.open(
        marker,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, owner_token.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse_verifier_capture_manifest(
    output: str, *, expected_count: int
) -> tuple[dict[str, Any], ...]:
    try:
        manifest = json.loads(output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("verifier capture manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise ValueError("verifier capture manifest version is invalid")
    file_count = manifest.get("file_count")
    artifacts = manifest.get("artifacts")
    total_bytes = manifest.get("total_bytes")
    if (
        not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or file_count != expected_count
        or file_count > MAX_VERIFIER_ARTIFACT_FILES
        or not isinstance(artifacts, list)
        or len(artifacts) != file_count
    ):
        raise ValueError("verifier capture manifest artifact count is invalid")

    parsed: list[dict[str, Any]] = []
    computed_total = 0
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError("verifier capture manifest artifact is invalid")
        size_bytes = artifact.get("size_bytes")
        sha256 = artifact.get("sha256")
        if (
            artifact.get("index") != index
            or artifact.get("staged_name") != f"{index:06d}"
        ):
            raise ValueError("verifier capture manifest artifact ordering is invalid")
        if (
            not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
            or size_bytes > MAX_VERIFIER_ARTIFACT_FILE_BYTES
        ):
            raise ValueError("verifier capture manifest exceeds per-file byte cap")
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise ValueError("verifier capture manifest artifact hash is invalid")
        computed_total += size_bytes
        parsed.append({"size_bytes": size_bytes, "sha256": sha256})
    if (
        not isinstance(total_bytes, int)
        or isinstance(total_bytes, bool)
        or total_bytes != computed_total
        or total_bytes > MAX_VERIFIER_ARTIFACT_TOTAL_BYTES
    ):
        raise ValueError("verifier capture manifest exceeds total byte cap")
    return tuple(parsed)


def _upload_verifier_capture_script(sandbox: Any, remote_script: str) -> None:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".py", prefix="boundarybench-capture-", delete=False
    ) as local_script:
        local_script.write(VERIFIER_ARTIFACT_CAPTURE_SCRIPT)
        local_path = local_script.name
    try:
        sandbox.fs.upload_file(local_path, remote_script)
    finally:
        try:
            os.unlink(local_path)
        except OSError:
            pass


def _cleanup_remote_verifier_capture(
    sandbox: Any, *, remote_staging: str, remote_script: str
) -> None:
    result = sandbox.process.exec(
        f"rm -rf -- {shlex.quote(remote_staging)} {shlex.quote(remote_script)}",
        timeout=30,
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(
            "remote verifier staging cleanup failed: "
            f"{getattr(result, 'result', '') or ''}"
        )


def _cleanup_local_verifier_snapshot(snapshot_root: Path) -> Exception | None:
    try:
        shutil.rmtree(snapshot_root)
    except Exception as exc:
        return RuntimeError(f"host snapshot cleanup failed: {exc}")
    return None


def _register_verifier_snapshot(snapshot: VerifierArtifactSnapshot) -> None:
    with _VERIFIER_SNAPSHOT_PROVENANCE_LOCK:
        if snapshot.owner_token in _VERIFIER_SNAPSHOT_PROVENANCE:
            raise RuntimeError("verifier snapshot owner token collision")
        _VERIFIER_SNAPSHOT_PROVENANCE[snapshot.owner_token] = snapshot.root


def _validate_snapshot_provenance(snapshot: VerifierArtifactSnapshot) -> None:
    root = snapshot.root
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("verifier snapshot provenance root is invalid")
    with _VERIFIER_SNAPSHOT_PROVENANCE_LOCK:
        registered_root = _VERIFIER_SNAPSHOT_PROVENANCE.get(snapshot.owner_token)
    if registered_root != root:
        raise ValueError("verifier snapshot provenance does not match exporter state")
    try:
        root_stat = root.lstat()
    except FileNotFoundError as exc:
        raise ValueError("verifier snapshot provenance root is missing") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("verifier snapshot provenance root is not a real directory")
    if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) & 0o077:
        raise ValueError("verifier snapshot provenance root is not private")
    if root.resolve(strict=True) != root:
        raise ValueError("verifier snapshot provenance root contains a symlink")
    marker = root / _VERIFIER_SNAPSHOT_MARKER
    try:
        marker_stat = marker.lstat()
    except FileNotFoundError as exc:
        raise ValueError("verifier snapshot provenance marker is missing") from exc
    if not stat.S_ISREG(marker_stat.st_mode) or stat.S_ISLNK(marker_stat.st_mode):
        raise ValueError("verifier snapshot provenance marker is not regular")
    if marker_stat.st_uid != os.getuid() or stat.S_IMODE(marker_stat.st_mode) & 0o077:
        raise ValueError("verifier snapshot provenance marker is not private")
    try:
        marker_token = marker.read_text(encoding="ascii")
    except OSError as exc:
        raise ValueError("verifier snapshot provenance marker is unreadable") from exc
    if not secrets.compare_digest(marker_token, snapshot.owner_token):
        raise ValueError("verifier snapshot provenance marker does not match")


def _validate_verifier_snapshot(
    snapshot: VerifierArtifactSnapshot, *, workspace_root: str
) -> tuple[VerifierArtifact, ...]:
    _validate_snapshot_provenance(snapshot)
    if workspace_root != snapshot.workspace_root:
        raise ValueError("verifier artifact workspace root does not match snapshot")
    if len(snapshot.artifacts) > MAX_VERIFIER_ARTIFACT_FILES:
        raise ValueError(
            "verifier artifact count exceeds cap "
            f"{MAX_VERIFIER_ARTIFACT_FILES}: {len(snapshot.artifacts)}"
        )
    declared_total = 0
    for artifact in snapshot.artifacts:
        size_bytes = artifact.size_bytes
        if (
            not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
            or size_bytes > MAX_VERIFIER_ARTIFACT_FILE_BYTES
        ):
            raise ValueError("verifier artifact exceeds per-file byte cap")
        declared_total += size_bytes
    if declared_total > MAX_VERIFIER_ARTIFACT_TOTAL_BYTES:
        raise ValueError("verifier artifacts exceed total byte cap")

    relative_paths: set[str] = set()
    remote_paths: set[str] = set()
    for artifact in snapshot.artifacts:
        relative_path = artifact.relative_path
        if (
            not isinstance(relative_path, str)
            or posixpath.isabs(relative_path)
            or relative_path in ("", ".")
            or posixpath.normpath(relative_path) != relative_path
            or relative_path.startswith("../")
        ):
            raise ValueError(
                f"verifier artifact relative path is invalid: {relative_path}"
            )
        if relative_path == _VERIFIER_SNAPSHOT_MARKER:
            raise ValueError("verifier artifact relative path is reserved")
        remote_path = _validate_handoff_path(
            artifact.remote_path, workspace_root=workspace_root
        )
        if remote_path != posixpath.join(workspace_root, relative_path):
            raise ValueError("verifier artifact path metadata is inconsistent")
        if relative_path in relative_paths or remote_path in remote_paths:
            raise ValueError("verifier artifact paths must be unique")
        relative_paths.add(relative_path)
        remote_paths.add(remote_path)

        expected_local_path = snapshot.root.joinpath(*relative_path.split("/"))
        if (
            not isinstance(artifact.local_path, Path)
            or artifact.local_path != expected_local_path
        ):
            raise ValueError(
                f"verifier artifact local path is not snapshot-owned: {relative_path}"
            )
        _validate_local_artifact_path(
            artifact.local_path,
            root=snapshot.root,
            relative_path=relative_path,
        )
        local_stat = artifact.local_path.lstat()
        if local_stat.st_size != artifact.size_bytes:
            raise ValueError(f"verifier artifact size changed: {relative_path}")
        if _sha256_path(artifact.local_path) != artifact.sha256:
            raise ValueError(f"verifier artifact hash changed: {relative_path}")
    return snapshot.artifacts


def _validate_local_artifact_path(
    local_path: Path, *, root: Path, relative_path: str
) -> None:
    current = root
    components = relative_path.split("/")
    for index, component in enumerate(components):
        current /= component
        try:
            current_stat = current.lstat()
        except FileNotFoundError as exc:
            raise ValueError(
                f"verifier artifact snapshot file is missing: {relative_path}"
            ) from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(
                f"verifier artifact local path contains a symlink: {relative_path}"
            )
        is_final = index == len(components) - 1
        if is_final and not stat.S_ISREG(current_stat.st_mode):
            raise ValueError(
                f"verifier artifact snapshot file is not regular: {relative_path}"
            )
        if not is_final and not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError(
                f"verifier artifact local path component is not a directory: {relative_path}"
            )
    if current != local_path:
        raise ValueError(
            f"verifier artifact local path is inconsistent: {relative_path}"
        )


def _destination_path_preparation_command(
    remote_path: str, *, workspace_root: str
) -> str:
    parent = posixpath.dirname(remote_path)
    parent_components = [workspace_root]
    current = workspace_root
    relative_parent = posixpath.relpath(parent, workspace_root)
    if relative_parent != ".":
        for component in relative_parent.split("/"):
            current = posixpath.join(current, component)
            parent_components.append(current)
    prechecks = [
        f"test ! -L {shlex.quote(component)} && "
        f"([ ! -e {shlex.quote(component)} ] || test -d {shlex.quote(component)})"
        for component in parent_components
    ]
    postchecks = [
        f"test ! -L {shlex.quote(component)} && test -d {shlex.quote(component)}"
        for component in parent_components
    ]
    quoted_remote = shlex.quote(remote_path)
    return " && ".join(
        (
            *prechecks,
            f"mkdir -p {shlex.quote(parent)}",
            *postchecks,
            f"test ! -L {quoted_remote}",
            f"([ ! -e {quoted_remote} ] || test -f {quoted_remote})",
        )
    )


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_pre_agent_setup_artifacts(
    sandbox: Any,
    *,
    daytona_policy_hardening: DaytonaPolicyHardening | None,
    enforcement_mode: str,
) -> None:
    """Remove probe scratch and native installer assets before the workload."""

    asset_dir = None
    if enforcement_mode == "native" and daytona_policy_hardening is not None:
        asset_dir = posixpath.normpath(daytona_policy_hardening.asset_dir)
    if asset_dir is not None and asset_dir != DEFAULT_HARDENING_ASSET_DIR:
        raise RuntimeError(
            "failed to remove native hardening assets: unsafe asset directory"
        )

    quoted_scratch_dirs = tuple(
        shlex.quote(path) for path in _PRE_AGENT_PROBE_SCRATCH_DIRS
    )
    quoted_scratch_globs = tuple(
        f"{shlex.quote(pattern.removesuffix('*'))}*"
        for pattern in _PRE_AGENT_PROBE_SCRATCH_GLOBS
    )
    find_expression = " ".join(
        (
            "\\(",
            " -o ".join(
                f"-name {shlex.quote(posixpath.basename(pattern))}"
                for pattern in _PRE_AGENT_PROBE_SCRATCH_GLOBS
            ),
            "\\)",
        )
    )
    scratch_command = (
        f"rm -rf -- {' '.join((*quoted_scratch_dirs, *quoted_scratch_globs))} && "
        + " && ".join(f"test ! -e {path}" for path in quoted_scratch_dirs)
        + f' && scratch_matches="$(find /tmp -maxdepth 1 {find_expression} '
        '-print -quit)" && test -z "$scratch_matches"'
    )
    scratch_result = sandbox.process.exec(
        scratch_command,
        timeout=30,
    )
    if getattr(scratch_result, "exit_code", 1) != 0:
        raise RuntimeError("failed to remove pre-agent probe scratch")

    if asset_dir is None:
        return

    asset_dir = shlex.quote(asset_dir)
    result = sandbox.process.exec(
        f"rm -rf -- {asset_dir} && test ! -e {asset_dir}", timeout=30
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError("failed to remove native hardening assets")


def _upload_text_to_sandbox(sandbox: Any, *, content: str, remote_path: str) -> None:
    """Upload ``content`` to ``remote_path`` via a local temp file, then chmod 644.

    Mirrors the historic prompt-file upload lifecycle: write a local temp, upload
    it, unlink the local temp even on failure, then make the remote file
    world-readable so the agent (which may run as a different user) can read it.
    """

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(content)
        local_path = f.name
    try:
        retry_daytona_transport(
            lambda: sandbox.fs.upload_file(local_path, remote_path),
            operation_name=f"upload {remote_path}",
        )
    finally:
        try:
            os.unlink(local_path)
        except OSError:
            pass
    retry_daytona_transport(
        lambda: sandbox.process.exec(f"chmod 644 {remote_path}", timeout=30),
        operation_name=f"chmod {remote_path}",
    )


def _upload_task_prompt(
    sandbox: Any,
    *,
    task_identifier: str,
    prompt_text: str,
    policy_prompt_fragment: str | None,
    allowlist_file_content: str | None,
) -> str:
    """Write the task prompt (and, when disclosed, the egress allowlist) into /tmp.

    When ``policy_prompt_fragment`` is provided it is prepended to ``prompt_text``
    with a single blank-line separator; otherwise the prompt file is byte-identical
    to ``prompt_text``. The allowlist file is written only when
    ``allowlist_file_content`` is provided. Both land under /tmp and survive
    ``remove_pre_agent_setup_artifacts`` (neither path matches its scratch set).

    Returns the exact prompt text uploaded (the "as delivered" string) so the
    caller can record it as the run's prompt — the transcript and eval-log must
    show what the agent actually received, not the pre-composition task text.
    """

    phase_started = time.perf_counter()
    phase_status = "success"
    try:
        prompt_content = compose_prompt(
            fragment=policy_prompt_fragment, task_text=prompt_text
        )
        _upload_text_to_sandbox(
            sandbox, content=prompt_content, remote_path=REMOTE_PROMPT_PATH
        )
        if allowlist_file_content is not None:
            _upload_text_to_sandbox(
                sandbox,
                content=allowlist_file_content,
                remote_path=REMOTE_ALLOWED_DOMAINS_PATH,
            )
    except Exception:
        phase_status = "error"
        raise
    finally:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=task_identifier,
            phase="prompt_upload",
            started_at=phase_started,
            status=phase_status,
        )
    return prompt_content


def run_terminalbench_task_in_daytona(
    sandbox: Any,
    bundle: TerminalBenchTaskBundle,
    *,
    daytona_policy_hardening: DaytonaPolicyHardening | None,
    openrouter_api_key: str,
    model: str = DEFAULT_OPENROUTER_MODEL,
    agent_workdir: str = DEFAULT_AGENT_WORKDIR,
    workspace_root: str = DEFAULT_AGENT_WORKDIR,
    agent_timeout_sec: int = 3600,
    requested_agent_timeout_sec: int | None = None,
    task_config_agent_timeout_sec: int | None = None,
    isolate_network: bool = False,
    block_network: bool = False,
    block_child_shell_network: bool = True,
    full_mac_enforcement: bool = False,
    run_agent_as_root: bool = False,
    hardening_config_metadata: dict[str, Any] | None = None,
    preflight: dict[str, Any] | None = None,
    runtime_policy_probe_report: dict[str, Any] | None = None,
    remote_tests_dir: str = REMOTE_TESTS_DIR,
    agentsh_session_id: str | None = None,
    agentsh_policy_session: dict[str, Any] | None = None,
    enforcement_mode: str = "legacy",
    harness: HarnessAdapter,
    effort_level: str | None = None,
    policy_prompt_fragment: str | None = None,
    allowlist_file_content: str | None = None,
    policy_prompt_provenance: dict[str, Any] | None = None,
) -> TerminalBenchRunResult:
    return _run_with_phase_timing_capture(
        _run_terminalbench_task_in_daytona_impl,
        sandbox,
        bundle,
        daytona_policy_hardening=daytona_policy_hardening,
        openrouter_api_key=openrouter_api_key,
        model=model,
        agent_workdir=agent_workdir,
        workspace_root=workspace_root,
        agent_timeout_sec=agent_timeout_sec,
        requested_agent_timeout_sec=requested_agent_timeout_sec,
        task_config_agent_timeout_sec=task_config_agent_timeout_sec,
        isolate_network=isolate_network,
        block_network=block_network,
        block_child_shell_network=block_child_shell_network,
        full_mac_enforcement=full_mac_enforcement,
        run_agent_as_root=run_agent_as_root,
        hardening_config_metadata=hardening_config_metadata,
        preflight=preflight,
        runtime_policy_probe_report=runtime_policy_probe_report,
        remote_tests_dir=remote_tests_dir,
        agentsh_session_id=agentsh_session_id,
        agentsh_policy_session=agentsh_policy_session,
        enforcement_mode=enforcement_mode,
        harness=harness,
        effort_level=effort_level,
        policy_prompt_fragment=policy_prompt_fragment,
        allowlist_file_content=allowlist_file_content,
        policy_prompt_provenance=policy_prompt_provenance,
    )


def _run_terminalbench_task_in_daytona_impl(
    sandbox: Any,
    bundle: TerminalBenchTaskBundle,
    *,
    daytona_policy_hardening: DaytonaPolicyHardening | None,
    openrouter_api_key: str,
    model: str = DEFAULT_OPENROUTER_MODEL,
    agent_workdir: str = DEFAULT_AGENT_WORKDIR,
    workspace_root: str = DEFAULT_AGENT_WORKDIR,
    agent_timeout_sec: int = 3600,
    requested_agent_timeout_sec: int | None = None,
    task_config_agent_timeout_sec: int | None = None,
    isolate_network: bool = False,
    block_network: bool = False,
    block_child_shell_network: bool = True,
    full_mac_enforcement: bool = False,
    run_agent_as_root: bool = False,
    hardening_config_metadata: dict[str, Any] | None = None,
    preflight: dict[str, Any] | None = None,
    runtime_policy_probe_report: dict[str, Any] | None = None,
    remote_tests_dir: str = REMOTE_TESTS_DIR,
    agentsh_session_id: str | None = None,
    agentsh_policy_session: dict[str, Any] | None = None,
    enforcement_mode: str = "legacy",
    harness: HarnessAdapter,
    effort_level: str | None = None,
    policy_prompt_fragment: str | None = None,
    allowlist_file_content: str | None = None,
    policy_prompt_provenance: dict[str, Any] | None = None,
) -> TerminalBenchRunResult:
    """Run the hardened agent in the task workspace, then the official verifier.

    `sandbox` must be provisioned by `provision_hardened_task_sandbox`. The agent
    (Claude Code driving an OpenRouter model) runs in the image's workdir under
    the selected policy's overlay stack. Hardened policy defaults keep the
    model-API network open, block tool-child network egress, and run the agent
    as the non-root Daytona user. The "control" policy passes all-False with the
    blank hardening config, so only Daytona/task-image baseline behavior
    remains. The verifier runs unhardened (it needs internet for uv/pytest).
    ``harness`` is required so hardening metadata never depends on an implicit
    adapter default.
    """

    task_started = time.perf_counter()
    task_identifier = bundle.task_name
    effective_effort_level = normalize_effort_level(harness, effort_level)
    effective_effort_level_source = effort_level_source(effort_level)
    delivered_prompt = _upload_task_prompt(
        sandbox,
        task_identifier=task_identifier,
        prompt_text=bundle.input,
        policy_prompt_fragment=policy_prompt_fragment,
        allowlist_file_content=allowlist_file_content,
    )

    agent_env = harness.agent_env(
        provider_api_key=openrouter_api_key, run_as_root=run_agent_as_root
    )
    agent_command = harness.agent_command(
        model=model,
        prompt_path=REMOTE_PROMPT_PATH,
        run_as_root=run_agent_as_root,
        effort_level=effective_effort_level,
    )
    phase_started = time.perf_counter()
    phase_status = "success"
    remove_pre_agent_setup_artifacts(
        sandbox,
        daytona_policy_hardening=daytona_policy_hardening,
        enforcement_mode=enforcement_mode,
    )
    if daytona_policy_hardening is None:
        command_to_run = f"cd {shlex.quote(agent_workdir)} && {agent_command}"
        if agentsh_session_id is not None:
            command_to_run = wrap_command_for_agentsh_session(
                session_id=agentsh_session_id,
                command=command_to_run,
                timeout_seconds=agent_timeout_sec,
            )
        try:
            agent_result = _run_command_with_deadline(
                sandbox,
                command=command_to_run,
                env=agent_env,
                timeout=agent_timeout_sec,
                capture_output_to_files=True,
            )
        except Exception as exc:
            phase_status = "error"
            _attach_session_artifacts_to_exception(
                exc, sandbox, harness=harness, run_as_root=run_agent_as_root
            )
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="agent_run",
                started_at=phase_started,
                status=phase_status,
                hardened=False,
            )
            _run_harness_post_agent_cleanup(
                sandbox, harness=harness, run_as_root=run_agent_as_root
            )
        effective_hardening_config = hardening_config_metadata or {}
        policy_events = harvest_passive_telemetry(
            sandbox,
            agent_stdout=getattr(agent_result, "stdout", "") or "",
            hardening_config=effective_hardening_config,
        )
    else:
        clear_policy_event_log(sandbox)
        effective_hardening = daytona_policy_hardening.hardening_config
        phase_started = time.perf_counter()
        try:
            agent_result = run_with_daytona_policy_hardening(
                sandbox,
                daytona_policy_hardening=daytona_policy_hardening,
                command=agent_command,
                cwd=agent_workdir,
                workspace=workspace_root,
                timeout=agent_timeout_sec,
                isolate_network=isolate_network,
                block_network=block_network,
                block_child_shell_network=block_child_shell_network,
                full_mac_enforcement=full_mac_enforcement,
                env=agent_env,
                run_as_root=run_agent_as_root,
                agentsh_session_id=agentsh_session_id,
                enforcement_mode=enforcement_mode,
                capture_output_to_files=True,
            )
        except Exception as exc:
            phase_status = "error"
            _attach_session_artifacts_to_exception(
                exc, sandbox, harness=harness, run_as_root=run_agent_as_root
            )
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="agent_run",
                started_at=phase_started,
                status=phase_status,
                hardened=True,
            )
            _run_harness_post_agent_cleanup(
                sandbox, harness=harness, run_as_root=run_agent_as_root
            )
        phase_started = time.perf_counter()
        phase_status = "success"
        try:
            policy_events = harvest_passive_telemetry(
                sandbox,
                agent_stdout=getattr(agent_result, "stdout", "") or "",
                hardening_config=effective_hardening,
            )
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="policy_event_read",
                started_at=phase_started,
                status=phase_status,
            )
        effective_hardening_config = effective_hardening.to_metadata()

    session_artifacts = _try_read_harness_session_artifacts(
        sandbox, harness=harness, run_as_root=run_agent_as_root
    )

    phase_started = time.perf_counter()
    phase_status = "success"
    try:
        verifier_kwargs: dict[str, Any] = {"remote_tests_dir": remote_tests_dir}
        if agent_workdir != DEFAULT_AGENT_WORKDIR:
            verifier_kwargs["remote_workdir"] = agent_workdir
        verifier = run_daytona_harbor_verifier(
            sandbox,
            bundle,
            **verifier_kwargs,
        )
    except Exception:
        phase_status = "error"
        raise
    finally:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=task_identifier,
            phase="harbor_verifier",
            started_at=phase_started,
            status=phase_status,
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=task_identifier,
            phase="task_run_total",
            started_at=task_started,
            status=phase_status,
        )

    openrouter_accounting = read_openrouter_accounting(sandbox)

    return TerminalBenchRunResult(
        sample_id=bundle.sample_id,
        task_name=bundle.task_name,
        prompt=delivered_prompt,
        reward=verifier.value,
        answer=verifier.answer,
        agent_exit_code=getattr(agent_result, "exit_code", None),
        agent_stdout=getattr(agent_result, "stdout", "") or "",
        agent_stderr=getattr(agent_result, "stderr", "") or "",
        agent_timed_out=getattr(agent_result, "timed_out", False),
        requested_agent_timeout_sec=requested_agent_timeout_sec,
        task_config_agent_timeout_sec=task_config_agent_timeout_sec,
        effective_agent_timeout_sec=agent_timeout_sec,
        sandbox_id=_sandbox_id(sandbox),
        verifier=verifier,
        hardening_config=effective_hardening_config,
        policy_prompt_provenance=dict(policy_prompt_provenance or {}),
        policy_events=policy_events,
        openrouter_accounting=openrouter_accounting,
        preflight=preflight,
        runtime_policy_probe_report=runtime_policy_probe_report,
        agentsh_agent_wrapped=agentsh_session_id is not None,
        agentsh_session_id=agentsh_session_id,
        agentsh_policy_session=agentsh_policy_session,
        agent_workdir=agent_workdir,
        workspace_root=workspace_root,
        harness_session_artifacts=session_artifacts,
        harness=harness.name,
        effort_level=effective_effort_level,
        effort_level_source=effective_effort_level_source,
        effort_level_applied=harness.effort_level_applied,
    )


def read_agent_version(
    sandbox: Any, *, harness: HarnessAdapter, run_as_root: bool
) -> str | None:
    """Best-effort ``<agent binary> --version`` for run metadata.

    Harbor records the installed agent version with every run; the install pin
    can still drift (env override, upstream re-tag), so the evidence comes from
    the provisioned sandbox rather than the pin constant. Never raises — a
    missing version must not fail or retry a run.
    """

    agent_bin = harness.agent_binary_path(run_as_root=run_as_root)
    try:
        result = sandbox.process.exec(f"{shlex.quote(agent_bin)} --version", timeout=30)
        if getattr(result, "exit_code", 1) != 0:
            return None
        output = str(getattr(result, "result", "") or "").strip()
        return output.splitlines()[0].strip() if output else None
    except Exception as exc:  # noqa: BLE001 - metadata must not change the run
        print(
            f"[terminalbench-daytona] WARN agent version read failed: {exc!r}",
            flush=True,
        )
        return None


def _run_harness_post_agent_cleanup(
    sandbox: Any, *, harness: HarnessAdapter, run_as_root: bool
) -> None:
    """Best-effort controller cleanup for harness daemons that outlive a kill."""

    if not isinstance(harness, HarnessPostAgentCleanup):
        return
    command = harness.post_agent_cleanup_command(run_as_root=run_as_root)
    if not command:
        return
    try:
        sandbox.process.exec(command, timeout=30)
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask run evidence
        print(
            f"[terminalbench-daytona] WARN harness cleanup failed: {exc!r}",
            flush=True,
        )


_SESSION_FILE_SENTINEL = "===INSPECT-BOUNDARY-SESSION-FILE"
_SESSION_B64_FILE_SENTINEL = "===INSPECT-BOUNDARY-SESSION-B64"
_SESSION_COUNT_SENTINEL = "===INSPECT-BOUNDARY-SESSION-COUNT"
_SESSION_SENTINEL_RE = re.compile(
    rf"^{re.escape(_SESSION_FILE_SENTINEL)} (?P<path>.+) (?P<size>\d+)===$"
)
_SESSION_B64_SENTINEL_RE = re.compile(
    rf"^{re.escape(_SESSION_B64_FILE_SENTINEL)} "
    rf"(?P<path>[A-Za-z0-9+/=]+) (?P<size>\d+)===$"
)


def _parse_session_artifact_stream(
    output: str,
) -> tuple[int | None, list[dict[str, Any]]]:
    """Parse the sentinel-delimited find/head stream into file entries."""

    total_count: int | None = None
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    content_lines: list[str] = []

    def _finish() -> None:
        nonlocal current, content_lines
        if current is None:
            return
        encoded = current.get("encoding") == "base64"
        content = "\n".join(content_lines)
        if encoded:
            try:
                if content_lines and content_lines[-1] == "":
                    content = "\n".join(content_lines[:-1])
                padded = content + "=" * (-len(content) % 4)
                decoded = base64.b64decode(padded, validate=True)
                content = decoded.decode("utf-8", errors="replace")
            except (ValueError, UnicodeDecodeError):
                content = ""
                current["truncated"] = True
        elif content.endswith("\n"):
            content = content[:-1]
        current["content"] = content
        current["truncated"] = bool(current.get("truncated")) or current[
            "size_bytes"
        ] > (len(content.encode("utf-8", errors="replace")) + 1)
        current.pop("encoding", None)
        files.append(current)
        current = None
        content_lines = []

    for line in output.split("\n"):
        if line.startswith(_SESSION_COUNT_SENTINEL):
            digits = "".join(ch for ch in line if ch.isdigit())
            total_count = int(digits) if digits else None
            continue
        b64_match = _SESSION_B64_SENTINEL_RE.match(line)
        if b64_match:
            _finish()
            try:
                path = base64.b64decode(b64_match.group("path"), validate=True).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, UnicodeDecodeError):
                path = "[invalid-path]"
            current = {
                "path": path,
                "size_bytes": int(b64_match.group("size")),
                "encoding": "base64",
            }
            continue
        match = _SESSION_SENTINEL_RE.match(line)
        if match:
            _finish()
            current = {
                "path": match.group("path"),
                "size_bytes": int(match.group("size")),
            }
            continue
        if current is not None:
            content_lines.append(line)
    _finish()
    return total_count, files


def _try_read_harness_session_artifacts(
    sandbox: Any, *, harness: HarnessAdapter, run_as_root: bool
) -> dict[str, Any] | None:
    """Export the harness's native session/rollout logs from the sandbox.

    Runs after the agent phase — on success and on failure — and strictly
    before sandbox teardown (harbor copies ``$CODEX_HOME/sessions`` to the
    agent log dir the same way). Read-only and best-effort: NEVER raises and
    never changes the run outcome; a failed export degrades to ``None``.
    """

    dirs = tuple(harness.session_artifact_dirs(run_as_root=run_as_root))
    if not dirs:
        return None
    phase_started = time.perf_counter()
    phase_status = "success"
    try:
        quoted_dirs = " ".join(shlex.quote(d) for d in dirs)
        script = (
            f'count="$(find {quoted_dirs} -type f 2>/dev/null | wc -l)"\n'
            f'echo "{_SESSION_COUNT_SENTINEL} ${{count}}==="\n'
            f"find {quoted_dirs} -type f 2>/dev/null | sort "
            f"| head -n {MAX_SESSION_ARTIFACT_FILES} "
            f"| while IFS= read -r f; do\n"
            f'  size="$(wc -c < "$f" 2>/dev/null || echo 0)"\n'
            f'  path_b64="$(printf "%s" "$f" | base64 -w0)"\n'
            f'  echo "{_SESSION_B64_FILE_SENTINEL} $path_b64 $size==="\n'
            f'  head -c {MAX_SESSION_ARTIFACT_FILE_BYTES} "$f" 2>/dev/null | base64 -w0\n'
            f"  echo\n"
            f"done | head -c {MAX_SESSION_ARTIFACT_TOTAL_BYTES}"
        )
        result = sandbox.process.exec(script, timeout=120)
        output = str(getattr(result, "result", "") or "")
        total_count, files = _parse_session_artifact_stream(output)
        if total_count in (0, None) and not files:
            return None
        exported = len(files)
        truncated = (
            any(entry["truncated"] for entry in files)
            or (total_count is not None and total_count > exported)
            or len(output) >= MAX_SESSION_ARTIFACT_TOTAL_BYTES
        )
        return {
            "harness": harness.name,
            "source_dirs": list(dirs),
            "file_count": total_count if total_count is not None else exported,
            "exported_file_count": exported,
            "truncated": truncated,
            "files": files,
        }
    except Exception as exc:  # noqa: BLE001 - export must not change the run
        phase_status = "error"
        print(
            "[terminalbench-daytona] WARN harness session artifact read "
            f"failed: {exc!r}",
            flush=True,
        )
        return None
    finally:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=getattr(sandbox, "id", "") or "sandbox",
            phase="session_artifact_read",
            started_at=phase_started,
            status=phase_status,
        )


def _attach_session_artifacts_to_exception(
    exc: BaseException, sandbox: Any, *, harness: HarnessAdapter, run_as_root: bool
) -> None:
    """Best-effort session export for a failing agent phase.

    The artifacts ride the exception (like phase timings) so the failure
    metadata path can persist them; the original exception is re-raised by
    the caller unmodified otherwise.
    """

    artifacts = _try_read_harness_session_artifacts(
        sandbox, harness=harness, run_as_root=run_as_root
    )
    if artifacts is not None:
        exc.harness_session_artifacts = artifacts  # type: ignore[attr-defined]


def _read_policy_events(sandbox: Any) -> list[dict[str, Any]]:
    result = sandbox.process.exec(
        "cat /tmp/boundarybench-policy-events.jsonl 2>/dev/null || true",
        timeout=15,
    )
    output = getattr(result, "result", "") or ""
    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _sandbox_state(sandbox: Any) -> str:
    state = getattr(sandbox, "state", None)
    return str(getattr(state, "value", state) or "").upper()


def _sandbox_labels(sandbox: Any) -> dict[str, Any]:
    labels = getattr(sandbox, "labels", None)
    return labels if isinstance(labels, dict) else {}


def _sandbox_create_labels() -> dict[str, str]:
    labels = dict(SANDBOX_LABELS)
    run_id = os.environ.get(SANDBOX_RUN_ID_ENV)
    if run_id:
        labels[SANDBOX_MANAGED_BY_LABEL] = _run_scoped_managed_by(run_id)
        labels[SANDBOX_RUN_ID_LABEL] = run_id
    return labels


def _run_scoped_managed_by(run_id: str) -> str:
    return f"{SANDBOX_MANAGED_BY_VALUE}-{run_id}"


def _print_phase_timing(
    *,
    component: str,
    identifier: str,
    phase: str,
    started_at: float,
    status: str,
    **fields: object,
) -> None:
    elapsed_ms = max(0, int((time.perf_counter() - started_at) * 1000))
    recorder = _PHASE_TIMING_RECORDER.get()
    if recorder is not None:
        recorder.record(
            {
                "component": component,
                "id": str(identifier),
                "phase": phase,
                "elapsed_ms": elapsed_ms,
                "status": status,
                **fields,
            }
        )
    details = " ".join(
        f"{key}={_phase_timing_value(value)}" for key, value in fields.items()
    )
    suffix = f" {details}" if details else ""
    print(
        "phase_timing "
        f"component={component} "
        f"id={_phase_timing_value(identifier)} "
        f"phase={phase} "
        f"elapsed_ms={elapsed_ms} "
        f"status={status}"
        f"{suffix}",
        flush=True,
    )


def _phase_timing_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value).replace(" ", "_")


def _sandbox_is_owned(
    labels: dict[str, Any],
    run_id: str | None,
) -> bool:
    namespace = labels.get(SANDBOX_NAMESPACE_LABEL)
    if namespace is not None:
        if namespace != SANDBOX_MANAGED_BY_VALUE:
            return False
    managed_by = labels.get(SANDBOX_MANAGED_BY_LABEL)
    if run_id is not None:
        labelled_run_id = labels.get(SANDBOX_RUN_ID_LABEL)
        managed_by_matches = managed_by == _run_scoped_managed_by(run_id)
        has_run_scoped_managed_by = isinstance(
            managed_by, str
        ) and managed_by.startswith(f"{SANDBOX_MANAGED_BY_VALUE}-")
        if labelled_run_id is not None and has_run_scoped_managed_by:
            return labelled_run_id == run_id and managed_by_matches
        return labelled_run_id == run_id or managed_by_matches
    return managed_by == SANDBOX_MANAGED_BY_VALUE or (
        isinstance(managed_by, str)
        and managed_by.startswith(f"{SANDBOX_MANAGED_BY_VALUE}-")
    )


def _is_delete_race(exc: Exception) -> bool:
    """Return true when Daytona reports an already-gone/deleting sandbox."""

    class_name = exc.__class__.__name__.lower()
    message = f"{exc!s} {exc!r}".lower()
    if "notfound" in class_name or "conflict" in class_name:
        return True
    if any(token in message for token in ("not found", "already deleted")):
        return True
    if any(token in message for token in ("404", "409", "conflict")):
        return True
    for attr in ("status", "status_code", "code"):
        value = getattr(exc, attr, None)
        if value in (404, 409, "404", "409"):
            return True
    return False


def _is_not_found_delete_race(exc: Exception) -> bool:
    """Return true only when deletion proves the sandbox is already absent."""

    class_name = exc.__class__.__name__.lower()
    if "notfound" in class_name:
        return True
    for attr in ("status", "status_code", "code"):
        value = getattr(exc, attr, None)
        if value in (404, "404"):
            return True
    return False


def reap_stale_terminalbench_sandboxes(
    daytona: Any,
    *,
    run_id: str | None = None,
    include_running: bool = False,
    strict_list: bool = False,
) -> tuple[int, int]:
    """Delete leftover sandboxes we own.

    Belt-and-suspenders for the per-task finally-delete and Daytona's own
    auto_delete. By default, sweeps only terminal/idle states so a concurrent
    batch is never disturbed. A completed Cloud Run batch passes its own run id
    with ``include_running=True`` so positively owned sandboxes that remain
    STARTED after the eval can be removed. Run-scoped cleanup never claims a
    sandbox carrying only the legacy managed label.
    """

    safe_to_delete = {"STOPPED", "ARCHIVED", "ERROR", "DESTROYED"}
    deleted = failed = 0
    confirmed_absent_ids: set[str] = set()

    try:
        sandboxes = daytona.list()
    except Exception:
        if strict_list:
            raise
        return (deleted, failed)
    for sandbox in sandboxes:
        labels = _sandbox_labels(sandbox)
        if not _sandbox_is_owned(labels, run_id):
            continue
        if not include_running and _sandbox_state(sandbox) not in safe_to_delete:
            continue
        try:
            daytona.delete(sandbox)
            deleted += 1
        except Exception as exc:
            if _is_not_found_delete_race(exc):
                sandbox_id = _sandbox_id(sandbox)
                if sandbox_id is not None:
                    confirmed_absent_ids.add(sandbox_id)
                continue
            if _is_delete_race(exc):
                continue
            failed += 1
    if strict_list:
        remaining = [
            sandbox
            for sandbox in daytona.list()
            if _sandbox_is_owned(_sandbox_labels(sandbox), run_id)
            and _sandbox_id(sandbox) not in confirmed_absent_ids
            and (
                include_running
                or _sandbox_state(sandbox) in safe_to_delete
            )
        ]
        failed = max(failed, len(remaining))
    return (deleted, failed)


@dataclass(frozen=True)
class TerminalBenchAgentRunResult:
    """Agent-phase outcome before clean postflight verification."""

    sample_id: str
    task_name: str
    prompt: str
    agent_exit_code: int | None
    agent_stdout: str
    agent_stderr: str = ""
    agent_timed_out: bool = False
    requested_agent_timeout_sec: int | None = None
    task_config_agent_timeout_sec: int | None = None
    effective_agent_timeout_sec: int | None = None
    hardening_config: dict[str, Any] = field(default_factory=dict)
    policy_prompt_provenance: dict[str, Any] = field(default_factory=dict)
    recovery_bundle_provenance: dict[str, Any] = field(default_factory=dict)
    policy_events: list[dict[str, Any]] = field(default_factory=list)
    preflight: dict[str, Any] | None = None
    runtime_policy_probe_report: dict[str, Any] | None = None
    openrouter_accounting: dict[str, Any] | None = None
    agentsh_agent_wrapped: bool = False
    agentsh_session_id: str | None = None
    agentsh_policy_session: dict[str, Any] | None = None
    agent_pid_namespace_isolation_observed: bool = False
    agent_workdir: str = DEFAULT_AGENT_WORKDIR
    workspace_root: str = DEFAULT_AGENT_WORKDIR
    harness_session_artifacts: dict[str, Any] | None = None
    agent_session_id: str | None = None
    agent_session_preserved: bool = False
    post_agent_listeners: str | None = None
    effort_level: str = field(kw_only=True)
    effort_level_source: str = field(kw_only=True)
    effort_level_applied: bool = field(kw_only=True)


def run_terminalbench_agent_in_daytona(
    sandbox: Any,
    bundle: TerminalBenchTaskBundle,
    *,
    daytona_policy_hardening: DaytonaPolicyHardening | None,
    openrouter_api_key: str,
    harness: HarnessAdapter,
    model: str = DEFAULT_OPENROUTER_MODEL,
    agent_workdir: str = DEFAULT_AGENT_WORKDIR,
    workspace_root: str = DEFAULT_AGENT_WORKDIR,
    agent_timeout_sec: int = 3600,
    requested_agent_timeout_sec: int | None = None,
    task_config_agent_timeout_sec: int | None = None,
    isolate_network: bool = False,
    block_network: bool = False,
    block_child_shell_network: bool = True,
    full_mac_enforcement: bool = False,
    run_agent_as_root: bool = False,
    hardening_config_metadata: dict[str, Any] | None = None,
    preflight: dict[str, Any] | None = None,
    runtime_policy_probe_report: dict[str, Any] | None = None,
    agentsh_session_id: str | None = None,
    agentsh_policy_session: dict[str, Any] | None = None,
    enforcement_mode: str = "legacy",
    effort_level: str | None = None,
    policy_prompt_fragment: str | None = None,
    allowlist_file_content: str | None = None,
    policy_prompt_provenance: dict[str, Any] | None = None,
    isolate_agent_pid_namespace: bool = False,
    preserve_agent_session: bool = False,
) -> TerminalBenchAgentRunResult:
    """Run only the agent phase in the task workspace (no verifier).

    This is the agent half of ``_run_terminalbench_task_in_daytona_impl``, used
    by split agent/verifier orchestration. The caller independently decides
    whether the verifier reuses this sandbox or runs in a clean one, and whether
    the agent needs a kill-on-exit PID namespace. ``harness`` builds the agent
    env/command so hardening metadata never depends on an implicit adapter
    default.

    ``preserve_agent_session`` keeps the agent's Daytona session alive so its
    background daemons survive into the shared-sandbox verifier for declared
    live-service tasks; the eval layer deletes the session after verification.
    """

    task_identifier = bundle.task_name
    effective_effort_level = normalize_effort_level(harness, effort_level)
    effective_effort_level_source = effort_level_source(effort_level)
    delivered_prompt = _upload_task_prompt(
        sandbox,
        task_identifier=task_identifier,
        prompt_text=bundle.input,
        policy_prompt_fragment=policy_prompt_fragment,
        allowlist_file_content=allowlist_file_content,
    )

    agent_env = harness.agent_env(
        provider_api_key=openrouter_api_key, run_as_root=run_agent_as_root
    )
    if preserve_agent_session:
        agent_env = {**agent_env, PRESERVE_AGENT_SESSION_ENV: "1"}
    agent_command = harness.agent_command(
        model=model,
        prompt_path=REMOTE_PROMPT_PATH,
        run_as_root=run_agent_as_root,
        effort_level=effective_effort_level,
    )
    phase_started = time.perf_counter()
    phase_status = "success"
    remove_pre_agent_setup_artifacts(
        sandbox,
        daytona_policy_hardening=daytona_policy_hardening,
        enforcement_mode=enforcement_mode,
    )
    if daytona_policy_hardening is None:
        command_to_run = f"cd {shlex.quote(agent_workdir)} && {agent_command}"
        if agentsh_session_id is not None:
            command_to_run = wrap_command_for_agentsh_session(
                session_id=agentsh_session_id,
                command=command_to_run,
                timeout_seconds=agent_timeout_sec,
            )
        try:
            agent_result = _run_command_with_deadline(
                sandbox,
                command=command_to_run,
                env=agent_env,
                timeout=agent_timeout_sec,
                capture_output_to_files=True,
                preserve_session=preserve_agent_session,
                session_id_prefix=MODEL_AGENT_SESSION_PREFIX,
                post_command_probe=AGENT_LISTENER_PROBE_COMMAND,
                isolate_agent_pid_namespace=isolate_agent_pid_namespace,
            )
        except Exception as exc:
            phase_status = "error"
            _attach_session_artifacts_to_exception(
                exc, sandbox, harness=harness, run_as_root=run_agent_as_root
            )
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="agent_run",
                started_at=phase_started,
                status=phase_status,
                hardened=False,
                pid_namespace_isolation=isolate_agent_pid_namespace,
            )
            if not preserve_agent_session:
                _run_harness_post_agent_cleanup(
                    sandbox, harness=harness, run_as_root=run_agent_as_root
                )
        effective_hardening_config = hardening_config_metadata or {}
        policy_events = harvest_passive_telemetry(
            sandbox,
            agent_stdout=getattr(agent_result, "stdout", "") or "",
            hardening_config=effective_hardening_config,
        )
    else:
        clear_policy_event_log(sandbox)
        effective_hardening = daytona_policy_hardening.hardening_config
        phase_started = time.perf_counter()
        try:
            agent_result = run_with_daytona_policy_hardening(
                sandbox,
                daytona_policy_hardening=daytona_policy_hardening,
                command=agent_command,
                cwd=agent_workdir,
                workspace=workspace_root,
                timeout=agent_timeout_sec,
                isolate_network=isolate_network,
                block_network=block_network,
                block_child_shell_network=block_child_shell_network,
                full_mac_enforcement=full_mac_enforcement,
                env=agent_env,
                run_as_root=run_agent_as_root,
                agentsh_session_id=agentsh_session_id,
                enforcement_mode=enforcement_mode,
                capture_output_to_files=True,
                preserve_session=preserve_agent_session,
                session_id_prefix=MODEL_AGENT_SESSION_PREFIX,
                post_command_probe=AGENT_LISTENER_PROBE_COMMAND,
                isolate_agent_pid_namespace=isolate_agent_pid_namespace,
            )
        except Exception as exc:
            phase_status = "error"
            _attach_session_artifacts_to_exception(
                exc, sandbox, harness=harness, run_as_root=run_agent_as_root
            )
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="agent_run",
                started_at=phase_started,
                status=phase_status,
                hardened=True,
                pid_namespace_isolation=isolate_agent_pid_namespace,
            )
            if not preserve_agent_session:
                _run_harness_post_agent_cleanup(
                    sandbox, harness=harness, run_as_root=run_agent_as_root
                )
        phase_started = time.perf_counter()
        phase_status = "success"
        try:
            policy_events = harvest_passive_telemetry(
                sandbox,
                agent_stdout=getattr(agent_result, "stdout", "") or "",
                hardening_config=effective_hardening,
            )
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_identifier,
                phase="policy_event_read",
                started_at=phase_started,
                status=phase_status,
            )
        effective_hardening_config = effective_hardening.to_metadata()

    session_artifacts = _try_read_harness_session_artifacts(
        sandbox, harness=harness, run_as_root=run_agent_as_root
    )
    openrouter_accounting = read_openrouter_accounting(sandbox)

    return TerminalBenchAgentRunResult(
        sample_id=bundle.sample_id,
        task_name=bundle.task_name,
        prompt=delivered_prompt,
        agent_exit_code=getattr(agent_result, "exit_code", None),
        agent_stdout=getattr(agent_result, "stdout", "") or "",
        agent_stderr=getattr(agent_result, "stderr", "") or "",
        agent_timed_out=getattr(agent_result, "timed_out", False),
        requested_agent_timeout_sec=requested_agent_timeout_sec,
        task_config_agent_timeout_sec=task_config_agent_timeout_sec,
        effective_agent_timeout_sec=agent_timeout_sec,
        hardening_config=effective_hardening_config,
        policy_prompt_provenance=dict(policy_prompt_provenance or {}),
        policy_events=policy_events,
        openrouter_accounting=openrouter_accounting,
        preflight=preflight,
        runtime_policy_probe_report=runtime_policy_probe_report,
        agentsh_agent_wrapped=agentsh_session_id is not None,
        agentsh_session_id=agentsh_session_id,
        agentsh_policy_session=agentsh_policy_session,
        agent_pid_namespace_isolation_observed=getattr(
            agent_result, "pid_namespace_isolation_applied", False
        ),
        agent_workdir=agent_workdir,
        workspace_root=workspace_root,
        harness_session_artifacts=session_artifacts,
        agent_session_id=getattr(agent_result, "session_id", None),
        agent_session_preserved=bool(
            preserve_agent_session and getattr(agent_result, "session_id", None)
        ),
        post_agent_listeners=getattr(agent_result, "post_command_probe_output", None),
        effort_level=effective_effort_level,
        effort_level_source=effective_effort_level_source,
        effort_level_applied=harness.effort_level_applied,
    )
