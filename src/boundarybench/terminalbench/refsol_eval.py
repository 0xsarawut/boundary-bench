"""Inspect task that runs Terminal-Bench reference solutions in Daytona sandboxes.

The canonical shipped ``solution/solve.sh`` for a task can run either on the
raw Daytona baseline (``policy=none``) or through the same native hardening
boundary used by agent runs. Harbor's official verifier remains the sole score
authority in both modes.

Each sample provisions a Daytona sandbox from the task's own Docker image,
uploads the shipped reference solution, runs it in an async Daytona session
that is never deleted (a session's ``delete_session`` cleanup can reap daemons
the solution started, e.g. pypi-server, before the verifier runs), then scores
with Harbor's official verifier.

There is no agent, harness runtime, or model call. Pass
``--model mockllm/model``.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import functools
import hashlib
import os
import re
import shlex
import tempfile
import threading
import time
import tomllib
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, Solver, TaskState, solver

import boundarybench.benchmarks.common.daytona as benchmark_daytona
from boundarybench.benchmarks.common.status_taxonomy import (
    DAYTONA_CONNECTION_MARKERS,
    DAYTONA_LIFECYCLE_MARKERS,
    EvalArtifactStatus,
    JobStatus,
    is_daytona_account_capacity_error,
    sample_benchmark_status,
)
from boundarybench.provenance import runtime_provenance
from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    install_daytona_policy_hardening,
    run_with_daytona_policy_hardening,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)
from boundarybench.daytona.policy_telemetry import (
    clear_policy_event_log,
    harvest_passive_telemetry,
)
from boundarybench.daytona.runtime_policy_probes import (
    RUNTIME_POLICY_PROBE_WORKSPACE,
    DaytonaRuntimeProbeSuiteError,
    ensure_runtime_policy_probe_suite_passed,
    run_runtime_policy_probe_suite_in_sandbox,
)
from boundarybench.terminalbench.daytona import (
    DaytonaVerifierResult,
    TerminalBenchTaskBundle,
    load_terminalbench_daytona_bundle,
    run_daytona_harbor_verifier,
    tar_directory_bytes,
    validate_shared_root_verifier_admission,
)
from boundarybench.terminalbench.daytona_constants import (
    DEFAULT_HARDENING_ASSET_DIR,
    SANDBOX_AUTO_DELETE_MIN,
    SANDBOX_RUN_ID_ENV,
)
from boundarybench.terminalbench.daytona_preflight import (
    PreflightFailedError,
    run_preflight,
)
from boundarybench.terminalbench.daytona_run import (
    _is_delete_race,
    _print_phase_timing,
    _sandbox_auto_stop_min,
    _sandbox_create_labels,
    _sandbox_is_owned,
    _sandbox_labels,
    daytona_task_resources,
    remove_pre_agent_setup_artifacts,
    reap_stale_terminalbench_sandboxes,
    task_docker_image,
)
from boundarybench.terminalbench.harbor import DEFAULT_TERMINAL_BENCH_2_1_REF
from boundarybench.terminalbench.task_applicability import applicability_metadata
from boundarybench.terminalbench.daytona_runtime_layer import (
    render_sandbox_base_script,
)
from boundarybench.terminalbench.policies import (
    HardeningPolicy,
    resolve_policy_for_run,
)
from boundarybench.terminalbench.task_config import (
    SUPPORTED_TASK_WORKSPACE_ROOTS,
    terminalbench_workspace_from_bundle,
)

_HARBOR_LOAD_LOCK = threading.Lock()

REFSOL_DEFAULT_TASK_IDS = "log-summary-date-ranges,openssl-selfsigned-cert,pypi-server"
REFSOL_NO_POLICY = "none"
REFSOL_NATIVE_POLICIES = frozenset(
    {"non-root", "low-nist", "moderate-nist", "high-nist"}
)
ENG_3310_ROOTLESS_WITNESS_VARIANT = "solvability-witnesses"
ENG_3310_ROOTLESS_WITNESS_TASK_IDS = frozenset(
    {
        "sqlite-with-gcov",
        "build-pmars",
        "adaptive-rejection-sampler",
        "make-doom-for-mips",
        "caffe-cifar-10",
    }
)
_ROOTLESS_WITNESSES_DIR = (
    Path(__file__).resolve().parent / "refsol_rootless_witnesses"
)
STATIC_EGRESS_WITNESS_VARIANT = "static-egress-witnesses"
STATIC_EGRESS_WITNESS_TASK_IDS = frozenset(
    {
        "bn-fit-modify",
        "build-cython-ext",
        "build-pmars",
        "build-pov-ray",
        "caffe-cifar-10",
        "chess-best-move",
        "cobol-modernization",
        "compile-compcert",
        "crack-7z-hash",
        "dna-assembly",
        "dna-insert",
        "financial-document-processor",
        "gcode-to-text",
        "hf-model-inference",
        "install-windows-3.11",
        "largest-eigenval",
        "log-summary-date-ranges",
        "make-doom-for-mips",
        "mcmc-sampling-stan",
        "merge-diff-arc-agi-task",
        "mteb-retrieve",
        "nginx-request-logging",
        "overfull-hbox",
        "protein-assembly",
        "pypi-server",
        "pytorch-model-cli",
        "rstan-to-pystan",
        "sam-cell-seg",
        "train-fasttext",
        "fix-git",
        "custom-memory-heap-crash",
        "qemu-alpine-ssh",
        "git-multibranch",
        "mailman",
        "configure-git-webserver",
    }
)
_NETWORK_WITNESSES_DIR = (
    Path(__file__).resolve().parent / "refsol_network_witnesses"
)


@dataclass(frozen=True)
class _WitnessVariant:
    """Static wiring for one opt-in committed reference-solution witness set.

    A witness variant swaps the shipped ``solve.sh`` for a committed asset that
    proves a task stays solvable under a specific hardening constraint —
    rootless execution, or a trusted-egress-only network policy. ``assets_dir``
    is a zero-arg callable rather than a stored ``Path`` so tests can monkeypatch
    the module-level directory globals it reads.
    """

    name: str
    task_ids: frozenset[str]
    assets_dir: Callable[[], Path]
    asset_path_prefix: str
    asset_noun: str
    solution_fidelity: str
    solution_override_reason: str


_WITNESS_VARIANTS: Mapping[str, _WitnessVariant] = MappingProxyType(
    {
        ENG_3310_ROOTLESS_WITNESS_VARIANT: _WitnessVariant(
            name=ENG_3310_ROOTLESS_WITNESS_VARIANT,
            task_ids=ENG_3310_ROOTLESS_WITNESS_TASK_IDS,
            assets_dir=lambda: _ROOTLESS_WITNESSES_DIR,
            asset_path_prefix="refsol_rootless_witnesses",
            asset_noun="rootless witness",
            solution_fidelity="committed_rootless_witness",
            solution_override_reason="rootless_witness_variant",
        ),
        STATIC_EGRESS_WITNESS_VARIANT: _WitnessVariant(
            name=STATIC_EGRESS_WITNESS_VARIANT,
            task_ids=STATIC_EGRESS_WITNESS_TASK_IDS,
            assets_dir=lambda: _NETWORK_WITNESSES_DIR,
            asset_path_prefix="refsol_network_witnesses",
            asset_noun="static-egress witness",
            solution_fidelity="committed_static_egress_witness",
            solution_override_reason="static_egress_witness_variant",
        ),
    }
)

WITNESS_VARIANT_NAMES: frozenset[str] = frozenset(_WITNESS_VARIANTS)
WITNESS_SOLUTION_FIDELITIES: frozenset[str] = frozenset(
    variant.solution_fidelity for variant in _WITNESS_VARIANTS.values()
)
REMOTE_SOLUTION_DIR = "/solution"
REMOTE_SOLUTION_PATH = "/solution/solve.sh"
SOLUTION_SESSION_PREFIX = "ia-refsol-"
DEFAULT_SOLUTION_TIMEOUT_SEC = 900
SOLUTION_EXEC_BUFFER_SEC = 60
SOLUTION_POLL_INTERVAL_SEC = 5
SOLUTION_POLL_MAX_TRANSIENT_ERRORS = 12
SOLUTION_STDOUT_TAIL_CHARS = 20_000
REFSOL_IDENTITY_MARKER = "__BOUNDARYBENCH_REFSOL_IDENTITY__"
_REFSOL_IDENTITY_RE = re.compile(
    rf"^{re.escape(REFSOL_IDENTITY_MARKER)} "
    r"effective_uid=(?P<uid>\d+) effective_user=(?P<user>\S+) "
    r"pwd=(?P<pwd>/\S*)$",
    re.MULTILINE,
)
SANDBOX_CREATE_TIMEOUT_SEC = 600
LEFTOVER_CHECK_ATTEMPTS = 6
LEFTOVER_CHECK_SLEEP_SEC = 5
DEFAULT_MAX_ATTEMPTS = 5
TRANSIENT_RETRY_BACKOFF_SEC = 5
EGRESS_RETRY_BACKOFF_SEC = 45
CAPACITY_WAIT_MAX_SEC = 900
CAPACITY_WAIT_INTERVAL_SEC = 60

_PHASE_COMPONENT = "terminalbench_refsol"

PIP_TIME_SHIM_ENV = "IA_REFSOL_PIP_TIME_SHIM"
_PIP_SHIM_DIR = "/usr/local/lib/boundarybench"
_PIP_SHIM_SETUP_TIMEOUT_SEC = 300

_EGRESS_MARKER = "transient egress unreachable"

_TRANSIENT_ERROR_MARKERS = (
    *DAYTONA_LIFECYCLE_MARKERS,
    *DAYTONA_CONNECTION_MARKERS,
    "max retries exceeded",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    _EGRESS_MARKER,
)

_EGRESS_FAILURE_MARKERS = (
    "connection reset by peer",
    "ssl connect error",
    "unable to establish ssl connection",
    "network is unreachable",
    "could not resolve host",
    "temporary failure in name resolution",
    "failed to connect to",
    "curl: (35",
    "curl: (7",
    "curl: (28",
    "curl: (56",
    "curl failed",
    "tlsv1 alert",
    "connection timed out",
)


class _TransientEgressError(RuntimeError):
    """A run failed on what looks like a transient outbound-network block."""


class _MissingPolicyEvidenceError(RuntimeError):
    """A gated run looked policy-blocked but lacked required policy evidence."""


def _is_transient_task_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc!r}".lower()
    return any(marker in text for marker in _TRANSIENT_ERROR_MARKERS)


def _looks_like_egress_failure(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _EGRESS_FAILURE_MARKERS)


def _resolve_refsol_policy(
    policy: str | None,
    *,
    task_id: str,
) -> tuple[HardeningPolicy | None, Any | None]:
    """Resolve the opt-in native policy and its task-aware live config."""

    normalized = str(policy or REFSOL_NO_POLICY).strip() or REFSOL_NO_POLICY
    if normalized == REFSOL_NO_POLICY:
        return None, None
    selected = resolve_policy_for_run(normalized)
    if selected.name not in REFSOL_NATIVE_POLICIES:
        allowed = ", ".join(sorted(REFSOL_NATIVE_POLICIES))
        raise ValueError(
            f"reference solutions support policy='none' or native policies "
            f"{allowed}; got {normalized!r}"
        )
    if selected.enforcement_mode != "native":
        raise ValueError(
            f"reference-solution policy {selected.name!r} must use native enforcement"
        )
    config = build_daytona_config_from_axes(
        AXIS_PRESETS[selected.name], task_id=task_id
    )
    return selected, config


def _has_possible_policy_egress_denial(
    policy_events: list[dict[str, Any]],
) -> bool:
    """Whether authoritative or inferred telemetry indicates an egress denial."""

    network_markers = ("network", "egress", "domain", "cidr", "proxy")
    for event in policy_events:
        if str(event.get("event_type") or "").lower() not in {
            "policy_block",
            "policy_block_inferred",
        }:
            continue
        context = " ".join(
            str(event.get(key) or "")
            for key in ("axis", "surface", "observer", "target", "reason")
        ).lower()
        if any(marker in context for marker in network_markers):
            return True
    return False


def _egress_failure_disposition(
    *,
    verifier_reward: float,
    solution_stdout: str,
    policy_events: list[dict[str, Any]],
    network_gated: bool,
) -> str:
    """Classify failed egress as none, retry, measurement, or invalid evidence."""

    if verifier_reward > 0 or not _looks_like_egress_failure(solution_stdout):
        return "none"
    if _has_possible_policy_egress_denial(policy_events):
        return "measurement"
    if network_gated:
        return "invalid"
    return "retry"


def _network_gate_enabled(
    selected: HardeningPolicy | None,
    hardening_config: Any | None,
) -> bool:
    if selected is None or hardening_config is None:
        return False
    return bool(
        selected.isolate_network
        or selected.block_network
        or hardening_config.native_egress_reject
        or hardening_config.domain_egress_enabled
    )


@dataclass(frozen=True)
class RefsolRunResult:
    """Everything recorded for one reference-solution run."""

    task_id: str
    harbor_ref: str
    image: str
    solution_path: str
    solution_exit_code: int | None
    solution_timed_out: bool
    solution_stdout_tail: str
    verifier: DaytonaVerifierResult
    sandbox_id: str | None
    run_id: str | None
    cleanup: dict[str, Any] = field(default_factory=dict)
    pip_time_shim: dict[str, Any] = field(default_factory=dict)
    solution_override: dict[str, Any] = field(default_factory=dict)
    policy: str = REFSOL_NO_POLICY
    hardened_execution: bool = False
    hardening_config: dict[str, Any] = field(default_factory=dict)
    policy_events: list[dict[str, Any]] = field(default_factory=list)
    preflight: dict[str, Any] | None = None
    runtime_policy_probe_report: dict[str, Any] | None = None
    solution_identity: dict[str, Any] | None = None
    verification_lifecycle: dict[str, Any] = field(default_factory=dict)
    agent_workdir: str = "/app"
    workspace_root: str = "/app"
    solution_fidelity: str = "compatibility_baseline"
    solution_variant: str | None = None
    solution_source: dict[str, Any] = field(default_factory=dict)

    @property
    def reward(self) -> float:
        return self.verifier.value

    @property
    def answer(self) -> str:
        return self.verifier.answer

    def to_metadata(self) -> dict[str, Any]:
        policy_block_count = sum(
            1
            for event in self.policy_events
            if event.get("event_type") == "policy_block"
        )
        metadata = {
            "task_id": self.task_id,
            "harbor_ref": self.harbor_ref,
            "image": self.image,
            "solution_path": self.solution_path,
            "solution_exit_code": self.solution_exit_code,
            "solution_timed_out": self.solution_timed_out,
            "solution_stdout_tail": self.solution_stdout_tail,
            "reward": self.reward,
            "answer": self.answer,
            "verifier": self.verifier.to_metadata(),
            "sandbox_id": self.sandbox_id,
            "run_id": self.run_id,
            "cleanup": dict(self.cleanup),
            "pip_time_shim": dict(self.pip_time_shim),
            "solution_override": dict(self.solution_override),
            "policy": self.policy,
            "hardened_execution": self.hardened_execution,
            "hardening_config": dict(self.hardening_config),
            "policy_events": list(self.policy_events),
            "policy_event_count": len(self.policy_events),
            "policy_block_count": policy_block_count,
            "blocked_surface_count": policy_block_count,
            "policy_evidence_seen": bool(self.policy_events),
            "preflight": self.preflight,
            "runtime_policy_probe_report": self.runtime_policy_probe_report,
            "solution_identity": self.solution_identity,
            "verification_lifecycle": dict(self.verification_lifecycle),
            "agent_workdir": self.agent_workdir,
            "workspace_root": self.workspace_root,
            "solution_fidelity": self.solution_fidelity,
            "execution_mode": "reference_solution",
        }
        if self.solution_variant is not None:
            metadata["solution_variant"] = self.solution_variant
            metadata["solution_source"] = dict(self.solution_source)
        return metadata


def _runner_executor() -> Any:
    return benchmark_daytona.runner_executor("tb-refsol")


def _task_toml_config(bundle: TerminalBenchTaskBundle) -> dict[str, Any]:
    task_toml = bundle.task_dir / "task.toml"
    if not task_toml.exists():
        return {}
    with open(task_toml, "rb") as f:
        return tomllib.load(f)


def _task_solution_timeout_sec(bundle: TerminalBenchTaskBundle) -> int:
    agent = _task_toml_config(bundle).get("agent") or {}
    timeout = agent.get("timeout_sec")
    if timeout is None:
        return DEFAULT_SOLUTION_TIMEOUT_SEC
    return max(1, int(float(timeout)))


def _task_solution_env(bundle: TerminalBenchTaskBundle) -> dict[str, str]:
    solution = _task_toml_config(bundle).get("solution") or {}
    env = solution.get("env") or {}
    if not isinstance(env, dict):
        raise ValueError(f"task {bundle.task_name} has invalid solution.env")
    return {str(k): str(v) for k, v in env.items()}


def _refsol_resources(bundle: TerminalBenchTaskBundle) -> Any:
    """Resolve the sandbox resources for a reference-solution run.

    Uses the exact ``task.toml [environment]`` resources so the queue's
    accounting matches the runtime allocation and the reference-solution smoke
    stays aligned with Terminal-Bench task configuration.
    """

    return daytona_task_resources(bundle)


def _provision_refsol_sandbox(
    daytona: Any,
    *,
    image: str,
    resources: Any,
    command_timeout_sec: int | None = None,
    create_timeout_sec: int = SANDBOX_CREATE_TIMEOUT_SEC,
) -> Any:
    """Create a sandbox from the raw task image — no runtime layering.

    A reference-solution run has no agent, so the agent runtime layer is not
    installed; the official verifier needs only fs upload, tar, and bash, which
    the Terminal-Bench task images provide. Labels carry the run id (when
    ``BOUNDARYBENCH_RUN_ID`` is set) so cleanup is provably run-scoped.
    """

    from daytona_sdk.common.daytona import CreateSandboxFromImageParams

    params = CreateSandboxFromImageParams(
        image=image,
        resources=resources,
        auto_stop_interval=_sandbox_auto_stop_min(command_timeout_sec),
        auto_delete_interval=SANDBOX_AUTO_DELETE_MIN,
        labels=_sandbox_create_labels(),
    )
    deadline = time.monotonic() + CAPACITY_WAIT_MAX_SEC
    while True:
        try:
            return daytona.create(params, timeout=create_timeout_sec)
        except Exception as exc:  # noqa: BLE001 - classify then re-raise
            if not is_daytona_account_capacity_error(f"{exc!s} {exc!r}"):
                raise
            if time.monotonic() > deadline:
                raise
            print(
                "[terminalbench-refsol] WARN daytona capacity exhausted; "
                f"retrying create in {CAPACITY_WAIT_INTERVAL_SEC}s: {exc!s:.200}",
                flush=True,
            )
            time.sleep(CAPACITY_WAIT_INTERVAL_SEC)


def _upload_solution_dir(sandbox: Any, bundle: TerminalBenchTaskBundle) -> None:
    """Upload the ENTIRE solution directory to /solution (Harbor contract).

    The official oracle solver copies the whole directory, and reference
    solutions rely on sibling files (e.g. headless-terminal's solve.sh does
    ``cp /solution/headless_terminal.py ...``). Uploading only solve.sh breaks
    those tasks. Mirrors upload_tests_dir_to_daytona's tarball approach.
    """

    solution_dir = bundle.task_dir / "solution"
    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as archive:
        archive.write(tar_directory_bytes(solution_dir))
        archive.flush()
        remote_archive = "/tmp/boundarybench-refsol-solution.tar.gz"
        sandbox.fs.upload_file(archive.name, remote_archive)
        quoted_dir = shlex.quote(REMOTE_SOLUTION_DIR)
        result = sandbox.process.exec(
            f"rm -rf {quoted_dir} && mkdir -p {quoted_dir} && "
            f"tar -xzf {shlex.quote(remote_archive)} -C {quoted_dir}",
            timeout=60,
        )
        if getattr(result, "exit_code", 1) != 0:
            raise RuntimeError(
                getattr(result, "result", "") or "failed to extract solution tarball"
            )


def _witness_variant(solution_variant: str) -> _WitnessVariant:
    """Resolve a registered witness variant, rejecting unknown names."""

    variant = _WITNESS_VARIANTS.get(solution_variant)
    if variant is None:
        raise ValueError(f"unknown solution variant {solution_variant!r}")
    return variant


def _witness_path(variant: _WitnessVariant, task_id: str) -> Path:
    return variant.assets_dir() / task_id / "solve.sh"


def _validate_solution_variant(
    solution_variant: str | None,
    *,
    task_id: str,
    policy_name: str,
) -> None:
    """Validate the explicit witness admission without auto-discovery."""

    if solution_variant is None:
        return
    variant = _witness_variant(solution_variant)
    if task_id not in variant.task_ids:
        raise ValueError(
            f"task {task_id!r} is not admitted for solution variant "
            f"{solution_variant!r}"
        )
    if policy_name == REFSOL_NO_POLICY:
        raise ValueError(
            f"solution variant {solution_variant!r} requires a native policy"
        )
    path = _witness_path(variant, task_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"{variant.asset_noun} asset is missing for task {task_id!r}: {path}"
        )


def witness_source(solution_variant: str, task_id: str) -> dict[str, str]:
    """Return fail-closed provenance for one allowlisted committed witness."""

    _, source = _witness_payload(_witness_variant(solution_variant), task_id)
    return source


def witness_variant_task_ids(solution_variant: str) -> frozenset[str]:
    """Return the task allowlist admitted for a witness variant."""

    return _witness_variant(solution_variant).task_ids


def witness_solution_fidelity(solution_variant: str) -> str:
    """Return the solution-fidelity label recorded for a witness variant."""

    return _witness_variant(solution_variant).solution_fidelity


def witness_solution_override(solution_variant: str) -> dict[str, Any]:
    """Return the solution-override provenance recorded for a witness variant."""

    return {
        "applied": False,
        "reason": _witness_variant(solution_variant).solution_override_reason,
    }


def _witness_payload(
    variant: _WitnessVariant, task_id: str
) -> tuple[bytes, dict[str, str]]:
    path = _witness_path(variant, task_id)
    if task_id not in variant.task_ids or not path.is_file():
        raise FileNotFoundError(
            f"{variant.asset_noun} asset is missing for task {task_id!r}: {path}"
        )
    payload = path.read_bytes()
    source = {
        "name": variant.name,
        "task_id": task_id,
        "asset_path": f"{variant.asset_path_prefix}/{task_id}/solve.sh",
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    return payload, source


def _apply_witness(
    sandbox: Any, variant: _WitnessVariant, task_id: str
) -> dict[str, str]:
    payload, source = _witness_payload(variant, task_id)
    with tempfile.NamedTemporaryFile(suffix=".sh") as tmp:
        tmp.write(payload)
        tmp.flush()
        sandbox.fs.upload_file(tmp.name, REMOTE_SOLUTION_PATH)
    result = sandbox.process.exec(
        f"chmod +x {shlex.quote(REMOTE_SOLUTION_PATH)}", timeout=30
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(
            getattr(result, "result", "")
            or f"failed to make {variant.asset_noun} executable"
        )
    return source


SOLUTION_OVERRIDES_ENV = "IA_REFSOL_SOLUTION_OVERRIDES"
_SOLUTION_OVERRIDES_DIR = Path(__file__).resolve().parent / "refsol_solution_overrides"


def _solution_overrides_enabled() -> bool:
    return os.environ.get(SOLUTION_OVERRIDES_ENV, "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _solution_override_solve_path(task_id: str) -> Path | None:
    """Return the committed override solve.sh for ``task_id`` if one exists."""

    candidate = _SOLUTION_OVERRIDES_DIR / task_id / "solve.sh"
    return candidate if candidate.is_file() else None


def _apply_solution_override(sandbox: Any, task_id: str) -> dict[str, Any]:
    """Overwrite ``/solution/solve.sh`` with the committed override, if any.

    Runs after ``_upload_solution_dir`` so sibling solution files are still
    present; only the entrypoint is replaced. Returns metadata recording whether
    an override was applied (and why it matters for provenance).
    """

    if not _solution_overrides_enabled():
        return {"applied": False, "reason": "disabled"}
    override = _solution_override_solve_path(task_id)
    if override is None:
        return {"applied": False}
    with tempfile.NamedTemporaryFile(suffix=".sh") as tmp:
        tmp.write(override.read_bytes())
        tmp.flush()
        sandbox.fs.upload_file(tmp.name, REMOTE_SOLUTION_PATH)
    sandbox.process.exec(f"chmod +x {shlex.quote(REMOTE_SOLUTION_PATH)}", timeout=30)
    return {
        "applied": True,
        "source": str(override.relative_to(_SOLUTION_OVERRIDES_DIR.parent)),
    }


def _solution_command(timeout_sec: int, env: dict[str, str], workdir: str) -> str:
    exports = "".join(
        f"export {key}={shlex.quote(value)}; " for key, value in env.items()
    )
    return (
        f"{exports}"
        f"cd {shlex.quote(workdir)} && "
        f"timeout -k 10 {int(timeout_sec)}s "
        f"bash -l {shlex.quote(REMOTE_SOLUTION_PATH)} < /dev/null 2>&1"
    )


def _hardened_solution_command(
    timeout_sec: int,
    env: dict[str, str],
    workdir: str,
) -> str:
    """Emit controller-defined identity evidence before solution-controlled output."""

    return (
        f"printf '{REFSOL_IDENTITY_MARKER} "
        "effective_uid=%s effective_user=%s pwd=%s\\n' "
        '"$(id -u)" "$(id -un)" "$(pwd -P)" && '
        f"{_solution_command(timeout_sec, env, workdir)}"
    )


def _parse_solution_identity(output: str) -> dict[str, Any]:
    """Parse the first marker emitted before the shipped solution starts."""

    match = _REFSOL_IDENTITY_RE.search(output)
    if match is None:
        raise RuntimeError(
            f"invalid hardened reference-solution identity evidence: {output!r}"
        )
    return {
        "effective_uid": int(match.group("uid")),
        "effective_user": match.group("user"),
        "observed_workdir": match.group("pwd"),
    }


def _validate_solution_identity(
    *,
    policy: str,
    expected_user: str,
    expected_workdir: str,
    identity: dict[str, Any],
) -> None:
    """Fail closed unless a requested hardened policy observed a non-root solve."""

    if policy not in REFSOL_NATIVE_POLICIES:
        return
    uid = identity.get("effective_uid")
    user = str(identity.get("effective_user") or "")
    if (
        not isinstance(uid, int)
        or isinstance(uid, bool)
        or uid == 0
        or user != expected_user
        or identity.get("observed_workdir") != expected_workdir
        or identity.get("policy") != policy
    ):
        raise RuntimeError(
            "solution identity is not non-root for policy "
            f"{policy!r}: {identity!r}"
        )


def _validate_refsol_workspace(
    *, workdir: str, workspace_root: str, hardening_config: Any
) -> None:
    """Bind task workdir and policy write boundaries before provisioning."""

    if workspace_root not in SUPPORTED_TASK_WORKSPACE_ROOTS:
        raise RuntimeError(f"unsupported reference-solution workspace: {workspace_root!r}")
    if workdir != workspace_root and not workdir.startswith(f"{workspace_root}/"):
        raise RuntimeError(
            f"reference-solution workdir {workdir!r} is outside {workspace_root!r}"
        )
    if hardening_config.filesystem_scope not in {"workspace", "read_only"}:
        return
    if workspace_root not in hardening_config.writable_path_exact:
        raise RuntimeError(
            "hardening config omits task workspace writable boundary "
            f"{workspace_root!r}"
        )
    if f"{workspace_root}/" not in hardening_config.writable_path_prefixes:
        raise RuntimeError(
            "hardening config omits task workspace writable prefix "
            f"{workspace_root}/"
        )


def _run_solution(
    sandbox: Any,
    *,
    timeout_sec: int,
    env: dict[str, str],
    workdir: str,
) -> tuple[int | None, bool, str, str | None]:
    """Run solve.sh in an async Daytona session that is NEVER deleted.

    Two failure modes shape this:
    - The documented pypi-server pitfall is a session runner's ``finally:
      delete_session`` reaping a daemon the solution started before the
      verifier runs. This runner therefore never deletes the solution session;
      it lives until the sandbox itself is deleted after verification.
    - Daytona's synchronous ``process.exec`` is unreliable for long-running
      commands (observed ``DaytonaError('Failed to execute command: ')`` within
      seconds on multi-minute solutions), so the solution runs via
      ``execute_session_command(run_async=True)`` + polling — the same
      transport the official verifier runner uses.

    The in-sandbox ``timeout`` wrapper gives deterministic timeout semantics
    (exit code 124); the polling deadline is only a backstop.
    """

    command = _solution_command(timeout_sec, env, workdir)
    process = sandbox.process
    if not hasattr(process, "create_session"):
        result = process.exec(
            command,
            timeout=int(timeout_sec) + SOLUTION_EXEC_BUFFER_SEC,
            env=None,
        )
        exit_code = getattr(result, "exit_code", None)
        exit_code = int(exit_code) if exit_code is not None else None
        stdout = getattr(result, "result", "") or ""
        return (
            exit_code,
            exit_code == 124,
            stdout[-SOLUTION_STDOUT_TAIL_CHARS:],
            None,
        )

    from daytona_sdk.common.process import SessionExecuteRequest

    session_id = SOLUTION_SESSION_PREFIX + uuid.uuid4().hex[:12]
    process.create_session(session_id)
    response = process.execute_session_command(
        session_id,
        SessionExecuteRequest(command=command, run_async=True),
        timeout=60,
    )
    cmd_id = response.cmd_id
    deadline = time.monotonic() + timeout_sec + SOLUTION_EXEC_BUFFER_SEC
    exit_code: int | None = None
    timed_out = False
    consecutive_poll_errors = 0
    while True:
        try:
            info = process.get_session_command(session_id, cmd_id)
            consecutive_poll_errors = 0
        except Exception as exc:  # noqa: BLE001 - retry transient session blips
            consecutive_poll_errors += 1
            if consecutive_poll_errors > SOLUTION_POLL_MAX_TRANSIENT_ERRORS:
                raise
            print(
                "[terminalbench-refsol] WARN transient session poll error "
                f"({consecutive_poll_errors}/{SOLUTION_POLL_MAX_TRANSIENT_ERRORS}): "
                f"{exc!r}",
                flush=True,
            )
            time.sleep(SOLUTION_POLL_INTERVAL_SEC)
            continue
        raw_exit_code = getattr(info, "exit_code", None)
        if raw_exit_code is not None:
            exit_code = int(raw_exit_code)
            break
        if time.monotonic() > deadline:
            timed_out = True
            break
        time.sleep(SOLUTION_POLL_INTERVAL_SEC)
    try:
        logs = process.get_session_command_logs(session_id, cmd_id)
        stdout = getattr(logs, "stdout", None) or getattr(logs, "output", "") or ""
    except Exception:  # noqa: BLE001 - logs are evidence, not scoring
        stdout = ""
    if exit_code == 124:
        timed_out = True
    return exit_code, timed_out, stdout[-SOLUTION_STDOUT_TAIL_CHARS:], session_id


def _cleanup_sandbox(
    daytona: Any, sandbox: Any, *, run_id: str | None
) -> dict[str, Any]:
    """Delete the sandbox, sweep run-scoped strays, and prove zero leftovers."""

    sandbox_deleted = False
    try:
        daytona.delete(sandbox)
        sandbox_deleted = True
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
        if _is_delete_race(exc):
            sandbox_deleted = True
        else:
            print(
                f"[terminalbench-refsol] WARN sandbox delete failed: {exc!r}",
                flush=True,
            )
    if not run_id:
        return {
            "sandbox_deleted": sandbox_deleted,
            "reap_deleted": 0,
            "reap_failed": 0,
            "leftover_count": 0,
            "leftover_ids": [],
            "status": "skipped_no_run_id",
        }
    reap_deleted, reap_failed = reap_stale_terminalbench_sandboxes(
        daytona, run_id=run_id, include_running=True
    )
    leftover_ids = _await_zero_leftovers(daytona, run_id=run_id)
    complete = sandbox_deleted and reap_failed == 0 and not leftover_ids
    return {
        "sandbox_deleted": sandbox_deleted,
        "reap_deleted": reap_deleted,
        "reap_failed": reap_failed,
        "leftover_count": len(leftover_ids),
        "leftover_ids": leftover_ids,
        "status": "complete" if complete else "partial",
    }


def _await_zero_leftovers(daytona: Any, *, run_id: str) -> list[str]:
    """Actively delete sandboxes owned by this run id until none remain.

    Daytona deletes are asynchronous, so a just-deleted sandbox can linger in
    the listing briefly. Rather than merely observing (which races the async
    delete), each pass re-issues delete on anything still owned by this run id,
    turning "still visible" into "actively removed". Only genuinely
    undeletable strays survive to be reported.
    """

    leftover_ids: list[str] = []
    for attempt in range(LEFTOVER_CHECK_ATTEMPTS):
        if attempt:
            time.sleep(LEFTOVER_CHECK_SLEEP_SEC)
        try:
            sandboxes = list(daytona.list())
        except Exception as exc:  # noqa: BLE001 - listing is evidence, not scoring
            print(
                f"[terminalbench-refsol] WARN sandbox list failed: {exc!r}",
                flush=True,
            )
            continue
        owned = [
            sandbox
            for sandbox in sandboxes
            if _sandbox_is_owned(_sandbox_labels(sandbox), run_id)
        ]
        if not owned:
            return []
        leftover_ids = [str(getattr(sandbox, "id", "unknown")) for sandbox in owned]
        for sandbox in owned:
            try:
                daytona.delete(sandbox)
            except Exception as exc:  # noqa: BLE001 - re-list next pass to confirm
                if _is_delete_race(exc):
                    continue
                print(
                    f"[terminalbench-refsol] WARN leftover delete failed: {exc!r}",
                    flush=True,
                )
    return leftover_ids


def _image_build_cutoff_date(image: str) -> str | None:
    """Derive an install-as-of cutoff date (``YYYY-MM-DD``) from the task image.

    Terminal-Bench task images encode their build date as the image tag
    (``<repo>/<image>:20251031`` -> 2025-10-31); every task in the
    terminal-bench-2.1 package is tagged this way. The cutoff returned is the
    day *after* the build date, so distributions published on the build day are
    still installable while anything released later — which the image could not
    have shipped with — is excluded. This is the generic hook the pip time-shim
    uses to make a reference solution's unpinned installs resolve to versions
    contemporary with the image, instead of newer releases that broke the API.

    Returns ``None`` when the tag is not a parseable date. In that case no
    version pinning is applied and the solution runs exactly as before.
    """

    name = image.rsplit("/", 1)[-1]
    tag = name.rsplit(":", 1)[1] if ":" in name else ""
    match = re.fullmatch(r"(\d{4})-?(\d{2})-?(\d{2})", tag)
    if not match:
        return None
    try:
        build_date = datetime.date(
            int(match.group(1)), int(match.group(2)), int(match.group(3))
        )
    except ValueError:
        return None
    return (build_date + datetime.timedelta(days=1)).isoformat()


_PIP_SHIM_WRAPPER = f"""#!/bin/sh
SHIMDIR={_PIP_SHIM_DIR}
export UV_EXCLUDE_NEWER="$(cat "$SHIMDIR/cutoff")"
UV="$(cat "$SHIMDIR/uvpath")"
self="$(basename "$0")"
REAL="$SHIMDIR/$self.real"
case "$1" in
  install|uninstall|freeze|list|show|check|sync|tree)
    use_system=1
    [ -n "$VIRTUAL_ENV" ] && use_system=0
    for a in "$@"; do
      case "$a" in
        --index-url|--index-url=*|-i|--extra-index-url|--extra-index-url=*|--find-links|--find-links=*|-f|--no-index)
          exec "$REAL" "$@" ;;
        --user|--target|--target=*|--prefix|--prefix=*|--python|--python=*|-p)
          use_system=0 ;;
      esac
    done
    [ "$use_system" = 1 ] && set -- "$@" --system
    exec "$UV" pip "$@"
    ;;
  *)
    exec "$REAL" "$@"
    ;;
esac
"""


def _install_pip_time_shim(sandbox: Any, *, cutoff_date: str) -> dict[str, Any]:
    """Route the sandbox's ``pip``/``pip3`` through ``uv pip --exclude-newer``.

    Ensures ``uv`` is present (installed via the image's own pip; uv itself is
    unconstrained), moves each pip entrypoint aside as ``<name>.real``, and
    drops in a wrapper that forwards installs to ``uv pip`` with the build-date
    cutoff. Idempotent and best-effort: if uv can't be obtained the box is left
    untouched and the solution runs with the stock pip (status recorded).
    """

    wrapper_b64 = base64.b64encode(_PIP_SHIM_WRAPPER.encode()).decode()
    setup = f"""set -e
SHIMDIR={_PIP_SHIM_DIR}
mkdir -p "$SHIMDIR"
printf '%s' {shlex.quote(cutoff_date)} > "$SHIMDIR/cutoff"
if ! command -v uv >/dev/null 2>&1; then
  python -m pip install -q --disable-pip-version-check uv >/dev/null 2>&1 \
    || pip install -q --disable-pip-version-check uv >/dev/null 2>&1 || true
fi
if ! command -v uv >/dev/null 2>&1; then echo "IA_SHIM_NO_UV"; exit 0; fi
UV="$(command -v uv)"
printf '%s' "$UV" > "$SHIMDIR/uvpath"
echo {shlex.quote(wrapper_b64)} | base64 -d > "$SHIMDIR/pip.wrapper"
for name in pip pip3; do
  p="$(command -v "$name" 2>/dev/null)" || continue
  real="$SHIMDIR/$name.real"
  [ -e "$real" ] || cp "$p" "$real"
  cp "$SHIMDIR/pip.wrapper" "$p"
  chmod +x "$p"
done
echo "IA_SHIM_OK cutoff=$(cat "$SHIMDIR/cutoff") uv=$UV"
"""
    result = sandbox.process.exec(
        f"bash -c {shlex.quote(setup)}", timeout=_PIP_SHIM_SETUP_TIMEOUT_SEC
    )
    stdout = getattr(result, "result", "") or ""
    exit_code = getattr(result, "exit_code", None)
    installed = "IA_SHIM_OK" in stdout
    return {
        "enabled": True,
        "installed": installed,
        "cutoff_date": cutoff_date,
        "uv_available": "IA_SHIM_NO_UV" not in stdout,
        "exit_code": exit_code,
        "output_tail": stdout[-2000:],
    }


def _restore_pip(sandbox: Any) -> None:
    """Restore the image's original pip entrypoints (best effort).

    Keeps the shim's blast radius to the solution run: the official verifier
    then executes against the stock pip exactly as Harbor authored it.
    """

    restore = f"""SHIMDIR={_PIP_SHIM_DIR}
for name in pip pip3; do
  real="$SHIMDIR/$name.real"
  [ -e "$real" ] || continue
  p="$(command -v "$name" 2>/dev/null)" || continue
  cp "$real" "$p"
done
"""
    try:
        sandbox.process.exec(f"bash -c {shlex.quote(restore)}", timeout=60)
    except Exception as exc:  # noqa: BLE001 - restore is best effort
        print(
            f"[terminalbench-refsol] WARN pip shim restore failed: {exc!r}",
            flush=True,
        )


def _pip_time_shim_enabled() -> bool:
    return os.environ.get(PIP_TIME_SHIM_ENV, "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def run_one_refsol_task(
    task_id: str,
    *,
    ref: str,
    solution_timeout_sec: int | None = None,
    policy: str = REFSOL_NO_POLICY,
    solution_variant: str | None = None,
) -> RefsolRunResult:
    """Provision, run the shipped reference solution, verify, and tear down."""

    run_id = os.environ.get(SANDBOX_RUN_ID_ENV) or None
    selected, hardening_config = _resolve_refsol_policy(policy, task_id=task_id)
    policy_name = selected.name if selected is not None else REFSOL_NO_POLICY
    _validate_solution_variant(
        solution_variant,
        task_id=task_id,
        policy_name=policy_name,
    )
    witness_variant = (
        _witness_variant(solution_variant) if solution_variant is not None else None
    )
    phase_started = time.perf_counter()
    phase_status = "success"
    with _HARBOR_LOAD_LOCK:
        try:
            bundle = load_terminalbench_daytona_bundle(task_id=task_id, harbor_ref=ref)
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component=_PHASE_COMPONENT,
                identifier=task_id,
                phase="harbor_task_load",
                started_at=phase_started,
                status=phase_status,
            )
    validate_shared_root_verifier_admission(bundle)
    solution_path = bundle.task_dir / "solution" / "solve.sh"
    if not solution_path.exists():
        raise FileNotFoundError(
            f"task {task_id} has no shipped reference solution at {solution_path}"
        )
    image = task_docker_image(bundle)
    timeout_sec = (
        solution_timeout_sec
        if solution_timeout_sec is not None
        else _task_solution_timeout_sec(bundle)
    )
    solution_env = _task_solution_env(bundle)
    workspace = terminalbench_workspace_from_bundle(bundle)
    workdir = workspace.workdir
    workspace_root = workspace.workspace_root
    if selected is not None and hardening_config is not None:
        _validate_refsol_workspace(
            workdir=workdir,
            workspace_root=workspace_root,
            hardening_config=hardening_config,
        )
    from daytona_sdk import Daytona

    daytona = Daytona()
    resources = _refsol_resources(bundle)
    sandbox = None
    hardening: DaytonaPolicyHardening | None = None
    preflight: dict[str, Any] | None = None
    runtime_policy_probe_report: dict[str, Any] | None = None
    policy_events: list[dict[str, Any]] = []
    solution_identity: dict[str, Any] | None = None
    solution_session_id: str | None = None
    try:
        phase_started = time.perf_counter()
        sandbox = _provision_refsol_sandbox(
            daytona,
            image=image,
            resources=resources,
            command_timeout_sec=timeout_sec,
        )
        _print_phase_timing(
            component=_PHASE_COMPONENT,
            identifier=task_id,
            phase="sandbox_provision_attempt",
            started_at=phase_started,
            status="success",
            resources=str(resources),
        )
        if selected is not None:
            phase_started = time.perf_counter()
            phase_status = "success"
            try:
                base_script = render_sandbox_base_script(
                    workdir=workspace_root,
                    run_agent_as_root=selected.run_agent_as_root,
                )
                base_result = sandbox.process.exec(base_script, timeout=600)
                if getattr(base_result, "exit_code", 1) != 0:
                    raise RuntimeError(
                        "harness-free sandbox base setup failed: "
                        f"{getattr(base_result, 'result', '') or ''}"
                    )
                hardening = install_daytona_policy_hardening(
                    sandbox,
                    DEFAULT_HARDENING_ASSET_DIR,
                    hardening_config=hardening_config,
                    install_landlock_mac_runner=selected.full_mac_enforcement,
                    enforcement_mode=selected.enforcement_mode,
                )
            except Exception:
                phase_status = "error"
                raise
            finally:
                _print_phase_timing(
                    component=_PHASE_COMPONENT,
                    identifier=task_id,
                    phase="harness_free_policy_setup",
                    started_at=phase_started,
                    status=phase_status,
                )

            phase_started = time.perf_counter()
            phase_status = "success"
            try:
                preflight_result = run_preflight(
                    sandbox,
                    policy=selected,
                    daytona_policy_hardening=hardening,
                )
                preflight = {
                    **preflight_result.to_compact_metadata(),
                    "policy": selected.name,
                }
            except Exception:
                phase_status = "error"
                raise
            finally:
                _print_phase_timing(
                    component=_PHASE_COMPONENT,
                    identifier=task_id,
                    phase="policy_preflight",
                    started_at=phase_started,
                    status=phase_status,
                )

            phase_started = time.perf_counter()
            phase_status = "success"
            try:
                probe_report = run_runtime_policy_probe_suite_in_sandbox(
                    sandbox,
                    daytona_policy_hardening=hardening,
                    policy_id=selected.name,
                    policy_name=selected.name,
                    overlays=selected.overlays,
                    agent_user=selected.agent_user,
                    workspace=RUNTIME_POLICY_PROBE_WORKSPACE,
                    isolate_network=selected.isolate_network,
                    block_network=selected.block_network,
                    block_child_shell_network=selected.block_child_shell_network,
                    unsupported_surfaces=selected.unsupported_surfaces,
                    probe_scope=selected.runtime_probe_scope,
                    full_mac_enforcement=selected.full_mac_enforcement,
                    enforcement_mode=selected.enforcement_mode,
                )
                runtime_policy_probe_report = {
                    **probe_report.to_metadata(),
                    "policy": selected.name,
                    "enforcement_mode": selected.enforcement_mode,
                }
                ensure_runtime_policy_probe_suite_passed(probe_report)
            except Exception:
                phase_status = "error"
                raise
            finally:
                _print_phase_timing(
                    component=_PHASE_COMPONENT,
                    identifier=task_id,
                    phase="runtime_policy_probes",
                    started_at=phase_started,
                    status=phase_status,
                )
        _upload_solution_dir(sandbox, bundle)
        solution_source: dict[str, Any] = {}
        if witness_variant is not None:
            solution_source = _apply_witness(sandbox, witness_variant, task_id)
        if witness_variant is not None:
            solution_override = {
                "applied": False,
                "reason": witness_variant.solution_override_reason,
            }
        elif selected is None:
            solution_override = _apply_solution_override(sandbox, task_id)
        else:
            solution_override = {"applied": False, "reason": "canonical_shipped"}
        pip_time_shim: dict[str, Any] = {"enabled": False}
        cutoff_date = _image_build_cutoff_date(image)
        if selected is not None:
            pip_time_shim = {
                "enabled": False,
                "reason": (
                    witness_variant.solution_fidelity
                    if witness_variant is not None
                    else "canonical_shipped"
                ),
            }
        elif _pip_time_shim_enabled() and cutoff_date is not None:
            phase_started = time.perf_counter()
            phase_status = "success"
            try:
                pip_time_shim = _install_pip_time_shim(sandbox, cutoff_date=cutoff_date)
            except Exception as exc:  # noqa: BLE001 - shim must not fail the run
                phase_status = "error"
                pip_time_shim = {
                    "enabled": True,
                    "installed": False,
                    "cutoff_date": cutoff_date,
                    "error": repr(exc)[:500],
                }
            finally:
                _print_phase_timing(
                    component=_PHASE_COMPONENT,
                    identifier=task_id,
                    phase="pip_time_shim_install",
                    started_at=phase_started,
                    status=phase_status,
                )
        elif cutoff_date is None:
            pip_time_shim = {"enabled": False, "reason": "no_image_build_date"}
        if hardening is not None and selected is not None:
            remove_pre_agent_setup_artifacts(
                sandbox,
                daytona_policy_hardening=hardening,
                enforcement_mode=selected.enforcement_mode,
            )
        phase_started = time.perf_counter()
        phase_status = "success"
        try:
            if hardening is None or selected is None:
                exit_code, timed_out, stdout_tail, solution_session_id = _run_solution(
                    sandbox,
                    timeout_sec=timeout_sec,
                    env=solution_env,
                    workdir=workdir,
                )
            else:
                clear_policy_event_log(sandbox)
                hardened_result = run_with_daytona_policy_hardening(
                    sandbox,
                    daytona_policy_hardening=hardening,
                    command=_hardened_solution_command(
                        timeout_sec, solution_env, workdir
                    ),
                    cwd=workdir,
                    workspace=workspace_root,
                    timeout=timeout_sec + SOLUTION_EXEC_BUFFER_SEC,
                    isolate_network=selected.isolate_network,
                    block_network=selected.block_network,
                    block_child_shell_network=selected.block_child_shell_network,
                    full_mac_enforcement=selected.full_mac_enforcement,
                    run_as_root=selected.run_agent_as_root,
                    enforcement_mode=selected.enforcement_mode,
                    preserve_session=True,
                    session_id_prefix=SOLUTION_SESSION_PREFIX,
                )
                exit_code = hardened_result.exit_code
                timed_out = hardened_result.timed_out or exit_code == 124
                stdout_tail = hardened_result.stdout[-SOLUTION_STDOUT_TAIL_CHARS:]
                solution_session_id = hardened_result.session_id
                solution_identity = _parse_solution_identity(hardened_result.stdout)
                solution_identity["policy"] = selected.name
                _validate_solution_identity(
                    policy=selected.name,
                    expected_user=selected.agent_user,
                    expected_workdir=workdir,
                    identity=solution_identity,
                )
                policy_events = harvest_passive_telemetry(
                    sandbox,
                    agent_stdout=hardened_result.stdout,
                    hardening_config=hardening.hardening_config,
                )
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component=_PHASE_COMPONENT,
                identifier=task_id,
                phase="refsol_solution_run",
                started_at=phase_started,
                status=phase_status,
            )
        if pip_time_shim.get("installed"):
            _restore_pip(sandbox)
        solution_sandbox_id = str(getattr(sandbox, "id", "") or "")
        phase_started = time.perf_counter()
        phase_status = "success"
        try:
            verifier = run_daytona_harbor_verifier(
                sandbox,
                bundle,
                remote_workdir=workdir,
            )
            if selected is not None:
                verifier_identity = verifier.verifier_identity
                if (
                    not isinstance(verifier_identity, dict)
                    or not isinstance(verifier_identity.get("effective_uid"), int)
                    or isinstance(verifier_identity.get("effective_uid"), bool)
                    or verifier_identity.get("effective_uid") != 0
                    or verifier_identity.get("effective_user") != "root"
                ):
                    raise RuntimeError(
                        f"observed verifier identity is not root: {verifier_identity!r}"
                    )
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component=_PHASE_COMPONENT,
                identifier=task_id,
                phase="harbor_verifier",
                started_at=phase_started,
                status=phase_status,
            )
        sandbox_id = str(getattr(sandbox, "id", "") or "")
        verification_lifecycle = {
            "solution_sandbox_id": solution_sandbox_id,
            "verifier_sandbox_id": sandbox_id,
            "solution_session_id": solution_session_id,
            "verifier_session_id": verifier.session_id,
            "phase_order": ["solution", "verifier"],
            "solution_completed_before_verifier": True,
            "verifier_fresh_session": bool(
                solution_session_id
                and verifier.session_id
                and solution_session_id != verifier.session_id
            ),
            "same_sandbox": bool(
                solution_sandbox_id
                and sandbox_id
                and solution_sandbox_id == sandbox_id
            ),
            "verifier_identity": verifier.verifier_identity,
        }
        egress_disposition = _egress_failure_disposition(
            verifier_reward=verifier.value,
            solution_stdout=stdout_tail,
            policy_events=policy_events,
            network_gated=_network_gate_enabled(selected, hardening_config),
        )
        if egress_disposition in {"retry", "invalid"}:
            phase_started = time.perf_counter()
            cleanup = _cleanup_sandbox(daytona, sandbox, run_id=run_id)
            sandbox = None
            _print_phase_timing(
                component=_PHASE_COMPONENT,
                identifier=task_id,
                phase="sandbox_delete",
                started_at=phase_started,
                status=cleanup["status"],
            )
            if egress_disposition == "invalid":
                raise _MissingPolicyEvidenceError(
                    "policy evidence contract invalid: network-gated reference "
                    f"solution {task_id!r} failed during egress without an "
                    "authoritative or inferred network policy event"
                )
            raise _TransientEgressError(
                f"{_EGRESS_MARKER}: task {task_id} solution could not reach an "
                "external host (intermittent Daytona egress block)"
            )
        phase_started = time.perf_counter()
        cleanup = _cleanup_sandbox(daytona, sandbox, run_id=run_id)
        sandbox = None
        _print_phase_timing(
            component=_PHASE_COMPONENT,
            identifier=task_id,
            phase="sandbox_delete",
            started_at=phase_started,
            status=cleanup["status"],
        )
        return RefsolRunResult(
            task_id=task_id,
            harbor_ref=ref,
            image=image,
            solution_path=REMOTE_SOLUTION_PATH,
            solution_exit_code=exit_code,
            solution_timed_out=timed_out,
            solution_stdout_tail=stdout_tail,
            verifier=verifier,
            sandbox_id=sandbox_id,
            run_id=run_id,
            cleanup=cleanup,
            pip_time_shim=pip_time_shim,
            solution_override=solution_override,
            policy=policy_name,
            hardened_execution=selected is not None,
            hardening_config=(
                {
                    **hardening_config.to_metadata(),
                    "policy": selected.name,
                    "enforcement_mode": selected.enforcement_mode,
                    "workspace_root": workspace_root,
                    "agent_workdir": workdir,
                }
                if selected is not None and hardening_config is not None
                else {}
            ),
            policy_events=policy_events,
            preflight=preflight,
            runtime_policy_probe_report=runtime_policy_probe_report,
            solution_identity=solution_identity,
            verification_lifecycle=verification_lifecycle,
            agent_workdir=workdir,
            workspace_root=workspace_root,
            solution_fidelity=(
                witness_variant.solution_fidelity
                if witness_variant is not None
                else (
                    "canonical_shipped"
                    if selected is not None
                    else "compatibility_baseline"
                )
            ),
            solution_variant=solution_variant,
            solution_source=solution_source,
        )
    finally:
        if sandbox is not None:
            phase_started = time.perf_counter()
            cleanup = _cleanup_sandbox(daytona, sandbox, run_id=run_id)
            _print_phase_timing(
                component=_PHASE_COMPONENT,
                identifier=task_id,
                phase="sandbox_delete",
                started_at=phase_started,
                status=cleanup["status"],
            )


def _exception_metadata(exc: BaseException) -> dict[str, str]:
    return {
        "error_type": type(exc).__name__,
        "error_message": str(exc)[:2000],
        "error_traceback": "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )[:8000],
    }


def _runtime_probe_failure_details(
    exc: DaytonaRuntimeProbeSuiteError,
) -> tuple[dict[str, Any], bool, int]:
    report = exc.report.to_metadata()
    required_failures = [
        result
        for result in report.get("results") or []
        if isinstance(result, dict)
        and result.get("required") is True
        and str(result.get("status") or "") in {"fail", "unsupported"}
    ]
    runtime_error_count = sum(
        str(result.get("classification") or "") == "runtime_error"
        for result in required_failures
    )
    return (
        report,
        bool(required_failures) and runtime_error_count == len(required_failures),
        runtime_error_count,
    )


def _policy_contract_failure_metadata(exc: BaseException) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if isinstance(exc, PreflightFailedError):
        fields["preflight_rejected"] = True
        fields["preflight_failed"] = True
        result = getattr(exc, "result", None)
        if result is not None and hasattr(result, "to_compact_metadata"):
            fields["preflight"] = result.to_compact_metadata()
    elif isinstance(exc, _MissingPolicyEvidenceError):
        fields["preflight_rejected"] = True
        fields["preflight_failed"] = True
    return fields


def _render_transcript_markdown(metadata: dict[str, Any]) -> str:
    verifier = metadata.get("verifier") or {}
    verifier_stdout = str(verifier.get("stdout") or "")[-4000:]
    cleanup = metadata.get("cleanup") or {}
    lines = [
        f"# Terminal-Bench reference solution — {metadata.get('task_id')}",
        "",
        f"- **Result:** {metadata.get('answer')} (reward={metadata.get('reward')})",
        "- **Execution mode:** reference solution "
        f"(policy={metadata.get('policy')}, no agent)",
        f"- **Benchmark ref:** {metadata.get('harbor_ref')}",
        f"- **Task image:** {metadata.get('image')}",
        f"- **Solution path:** {metadata.get('solution_path')}",
        f"- **Solution exit code:** {metadata.get('solution_exit_code')}"
        + (" (timed out)" if metadata.get("solution_timed_out") else ""),
        f"- **Verifier exit code:** {verifier.get('exit_code')}",
        f"- **Sandbox:** {metadata.get('sandbox_id')}",
        f"- **Run id:** {metadata.get('run_id')}",
        f"- **Cleanup:** status={cleanup.get('status')} "
        f"leftovers={cleanup.get('leftover_count')} "
        f"reap_deleted={cleanup.get('reap_deleted')} "
        f"reap_failed={cleanup.get('reap_failed')}",
    ]
    if metadata.get("error_message"):
        lines += ["", "## Error", "", "```", str(metadata["error_message"]), "```"]
    if verifier_stdout:
        lines += ["", "## Verifier output (tail)", "", "```", verifier_stdout, "```"]
    return "\n".join(lines) + "\n"


@solver
def refsol_daytona_solver(
    *,
    ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    solution_timeout_sec: int | None = None,
    policy: str = REFSOL_NO_POLICY,
    solution_variant: str | None = None,
    runner: Any = run_one_refsol_task,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> Solver:
    """Run one Terminal-Bench reference solution in Daytona per sample."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        task_id = str(
            (state.metadata or {}).get("terminal_bench_task_id") or state.sample_id
        )
        display_model = str(state.model)
        retry_errors: list[str] = []
        metadata: dict[str, Any]
        for attempt in range(1, max_attempts + 1):
            try:
                loop = asyncio.get_running_loop()
                runner_kwargs = {
                    "ref": ref,
                    "solution_timeout_sec": solution_timeout_sec,
                    "policy": policy,
                }
                if solution_variant is not None:
                    runner_kwargs["solution_variant"] = solution_variant
                result = await loop.run_in_executor(
                    _runner_executor(),
                    functools.partial(
                        runner,
                        task_id,
                        **runner_kwargs,
                    ),
                )
                metadata = result.to_metadata()
                metadata["attempt"] = attempt
                metadata["max_attempts"] = max_attempts
                if retry_errors:
                    metadata["retry_errors"] = retry_errors
                if (state.metadata or {}).get("runner_provenance"):
                    metadata["runner_provenance"] = state.metadata["runner_provenance"]
                state.output = ModelOutput(
                    model=display_model,
                    completion=f"reward={result.reward} answer={result.answer}",
                    metadata=metadata,
                )
                break
            except Exception as exc:  # noqa: BLE001 - isolate per-task failures
                error_text = repr(exc)[:1000]
                if is_daytona_account_capacity_error(f"{exc!s} {exc!r}"):
                    raise
                if _is_transient_task_error(exc) and attempt < max_attempts:
                    retry_errors.append(error_text)
                    backoff = (
                        EGRESS_RETRY_BACKOFF_SEC
                        if _EGRESS_MARKER in error_text.lower()
                        else TRANSIENT_RETRY_BACKOFF_SEC * attempt
                    )
                    await asyncio.sleep(backoff)
                    continue
                probe_report: dict[str, Any] | None = None
                runtime_only_probe_failure = False
                runtime_error_count = 0
                if isinstance(exc, DaytonaRuntimeProbeSuiteError):
                    (
                        probe_report,
                        runtime_only_probe_failure,
                        runtime_error_count,
                    ) = _runtime_probe_failure_details(exc)
                invalid = isinstance(
                    exc, (PreflightFailedError, _MissingPolicyEvidenceError)
                ) or (
                    isinstance(exc, DaytonaRuntimeProbeSuiteError)
                    and not runtime_only_probe_failure
                )
                answer = "INVALID" if invalid else "ERROR"
                metadata = {
                    "task_id": task_id,
                    "harbor_ref": ref,
                    "reward": 0.0,
                    "answer": answer,
                    "error": error_text,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "policy": policy,
                    "hardened_execution": policy != REFSOL_NO_POLICY,
                    "execution_mode": "reference_solution",
                    **_exception_metadata(exc),
                    **_policy_contract_failure_metadata(exc),
                }
                if solution_variant is not None:
                    metadata["solution_variant"] = solution_variant
                if probe_report is not None:
                    metadata.update(
                        {
                            "runtime_policy_probe_report": probe_report,
                            "preflight_rejected": invalid,
                            "preflight_failed": invalid,
                            "hardening_preflight_infra_retry_eligible": (
                                runtime_only_probe_failure
                            ),
                            "hardening_preflight_runtime_error_count": (
                                runtime_error_count
                            ),
                        }
                    )
                metadata["benchmark_status"] = sample_benchmark_status(
                    metadata,
                    job_status=JobStatus.COMPLETED,
                    eval_artifact_status=EvalArtifactStatus.COMPLETE,
                )
                if retry_errors:
                    metadata["retry_errors"] = retry_errors
                if (state.metadata or {}).get("runner_provenance"):
                    metadata["runner_provenance"] = state.metadata["runner_provenance"]
                state.output = ModelOutput(
                    model=display_model,
                    completion=f"reward=0.0 answer={answer}",
                    metadata=metadata,
                )
                break
        state.metadata["terminalbench_refsol"] = metadata
        state.metadata["reward"] = float(metadata.get("reward", 0.0))
        state.metadata["transcript_markdown"] = _render_transcript_markdown(metadata)
        state.completed = True
        return state

    return solve


@scorer(metrics=[mean()])
def refsol_daytona_scorer():
    """Score = official Harbor verifier reward. Nothing else gates it.

    The score answers exactly one question — did the canonical reference
    solution pass the official verifier — so it is the raw verifier reward.
    Two things are deliberately NOT score gates:
    - Solution exit status: Harbor's oracle ignores it; canonical solve.sh
      scripts may exit nonzero while the verifier still passes (git-multibranch).
    - Sandbox cleanup: leftover/reap state is an infra-timing property (Daytona
      deletes async; auto_delete is the backstop), not a statement about
      solution correctness. Gating the score on a 30s cleanup observation makes
      a genuinely-passing task flakily score 0. Cleanup stays in metadata as
      evidence and is asserted separately (per the ticket's distinct
      "zero remaining sandboxes" criterion), not folded into correctness.
    """

    async def score(state: TaskState, target: Target) -> Score:
        metadata = (state.metadata or {}).get("terminalbench_refsol") or {}
        reward = float(metadata.get("reward", 0.0))
        answer = str(metadata.get("answer") or ("PASS" if reward > 0 else "FAIL"))
        cleanup = metadata.get("cleanup") or {}
        explanation = (
            f"Official Harbor verifier reward={reward}; "
            f"solution_exit_code={metadata.get('solution_exit_code')}; "
            f"cleanup={cleanup.get('status')} "
            f"leftovers={cleanup.get('leftover_count')}"
        )
        if answer not in {"PASS", "FAIL"}:
            return Score.unscored(
                answer=answer,
                explanation=(
                    f"{answer} — pipeline or policy-evidence failure; "
                    "excluded from reference-solution metrics"
                ),
                metadata=metadata,
            )
        return Score(
            value=reward,
            answer=answer,
            explanation=explanation,
            metadata=metadata,
        )

    return score


def _task_ids(task_ids: str | list[str]) -> list[str]:
    if isinstance(task_ids, str):
        return [tid.strip() for tid in task_ids.split(",") if tid.strip()]
    return [str(tid) for tid in task_ids]


@task
def refsol_terminalbench_daytona(
    task_ids: str | list[str] = REFSOL_DEFAULT_TASK_IDS,
    ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    solution_timeout_sec: int | None = None,
    policy: str = REFSOL_NO_POLICY,
    solution_variant: str | None = None,
) -> Task:
    """Run Terminal-Bench reference solutions in Daytona under a native policy.

    ``task_ids`` is a comma-separated list (or list) of terminal-bench-2.1 task
    ids. Every sample runs the task's shipped ``solution/solve.sh`` and the
    official Harbor verifier. ``none`` preserves the raw baseline; the five
    supported named policies apply native hardening without installing an agent
    harness or provider proxy.
    """

    ids = _task_ids(task_ids)
    resolved = {tid: _resolve_refsol_policy(policy, task_id=tid) for tid in ids}
    for tid in ids:
        _validate_solution_variant(
            solution_variant,
            task_id=tid,
            policy_name=(
                resolved[tid][0].name
                if resolved[tid][0] is not None
                else REFSOL_NO_POLICY
            ),
        )
    runner_provenance = runtime_provenance()
    samples = [
        Sample(
            id=tid,
            input=tid,
            metadata={
                "terminal_bench_task_id": tid,
                "dataset": "terminal-bench-2.1",
                "dataset_version": "terminal-bench-2.1",
                "harbor_package_ref": ref,
                "policy": (
                    resolved[tid][0].name
                    if resolved[tid][0] is not None
                    else REFSOL_NO_POLICY
                ),
                "hardened_execution": resolved[tid][0] is not None,
                "hardening_config": (
                    {
                        **resolved[tid][1].to_metadata(),
                        "enforcement_mode": resolved[tid][0].enforcement_mode,
                    }
                    if resolved[tid][0] is not None
                    else {}
                ),
                "execution_mode": "reference_solution",
                "runner_provenance": runner_provenance,
                **applicability_metadata(tid, policy),
                **(
                    {"solution_variant": solution_variant}
                    if solution_variant is not None
                    else {}
                ),
            },
        )
        for tid in ids
    ]
    return Task(
        dataset=MemoryDataset(samples),
        solver=refsol_daytona_solver(
            ref=ref,
            solution_timeout_sec=solution_timeout_sec,
            policy=policy,
            solution_variant=solution_variant,
        ),
        scorer=refsol_daytona_scorer(),
        sandbox=None,
    )
