from __future__ import annotations

import tomllib
from dataclasses import dataclass
from math import ceil
from pathlib import Path
from posixpath import isabs, normpath
from typing import Any, Literal, Mapping, cast


HarborVerifierEnvironmentMode = Literal["shared", "separate"]
HarborVerifierEnvironmentSource = Literal[
    "verifier.environment_mode",
    "verifier.environment",
    "harbor_default",
]


@dataclass(frozen=True)
class HarborVerifierEnvironmentResolution:
    mode: HarborVerifierEnvironmentMode
    source: HarborVerifierEnvironmentSource


def resolve_harbor_verifier_environment(
    harbor_config: Mapping[str, Any],
) -> HarborVerifierEnvironmentResolution:
    """Validate and resolve Harbor's authoritative single-step verifier mode."""

    from harbor.models.task.config import TaskConfig
    from harbor.models.task.verifier_mode import resolve_task_verifier_mode

    task_config = TaskConfig.model_validate(harbor_config)
    if task_config.steps:
        raise ValueError(
            "unsupported Harbor multi-step task config: the Daytona runner "
            "supports only the single-step verifier lifecycle"
        )

    mode = cast(
        HarborVerifierEnvironmentMode,
        resolve_task_verifier_mode(task_config).value,
    )
    if task_config.verifier.environment_mode is not None:
        source: HarborVerifierEnvironmentSource = "verifier.environment_mode"
    elif task_config.verifier.environment is not None:
        source = "verifier.environment"
    else:
        source = "harbor_default"
    return HarborVerifierEnvironmentResolution(
        mode=mode,
        source=source,
    )


DaytonaVerifierLifecycleSource = Literal[
    "verifier.environment_mode",
    "verifier.environment",
    "harbor_default",
]


@dataclass(frozen=True)
class DaytonaVerifierLifecycleResolution:
    declared_mode: HarborVerifierEnvironmentMode
    declared_source: HarborVerifierEnvironmentSource
    effective_mode: HarborVerifierEnvironmentMode
    effective_source: DaytonaVerifierLifecycleSource
    handoff_paths: tuple[str, ...]
    override_reason: Literal["pinned_terminal_bench_ref"] | None


def resolve_daytona_verifier_lifecycle(
    *,
    task_id: str,
    harbor_ref: str,
    declared: HarborVerifierEnvironmentResolution,
) -> DaytonaVerifierLifecycleResolution:
    """Preserve Harbor's authoritative verifier environment lifecycle."""

    return DaytonaVerifierLifecycleResolution(
        declared_mode=declared.mode,
        declared_source=declared.source,
        effective_mode=declared.mode,
        effective_source=declared.source,
        handoff_paths=(),
        override_reason=None,
    )


AgentProcessDisposition = Literal["reap", "preserve"]
AgentProcessDispositionSource = Literal[
    "safe_default",
    "boundarybench_ref_task_policy",
]
AgentProcessDispositionReason = Literal[
    "unlisted_tasks_preserve_harbor_semantics",
    "reap_conflicting_agent_process",
    "verifier_requires_live_service",
]

TERMINAL_BENCH_REF = (
    "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
)


@dataclass(frozen=True)
class AgentProcessDispositionResolution:
    disposition: AgentProcessDisposition
    source: AgentProcessDispositionSource
    reason: AgentProcessDispositionReason


_SAFE_AGENT_PROCESS_DISPOSITION = AgentProcessDispositionResolution(
    disposition="preserve",
    source="safe_default",
    reason="unlisted_tasks_preserve_harbor_semantics",
)

_AGENT_PROCESS_DISPOSITION_POLICIES: Mapping[
    tuple[str, str],
    tuple[
        HarborVerifierEnvironmentResolution,
        AgentProcessDispositionResolution,
    ],
] = {
    (
        TERMINAL_BENCH_REF,
        "pytorch-model-recovery",
    ): (
        HarborVerifierEnvironmentResolution(mode="shared", source="harbor_default"),
        AgentProcessDispositionResolution(
            disposition="reap",
            source="boundarybench_ref_task_policy",
            reason="reap_conflicting_agent_process",
        ),
    ),
    (
        TERMINAL_BENCH_REF,
        "pypi-server",
    ): (
        HarborVerifierEnvironmentResolution(mode="shared", source="harbor_default"),
        AgentProcessDispositionResolution(
            disposition="preserve",
            source="boundarybench_ref_task_policy",
            reason="verifier_requires_live_service",
        ),
    ),
}


def resolve_agent_process_disposition(
    *,
    task_id: str,
    harbor_ref: str,
    declared: HarborVerifierEnvironmentResolution,
) -> AgentProcessDispositionResolution:
    """Resolve process cleanup independently from Harbor's verifier lifecycle."""

    policy = _AGENT_PROCESS_DISPOSITION_POLICIES.get((harbor_ref, task_id))
    if policy is None:
        return _SAFE_AGENT_PROCESS_DISPOSITION

    expected_declaration, resolution = policy
    if declared != expected_declaration:
        raise ValueError(
            "Harbor verifier declaration drift for pinned agent process policy "
            f"{(harbor_ref, task_id)!r}: expected "
            f"{(expected_declaration.mode, expected_declaration.source)!r}, got "
            f"{(declared.mode, declared.source)!r}"
        )
    return resolution


AgentSessionLifecycle = Literal["preserve_until_verified", "delete_on_agent_exit"]
AgentSessionLifecycleSource = Literal[
    "safe_default",
    "boundarybench_ref_task_policy",
]
AgentSessionLifecycleReason = Literal[
    "unlisted_tasks_delete_agent_session_after_exit",
    "verifier_requires_live_service",
    "verifier_self_starts_service_from_artifacts",
]


@dataclass(frozen=True)
class AgentSessionLifecycleResolution:
    lifecycle: AgentSessionLifecycle
    source: AgentSessionLifecycleSource
    reason: AgentSessionLifecycleReason
    service_evidence: str | None = None


_SAFE_AGENT_SESSION_LIFECYCLE = AgentSessionLifecycleResolution(
    lifecycle="delete_on_agent_exit",
    source="safe_default",
    reason="unlisted_tasks_delete_agent_session_after_exit",
)


def _preserve_live_service(service_evidence: str) -> AgentSessionLifecycleResolution:
    return AgentSessionLifecycleResolution(
        lifecycle="preserve_until_verified",
        source="boundarybench_ref_task_policy",
        reason="verifier_requires_live_service",
        service_evidence=service_evidence,
    )


def _verifier_self_starts(service_evidence: str) -> AgentSessionLifecycleResolution:
    return AgentSessionLifecycleResolution(
        lifecycle="delete_on_agent_exit",
        source="boundarybench_ref_task_policy",
        reason="verifier_self_starts_service_from_artifacts",
        service_evidence=service_evidence,
    )


_AGENT_SESSION_LIFECYCLE_POLICIES: Mapping[
    tuple[str, str], AgentSessionLifecycleResolution
] = {
    (TERMINAL_BENCH_REF, "pypi-server"): _preserve_live_service(
        "pip install --index-url http://localhost:8080/simple vectorops==0.1.0 "
        "(tests/test_outputs.py:24-31)"
    ),
    (TERMINAL_BENCH_REF, "qemu-alpine-ssh"): _preserve_live_service(
        "sshpass ssh -p 2222 root@localhost 'uname -r' into agent-booted QEMU "
        "(tests/test_outputs.py:23-39)"
    ),
    (TERMINAL_BENCH_REF, "hf-model-inference"): _preserve_live_service(
        "requests.post http://localhost:5000/sentiment against agent's Flask app "
        "(tests/test_outputs.py:50,68)"
    ),
    (TERMINAL_BENCH_REF, "kv-store-grpc"): _preserve_live_service(
        "socket connect + grpc.insecure_channel to 127.0.0.1:5328 "
        "(tests/test_outputs.py:91-120)"
    ),
    (TERMINAL_BENCH_REF, "git-multibranch"): _preserve_live_service(
        "git clone/push git@localhost + curl https://localhost:8443 "
        "(tests/test_outputs.py:26-73)"
    ),
    (TERMINAL_BENCH_REF, "mailman"): _preserve_live_service(
        "smtplib.SMTP('localhost', 25) drives join/announce/leave mail pipeline "
        "(tests/test_outputs.py:89)"
    ),
    (TERMINAL_BENCH_REF, "nginx-request-logging"): _preserve_live_service(
        "requests.get http://localhost:8080 + live access-log probes "
        "(tests/test_outputs.py:22-148)"
    ),
    (TERMINAL_BENCH_REF, "qemu-startup"): _preserve_live_service(
        "expect 'spawn telnet localhost 6665' serial-console login "
        "(tests/test_outputs.py:20-60)"
    ),
    (TERMINAL_BENCH_REF, "install-windows-3.11"): _preserve_live_service(
        "pgrep qemu-system + netstat :5901/:80 + socat QEMU monitor socket + "
        "vncsnapshot (tests/test_outputs.py:21-405)"
    ),
    (TERMINAL_BENCH_REF, "configure-git-webserver"): _preserve_live_service(
        "git clone user@localhost:/git/server + curl http://localhost:8080/hello.html "
        "(tests/verify.sh:26-44)"
    ),
    (TERMINAL_BENCH_REF, "headless-terminal"): _verifier_self_starts(
        "verifier launches python -m http.server 8000 itself via delivered library "
        "(tests/test_outputs.py:124-127)"
    ),
    (TERMINAL_BENCH_REF, "torch-pipeline-parallelism"): _verifier_self_starts(
        "verifier spawns its own torch.distributed ranks on localhost:12355 "
        "(tests/test_outputs.py:48-52)"
    ),
    (TERMINAL_BENCH_REF, "torch-tensor-parallelism"): _verifier_self_starts(
        "verifier spawns its own torch.distributed ranks on localhost:12355 "
        "(tests/test_outputs.py:30-34)"
    ),
}


def resolve_agent_session_lifecycle(
    *,
    task_id: str,
    harbor_ref: str,
) -> AgentSessionLifecycleResolution:
    """Resolve whether the agent's Daytona session must outlive the agent for the verifier."""

    return _AGENT_SESSION_LIFECYCLE_POLICIES.get(
        (harbor_ref, task_id), _SAFE_AGENT_SESSION_LIFECYCLE
    )


@dataclass(frozen=True)
class TerminalBenchTaskConfig:
    task_id: str
    task_dir: Path
    agent_timeout_sec: int
    verifier_timeout_sec: int
    docker_image: str
    cpu: int
    memory_gib: int
    disk_gib: int
    gpu: int
    environment_env: dict[str, str]
    verifier_env: dict[str, str]
    solution_env: dict[str, str]
    mcp_servers: Any
    build_timeout_sec: int | None = None
    network_mode: str | None = None
    allow_internet: bool | None = None

    def resource_demand(self) -> dict[str, int]:
        return {
            "cpu": self.cpu,
            "memory_gib": self.memory_gib,
            "disk_gib": self.disk_gib,
            "gpu": self.gpu,
        }


def task_id_from_task_name(task_name: str) -> str:
    return task_name.rsplit("/", 1)[-1]


def load_task_toml(task_dir: Path, *, task_name: str = "") -> dict[str, Any]:
    task_toml = task_dir / "task.toml"
    if not task_toml.exists():
        label = f" for task {task_name}" if task_name else ""
        raise FileNotFoundError(
            f"Terminal-Bench task.toml not found{label}: {task_toml}"
        )
    with task_toml.open("rb") as f:
        payload = tomllib.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f"task.toml must contain a mapping: {task_toml}")
    return payload


def terminalbench_task_config_from_dir(
    task_dir: Path,
    *,
    task_name: str,
) -> TerminalBenchTaskConfig:
    payload = load_task_toml(task_dir, task_name=task_name)
    agent = _section(payload, "agent", task_name)
    verifier = _section(payload, "verifier", task_name)
    environment = _section(payload, "environment", task_name)
    return TerminalBenchTaskConfig(
        task_id=task_id_from_task_name(task_name),
        task_dir=task_dir,
        agent_timeout_sec=_positive_seconds(
            agent.get("timeout_sec"),
            field_name="agent.timeout_sec",
            task_name=task_name,
        ),
        verifier_timeout_sec=_positive_seconds(
            verifier.get("timeout_sec"),
            field_name="verifier.timeout_sec",
            task_name=task_name,
        ),
        docker_image=_required_string(
            environment.get("docker_image"),
            field_name="environment.docker_image",
            task_name=task_name,
        ),
        cpu=_positive_int(
            environment.get("cpus"),
            field_name="environment.cpus",
            task_name=task_name,
        ),
        memory_gib=_mb_to_gib(
            environment.get("memory_mb"),
            field_name="environment.memory_mb",
            task_name=task_name,
        ),
        disk_gib=_mb_to_gib(
            environment.get("storage_mb"),
            field_name="environment.storage_mb",
            task_name=task_name,
        ),
        gpu=_nonnegative_int(
            environment.get("gpus"),
            field_name="environment.gpus",
            task_name=task_name,
        ),
        environment_env=_string_map(
            environment.get("env"),
            field_name="environment.env",
            task_name=task_name,
        ),
        verifier_env=_string_map(
            verifier.get("env"),
            field_name="verifier.env",
            task_name=task_name,
        ),
        solution_env=_string_map(
            _section(payload, "solution", task_name).get("env"),
            field_name="solution.env",
            task_name=task_name,
        ),
        mcp_servers=_mcp_servers(
            environment.get("mcp_servers"),
            field_name="environment.mcp_servers",
            task_name=task_name,
        ),
        build_timeout_sec=_optional_positive_seconds(
            environment.get("build_timeout_sec"),
            field_name="environment.build_timeout_sec",
            task_name=task_name,
        ),
        network_mode=_optional_string(environment.get("network_mode")),
        allow_internet=_optional_bool(environment.get("allow_internet")),
    )


def terminalbench_task_config_from_bundle(bundle: Any) -> TerminalBenchTaskConfig:
    return terminalbench_task_config_from_dir(
        Path(bundle.task_dir),
        task_name=str(bundle.task_name),
    )


DEFAULT_TASK_IMAGE_WORKDIR = "/app"
SUPPORTED_TASK_WORKSPACE_ROOTS = ("/app", "/workspace")


@dataclass(frozen=True)
class TerminalBenchWorkspaceResolution:
    workdir: str
    workspace_root: str


def resolve_terminalbench_workspace(workdir: str) -> TerminalBenchWorkspaceResolution:
    if not isabs(workdir):
        raise ValueError(f"Terminal-Bench image workdir must be absolute: {workdir!r}")
    if ".." in workdir.split("/"):
        raise ValueError(
            f"Terminal-Bench image workdir must not contain traversal: {workdir!r}"
        )

    normalized = normpath(workdir)
    for workspace_root in SUPPORTED_TASK_WORKSPACE_ROOTS:
        if normalized == workspace_root or normalized.startswith(f"{workspace_root}/"):
            return TerminalBenchWorkspaceResolution(
                workdir=normalized,
                workspace_root=workspace_root,
            )
    raise ValueError(
        "Terminal-Bench image workdir must use a supported workspace root "
        f"{SUPPORTED_TASK_WORKSPACE_ROOTS}: {normalized!r}"
    )


def task_image_workdir(
    task_dir: Path, *, default: str = DEFAULT_TASK_IMAGE_WORKDIR
) -> str:
    """Resolve the task image's WORKDIR from its environment Dockerfile.

    Harbor execs both the agent and the oracle/verifier in the image's
    working directory (``sandbox().exec`` with no cwd), and tasks rely on it
    (e.g. fix-git operates on a repo at WORKDIR /app/personal-site). Daytona
    sessions do not start in the image WORKDIR, so it is resolved here from
    the shipped Dockerfile; /app is the Terminal-Bench default. Absolute and
    relative (chained) WORKDIR lines are honored; unresolved ``$``-variable
    values fail closed instead of silently falling back to another directory.
    """

    dockerfile = Path(task_dir) / "environment" / "Dockerfile"
    workdir = default
    if not dockerfile.exists():
        return workdir
    for raw_line in dockerfile.read_text(errors="replace").splitlines():
        line = raw_line.strip()
        if not line.upper().startswith("WORKDIR"):
            continue
        value = line[len("WORKDIR") :].strip().strip('"').strip("'")
        if not value:
            continue
        if "$" in value:
            raise ValueError(
                "Terminal-Bench image WORKDIR contains an unresolved variable: "
                f"{value!r}"
            )
        if value.startswith("/"):
            workdir = value
        else:
            workdir = f"{workdir.rstrip('/')}/{value}"
    return workdir


def task_image_workdir_from_bundle(bundle: Any) -> str:
    return task_image_workdir(Path(bundle.task_dir))


def terminalbench_workspace_from_bundle(
    bundle: Any,
) -> TerminalBenchWorkspaceResolution:
    return resolve_terminalbench_workspace(task_image_workdir_from_bundle(bundle))


def terminalbench_resource_demand_from_bundle(bundle: Any) -> dict[str, int]:
    return terminalbench_resource_demand_from_dir(
        Path(bundle.task_dir),
        task_name=str(bundle.task_name),
    )


def terminalbench_resource_demand_from_dir(
    task_dir: Path,
    *,
    task_name: str,
) -> dict[str, int]:
    payload = load_task_toml(task_dir, task_name=task_name)
    environment = _section(payload, "environment", task_name)
    return {
        "cpu": _positive_int(
            environment.get("cpus"),
            field_name="environment.cpus",
            task_name=task_name,
        ),
        "memory_gib": _mb_to_gib(
            environment.get("memory_mb"),
            field_name="environment.memory_mb",
            task_name=task_name,
        ),
        "disk_gib": _mb_to_gib(
            environment.get("storage_mb"),
            field_name="environment.storage_mb",
            task_name=task_name,
        ),
        "gpu": _nonnegative_int(
            environment.get("gpus"),
            field_name="environment.gpus",
            task_name=task_name,
        ),
    }


def task_toml_environment(task_dir: Path, *, task_name: str) -> dict[str, Any]:
    payload = load_task_toml(task_dir, task_name=task_name)
    environment = payload.get("environment") or {}
    if not isinstance(environment, dict):
        raise ValueError(f"task {task_name} has invalid environment config")
    return environment


def task_toml_agent_timeout(task_dir: Path, *, task_name: str) -> int:
    payload = load_task_toml(task_dir, task_name=task_name)
    agent = _section(payload, "agent", task_name)
    return _positive_seconds(
        agent.get("timeout_sec"),
        field_name="agent.timeout_sec",
        task_name=task_name,
    )


def _section(
    payload: Mapping[str, Any],
    section_name: str,
    task_name: str,
) -> Mapping[str, Any]:
    value = payload.get(section_name)
    if not isinstance(value, Mapping):
        raise ValueError(f"task {task_name} missing task.toml [{section_name}] section")
    return value


def _positive_seconds(value: Any, *, field_name: str, task_name: str) -> int:
    parsed = _optional_positive_seconds(
        value, field_name=field_name, task_name=task_name
    )
    if parsed is None:
        raise ValueError(f"task {task_name} missing task.toml {field_name}")
    return parsed


def _optional_positive_seconds(
    value: Any,
    *,
    field_name: str,
    task_name: str,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        )
    try:
        parsed = int(float(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        ) from exc
    if parsed <= 0:
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        )
    return parsed


def _positive_int(value: Any, *, field_name: str, task_name: str) -> int:
    parsed = _nonnegative_int(value, field_name=field_name, task_name=task_name)
    if parsed <= 0:
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        )
    return parsed


def _nonnegative_int(value: Any, *, field_name: str, task_name: str) -> int:
    if value is None:
        raise ValueError(f"task {task_name} missing task.toml {field_name}")
    if isinstance(value, bool):
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        )
    try:
        parsed = int(float(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        ) from exc
    if parsed < 0:
        raise ValueError(
            f"task {task_name} has invalid task.toml {field_name}: {value!r}"
        )
    return parsed


def _mb_to_gib(value: Any, *, field_name: str, task_name: str) -> int:
    parsed = _positive_int(value, field_name=field_name, task_name=task_name)
    return max(1, ceil(parsed / 1024))


def _required_string(value: Any, *, field_name: str, task_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"task {task_name} missing task.toml {field_name}")
    return value.strip()


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    return value.strip() or None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return None


def _string_map(value: Any, *, field_name: str, task_name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"task {task_name} has invalid task.toml {field_name}")
    return {str(key): str(item) for key, item in value.items()}


def _mcp_servers(value: Any, *, field_name: str, task_name: str) -> Any:
    if value is None:
        return []
    if not isinstance(value, (Mapping, list)):
        raise ValueError(f"task {task_name} has invalid task.toml {field_name}")
    return dict(value) if isinstance(value, Mapping) else list(value)
