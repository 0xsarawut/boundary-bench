"""Reusable policy preflight proof plans and result metadata.

The preflight gate proves a selected policy inside the exact benchmark image
before the agent starts. Proof plans are derived from policy/config surfaces so
new policies can add rules without adding policy-name conditionals to benchmark
runners.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from boundarybench.policy_surfaces.catalog import PolicySurfaceProbe
from boundarybench.policy_surfaces.evaluator import (
    ProbeExecution,
    ProbeResult,
    evaluate_probe,
)
from boundarybench.policy_surfaces.markers import contains_policy_blocked_output_marker


PREFLIGHT_SCHEMA = "boundarybench.policy-preflight.v1"


class PolicyHardeningConfig(Protocol):
    denied_command_names: tuple[str, ...]
    denied_exec_paths: tuple[str, ...]
    denied_path_exact: tuple[str, ...]
    denied_path_prefixes: tuple[str, ...]
    tee_denied_patterns: tuple[str, ...]
    child_network_command_names: tuple[str, ...]
    strip_env_vars: tuple[str, ...]


@dataclass(frozen=True)
class PolicyPreflightSpec:
    """Benchmark-independent policy inputs needed to build proof probes."""

    policy: str
    overlays: tuple[str, ...]
    config: PolicyHardeningConfig
    agent_user: str
    run_agent_as_root: bool


@dataclass(frozen=True)
class PolicyProofProbe:
    """One executable proof for one policy rule."""

    probe_id: str
    rule_id: str
    surface: str
    command: str
    expectation: str
    description: str
    required_for_benchmark: bool = True
    policy_evidence_required: bool = True
    timeout_seconds: int = 30
    env: dict[str, str] = field(default_factory=dict)
    unsupported_reason: str | None = None

    def to_surface_probe(self) -> PolicySurfaceProbe:
        return PolicySurfaceProbe(
            case_id=self.probe_id,
            surface=self.surface,
            command=self.command,
            expectation=self.expectation,  # type: ignore[arg-type]
            description=self.description,
            required_for_benchmark=self.required_for_benchmark,
            policy_evidence_required=self.policy_evidence_required,
            timeout_seconds=self.timeout_seconds,
        )

    def to_metadata(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "rule_id": self.rule_id,
            "surface": self.surface,
            "command": self.command,
            "expectation": self.expectation,
            "description": self.description,
            "required_for_benchmark": self.required_for_benchmark,
            "policy_evidence_required": self.policy_evidence_required,
            "timeout_seconds": self.timeout_seconds,
            "env_keys": sorted(self.env),
            "unsupported_reason": self.unsupported_reason,
        }

    def to_probe_result(
        self,
        *,
        observed: str,
        status: str,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        message: str,
    ) -> ProbeResult:
        return ProbeResult(
            case_id=self.probe_id,
            surface=self.surface,
            expected=self.expectation,
            observed=observed,
            status=status,
            required_for_benchmark=self.required_for_benchmark,
            policy_evidence_required=self.policy_evidence_required,
            policy_evidence_seen=status == "pass",
            policy_evidence_id=None,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            message=message,
            metadata={
                "rule_id": self.rule_id,
                "probe_id": self.probe_id,
                "proof": self.to_metadata(),
            },
        )


@dataclass(frozen=True)
class PolicyProofRule:
    """A selected policy rule and the probes that prove it."""

    rule_id: str
    surface: str
    target: str
    config_source: str
    probe_ids: tuple[str, ...]
    required_for_benchmark: bool = True

    def to_metadata(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "surface": self.surface,
            "target": self.target,
            "config_source": self.config_source,
            "probe_ids": list(self.probe_ids),
            "required_for_benchmark": self.required_for_benchmark,
        }


@dataclass(frozen=True)
class PolicyProofPlan:
    """The complete proof plan for one selected policy."""

    policy: str
    rules: tuple[PolicyProofRule, ...]
    probes: tuple[PolicyProofProbe, ...]

    @property
    def required_rules(self) -> tuple[PolicyProofRule, ...]:
        return tuple(rule for rule in self.rules if rule.required_for_benchmark)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": PREFLIGHT_SCHEMA,
            "policy": self.policy,
            "required_rule_count": len(self.required_rules),
            "probe_count": len(self.probes),
            "rules": [rule.to_metadata() for rule in self.rules],
            "probes": [probe.to_metadata() for probe in self.probes],
        }


@dataclass(frozen=True)
class PreflightResult:
    """Outcome of a policy proof plan in one task image."""

    passed: bool
    proof_plan: PolicyProofPlan
    results: tuple[ProbeResult, ...]
    failed_probes: tuple[ProbeResult, ...] = field(default_factory=tuple)

    @property
    def failed_rule_ids(self) -> tuple[str, ...]:
        seen: list[str] = []
        for probe in self.failed_probes:
            rule_id = _probe_rule_id(probe)
            if rule_id and rule_id not in seen:
                seen.append(rule_id)
        return tuple(seen)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": PREFLIGHT_SCHEMA,
            "preflight_passed": self.passed,
            "proof_plan": self.proof_plan.to_metadata(),
            "probe_count": len(self.results),
            "failed_count": len(self.failed_probes),
            "failed_rule_ids": list(self.failed_rule_ids),
            "failed_probe_ids": [probe.case_id for probe in self.failed_probes],
            "failed_probes": [probe.to_metadata() for probe in self.failed_probes],
            "all_probes": [probe.to_metadata() for probe in self.results],
        }

    def to_compact_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": PREFLIGHT_SCHEMA,
            "preflight_passed": self.passed,
            "policy": self.proof_plan.policy,
            "required_rule_count": len(self.proof_plan.required_rules),
            "probe_count": len(self.results),
            "failed_count": len(self.failed_probes),
            "failed_rule_ids": list(self.failed_rule_ids),
            "failed_probe_ids": [probe.case_id for probe in self.failed_probes],
            "rules": [rule.to_metadata() for rule in self.proof_plan.rules],
            "all_probes": [_compact_probe_result(probe) for probe in self.results],
        }


class PreflightFailedError(RuntimeError):
    """Raised when a required policy proof fails before agent launch."""

    def __init__(self, message: str, *, result: PreflightResult) -> None:
        super().__init__(message)
        self.result = result

    def to_metadata(self) -> dict[str, Any]:
        return self.result.to_metadata()


def build_policy_proof_plan_from_spec(spec: PolicyPreflightSpec) -> PolicyProofPlan:
    """Derive a proof plan from the selected policy and hardening config."""

    if not spec.overlays:
        return PolicyProofPlan(policy=spec.policy, rules=(), probes=())

    rules: list[PolicyProofRule] = []
    probes: list[PolicyProofProbe] = []

    if "nonroot-agent" in spec.overlays and not spec.run_agent_as_root:
        _append_rule(
            rules,
            probes,
            rule_id=f"nonroot-agent:{spec.agent_user}",
            surface="user",
            target=spec.agent_user,
            config_source="agent_user",
            command='test "$(id -u)" != "0" 2>&1',
            expectation="allowed",
            description=f"Agent runs as non-root user {spec.agent_user}.",
            policy_evidence_required=False,
        )

    if "blocked-surfaces" in spec.overlays:
        for name in spec.config.denied_command_names:
            quoted = shlex.quote(name)
            _append_rule(
                rules,
                probes,
                rule_id=f"command-name:{name}",
                surface="command",
                target=name,
                config_source="denied_command_names",
                command=f"{quoted} --version 2>&1",
                expectation="blocked",
                description=f"Command name {name!r} is denied by PATH shim policy.",
            )
        for path in spec.config.denied_exec_paths:
            _append_rule(
                rules,
                probes,
                rule_id=f"exec-path:{path}",
                surface="exec-path",
                target=path,
                config_source="denied_exec_paths",
                command=f"{shlex.quote(path)} --version 2>&1",
                expectation="blocked",
                description=f"Executable path {path!r} is denied by mount policy.",
            )
        for path in spec.config.denied_path_exact:
            _append_rule(
                rules,
                probes,
                rule_id=f"path-exact:{path}",
                surface="file-read",
                target=path,
                config_source="denied_path_exact",
                command=_read_probe(path),
                expectation="blocked",
                description=f"Exact path {path!r} is denied by preload policy.",
            )
        for prefix in spec.config.denied_path_prefixes:
            probe_path = _prefix_probe_path(prefix)
            _append_rule(
                rules,
                probes,
                rule_id=f"path-prefix:{prefix}",
                surface="file-read",
                target=prefix,
                config_source="denied_path_prefixes",
                command=_read_probe(probe_path),
                expectation="blocked",
                description=f"Path prefix {prefix!r} is denied by preload policy.",
            )
        for pattern in spec.config.tee_denied_patterns:
            probe_path = _tee_probe_path(pattern)
            _append_rule(
                rules,
                probes,
                rule_id=f"tee-pattern:{pattern}",
                surface="file-write",
                target=pattern,
                config_source="tee_denied_patterns",
                command=f"echo x | tee {shlex.quote(probe_path)} 2>&1",
                expectation="blocked",
                description=f"tee writes matching {pattern!r} are denied.",
            )

    if "env-strip" in spec.overlays:
        for name in spec.config.strip_env_vars:
            _append_rule(
                rules,
                probes,
                rule_id=f"env-var:{name}",
                surface="environment",
                target=name,
                config_source="strip_env_vars",
                command=f"test -z \"$${name}\" 2>&1".replace("$$", "$"),
                expectation="absent",
                description=f"Environment variable {name!r} is stripped.",
                policy_evidence_required=False,
                env={name: "boundarybench-env-probe-secret"},
            )

    if "child-network" in spec.overlays:
        command_denied_names = set(spec.config.denied_command_names)
        for name in spec.config.child_network_command_names:
            child_probe = _child_network_probe(name)
            required_for_benchmark = name not in command_denied_names
            if child_probe is None:
                _append_rule(
                    rules,
                    probes,
                    rule_id=f"child-network:{name}",
                    surface="network",
                    target=name,
                    config_source="child_network_command_names",
                    command="",
                    expectation="blocked",
                    description=(
                        f"Child command {name!r} cannot make direct network calls."
                    ),
                    required_for_benchmark=False,
                    policy_evidence_required=False,
                    unsupported_reason=(
                        "no deterministic child-network probe is implemented "
                        f"for command {name!r}"
                    ),
                )
            else:
                _append_rule(
                    rules,
                    probes,
                    rule_id=f"child-network:{name}",
                    surface="network",
                    target=name,
                    config_source="child_network_command_names",
                    command=child_probe,
                    expectation="blocked",
                    description=(
                        f"Child command {name!r} cannot make direct network calls."
                    ),
                    required_for_benchmark=required_for_benchmark,
                    policy_evidence_required=required_for_benchmark,
                )

    return PolicyProofPlan(
        policy=spec.policy,
        rules=tuple(rules),
        probes=tuple(probes),
    )


def build_preflight_result(
    proof_plan: PolicyProofPlan, results: tuple[ProbeResult, ...]
) -> PreflightResult:
    """Build the shared preflight outcome from executed probe results."""

    failed = tuple(
        result
        for result in results
        if result.required_for_benchmark and result.status == "fail"
    )
    return PreflightResult(
        passed=not failed,
        proof_plan=proof_plan,
        results=results,
        failed_probes=failed,
    )


def raise_if_preflight_failed(preflight: PreflightResult) -> None:
    if preflight.passed:
        return
    failed_rules = ", ".join(preflight.failed_rule_ids)
    raise PreflightFailedError(
        "policy preflight failed" + (f": {failed_rules}" if failed_rules else ""),
        result=preflight,
    )


def _append_rule(
    rules: list[PolicyProofRule],
    probes: list[PolicyProofProbe],
    *,
    rule_id: str,
    surface: str,
    target: str,
    config_source: str,
    command: str,
    expectation: str,
    description: str,
    required_for_benchmark: bool = True,
    policy_evidence_required: bool = True,
    env: dict[str, str] | None = None,
    unsupported_reason: str | None = None,
) -> None:
    probe_id = f"{rule_id}:probe"
    probes.append(
        PolicyProofProbe(
            probe_id=probe_id,
            rule_id=rule_id,
            surface=surface,
            command=command,
            expectation=expectation,
            description=description,
            required_for_benchmark=required_for_benchmark,
            policy_evidence_required=policy_evidence_required,
            env=dict(env or {}),
            unsupported_reason=unsupported_reason,
        )
    )
    rules.append(
        PolicyProofRule(
            rule_id=rule_id,
            surface=surface,
            target=target,
            config_source=config_source,
            probe_ids=(probe_id,),
            required_for_benchmark=required_for_benchmark,
        )
    )


def unsupported_policy_probe_result(probe: PolicyProofProbe) -> ProbeResult:
    if probe.unsupported_reason:
        return probe.to_probe_result(
            observed="unsupported",
            status="unsupported",
            exit_code=None,
            stdout="",
            stderr="",
            message=f"probe is unsupported: {probe.unsupported_reason}",
        )
    raise ValueError(f"probe {probe.probe_id!r} is not marked unsupported")


def policy_evidence_seen(
    stdout: str, stderr: str, *, block_message: str | None = None
) -> bool:
    combined = f"{stdout}\n{stderr}"
    if contains_policy_blocked_output_marker(combined):
        return True
    normalized = combined.lower()
    if block_message and block_message.strip():
        if block_message.lower() in normalized:
            return True
    generic_denials = (
        "permission denied",
        "operation not permitted",
        "not allowed",
    )
    return any(marker in normalized for marker in generic_denials)


def evaluate_policy_proof_probe(
    probe: PolicyProofProbe, execution: ProbeExecution
) -> ProbeResult:
    evaluated = evaluate_probe(probe.to_surface_probe(), execution)
    if _probe_target_unavailable(probe, execution):
        evaluated = replace(
            evaluated,
            observed="not_applicable",
            status="not_applicable",
            policy_evidence_seen=False,
            message="probe target was not available in this task image",
        )
    return replace(
        evaluated,
        metadata={
            **evaluated.metadata,
            "rule_id": probe.rule_id,
            "probe_id": probe.probe_id,
            "proof": probe.to_metadata(),
        },
    )


def _read_probe(path: str) -> str:
    return (
        "python3 -c "
        + shlex.quote(
            "import sys; "
            f"open({path!r}, 'rb').read(1); "
            "sys.stdout.write('read allowed')"
        )
        + " 2>&1"
    )


def _prefix_probe_path(prefix: str) -> str:
    if prefix.endswith("/"):
        return prefix + "boundarybench-preflight"
    if prefix.endswith("*"):
        return prefix.rstrip("*") + "boundarybench-preflight"
    return prefix


def _tee_probe_path(pattern: str) -> str:
    if pattern.endswith("*"):
        return pattern.rstrip("*") + "boundarybench-preflight"
    if pattern.endswith("/"):
        return pattern + "boundarybench-preflight"
    return pattern


def _child_network_probe(command_name: str) -> str | None:
    quoted = shlex.quote(command_name)
    script = (
        "import socket; "
        "sock=socket.socket(); "
        "sock.settimeout(5); "
        "sock.connect(('93.184.216.34', 80)); "
        "print('connected')"
    )
    if command_name in {"python", "python3"}:
        shell_script = f"{quoted} -c {shlex.quote(script)}"
        return f"bash -lc {shlex.quote(shell_script)} 2>&1"
    if command_name in {"bash", "bash.real", "sh", "dash"}:
        shell_script = f"python3 -c {shlex.quote(script)}"
        return f"{quoted} -c {shlex.quote(shell_script)} 2>&1"
    if command_name == "curl":
        return f"{quoted} --max-time 5 http://93.184.216.34 2>&1"
    if command_name == "wget":
        return f"{quoted} -T 5 -O - http://93.184.216.34 2>&1"
    if command_name in {"nc", "netcat"}:
        return f"printf '' | {quoted} -w 5 93.184.216.34 80 2>&1"
    if command_name == "git":
        return f"{quoted} ls-remote http://93.184.216.34/preflight 2>&1"
    if command_name in {"pip", "pip3"}:
        return (
            f"{quoted} index versions boundarybench-preflight-never "
            "--index-url http://93.184.216.34/simple "
            "--trusted-host 93.184.216.34 --timeout 5 --retries 0 2>&1"
        )
    if command_name == "uv":
        return (
            f"{quoted} pip install boundarybench-preflight-never "
            "--index-url http://93.184.216.34/simple 2>&1"
        )
    if command_name in {"npm", "pnpm"}:
        return (
            f"{quoted} view boundarybench-preflight-never "
            "--registry http://93.184.216.34 2>&1"
        )
    if command_name == "perl":
        perl_script = (
            "use IO::Socket::INET; "
            "IO::Socket::INET->new(PeerAddr=>'93.184.216.34',PeerPort=>80,Timeout=>5) "
            "or die $!;"
        )
        return f"{quoted} -e {shlex.quote(perl_script)} 2>&1"
    if command_name == "ruby":
        ruby_script = (
            "require 'socket'; "
            "s=TCPSocket.new('93.184.216.34',80); "
            "puts 'connected'; s.close"
        )
        return f"{quoted} -e {shlex.quote(ruby_script)} 2>&1"
    return None


def _probe_rule_id(result: ProbeResult) -> str:
    rule_id = result.metadata.get("rule_id")
    return str(rule_id) if rule_id else ""


def _compact_probe_result(result: ProbeResult) -> dict[str, Any]:
    return {
        "case_id": result.case_id,
        "probe_id": str(result.metadata.get("probe_id") or result.case_id),
        "rule_id": _probe_rule_id(result),
        "surface": result.surface,
        "expected": result.expected,
        "observed": result.observed,
        "status": result.status,
        "required_for_benchmark": result.required_for_benchmark,
        "policy_evidence_required": result.policy_evidence_required,
        "policy_evidence_seen": result.policy_evidence_seen,
        "policy_evidence_id": result.policy_evidence_id,
        "exit_code": result.exit_code,
    }


def preflight_fixture_commands(proof_plan: PolicyProofPlan) -> list[str]:
    dirs: set[str] = set()
    files: set[str] = set()
    remove_paths: set[str] = set()
    prefix_roots = {
        rule.target.rstrip("/")
        for rule in proof_plan.rules
        if rule.config_source == "denied_path_prefixes"
    }

    for rule in proof_plan.rules:
        if rule.config_source == "denied_path_exact":
            if not _can_materialize_fixture(rule.target):
                continue
            if rule.target.rstrip("/") in prefix_roots:
                dirs.add(rule.target)
            else:
                files.add(rule.target)
                dirs.add(_parent_dir(rule.target))
        elif rule.config_source == "denied_path_prefixes":
            path = _prefix_probe_path(rule.target)
            if not _can_materialize_fixture(path):
                continue
            files.add(path)
            dirs.add(_parent_dir(path))
        elif rule.config_source == "tee_denied_patterns":
            path = _tee_probe_path(rule.target)
            if not _can_materialize_fixture(path):
                continue
            remove_paths.add(path)
            dirs.add(_parent_dir(path))

    files = {path for path in files if path not in dirs}
    commands: list[str] = []
    for directory in sorted(dirs):
        if directory and directory != "/":
            commands.append(f"mkdir -p {shlex.quote(directory)}")
    for path in sorted(files):
        content, mode = _fixture_file_content_and_mode(path)
        quoted = shlex.quote(path)
        commands.append(
            f"if [ ! -e {quoted} ]; then "
            f"printf '%s\\n' {shlex.quote(content)} "
            f"> {quoted}; "
            f"chmod {mode} {quoted}; "
            "fi"
        )
    for path in sorted(remove_paths):
        commands.append(f"rm -f {shlex.quote(path)}")
    return commands


def _can_materialize_fixture(path: str) -> bool:
    normalized = "/" + path.lstrip("/")
    return not normalized.startswith(("/dev/", "/proc/", "/sys/"))


def _fixture_file_content_and_mode(path: str) -> tuple[str, str]:
    if path == "/etc/sudoers" or path.startswith("/etc/sudoers.d/"):
        return "# boundarybench-preflight", "0440"
    return "boundarybench-preflight", "0644"


def _parent_dir(path: str) -> str:
    stripped = path.rstrip("/")
    if "/" not in stripped:
        return "."
    parent = stripped.rsplit("/", 1)[0]
    return parent or "/"


def _probe_target_unavailable(
    probe: PolicyProofProbe, execution: ProbeExecution
) -> bool:
    output = execution.output.lower()
    if execution.exit_code is None or execution.exit_code == 0:
        return False
    unavailable_markers = (
        "no such file or directory",
        "command not found",
        "not found",
        "cannot access",
    )
    if not any(marker in output for marker in unavailable_markers):
        return False
    return probe.surface in {"command", "exec-path", "file-read", "file-write", "network"}
