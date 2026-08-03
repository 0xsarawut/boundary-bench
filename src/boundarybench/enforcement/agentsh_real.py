from __future__ import annotations

import asyncio
import contextlib
import http.client
import ipaddress
import json
import os
import shlex
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from boundarybench.enforcement.agentsh_events import AgentSHEvent
from boundarybench.enforcement.agentsh_policy_compiler import (
    compile_agentsh_policy,
)
from boundarybench.enforcement.agentsh_policy_constants import (
    BASE_DENIED_PRIVILEGE_COMMANDS,
)
from boundarybench.enforcement.agentsh_policy_materialize import (
    materialize_agentsh_policy,
)
from boundarybench.enforcement.agentsh_policy_types import (
    AgentSHPolicyBundle,
    AgentSHPolicyRule,
)
from boundarybench.enforcement.agentsh_preflight import (
    build_agentsh_preflight_results,
)
from boundarybench.enforcement.agentsh_types import (
    AgentSHPreflightReport,
    AgentSHSession,
)
from boundarybench.enforcement.config import EnforcementConfig
from boundarybench.enforcement.preflight import preflight_passed


KNOWN_DENY_MARKERS = (
    "blocked by agentsh policy",
    "agentsh policy denied",
    "denied by agentsh policy",
    "agentsh: denied",
)


@dataclass(frozen=True)
class AgentSHProbeSpec:
    rule: AgentSHPolicyRule
    command: tuple[str, ...]
    expected_decision: str
    target_path: str | None = None


class RealAgentSHBackend:
    """Fail-closed real AgentSH boundary backed by structured subprocess calls."""

    backend_kind = "real"
    evidence_tier = "real_agentsh"
    wraps_upstream_solver = False

    def __init__(
        self,
        *,
        agentsh_bin: str | None = None,
        runtime_mode: str | None = None,
        version_timeout_seconds: float = 5.0,
        ready_timeout_seconds: float = 10.0,
    ) -> None:
        self.agentsh_bin = agentsh_bin or os.environ.get("AGENTSH_BIN")
        self.runtime_mode = (
            runtime_mode
            or os.environ.get("BOUNDARYBENCH_AGENTSH_RUNTIME")
            or "server_session"
        )
        if self.runtime_mode not in {"server_session", "cli_wrap"}:
            raise ValueError(
                "BOUNDARYBENCH_AGENTSH_RUNTIME must be "
                "'server_session' or 'cli_wrap'"
            )
        self.version_timeout_seconds = version_timeout_seconds
        self.ready_timeout_seconds = ready_timeout_seconds
        self.server_url = os.environ.get("AGENTSH_SERVER", "http://127.0.0.1:18080")
        self._server_process: asyncio.subprocess.Process | None = None
        self._probe_env_overrides: dict[str, str] = {}
        self._probe_fixture_metadata: dict[str, Any] = {}

    def compile_policy(self, config: EnforcementConfig) -> AgentSHPolicyBundle:
        bundle = compile_agentsh_policy(config)
        return materialize_agentsh_policy(bundle)

    async def start_session(
        self, config: EnforcementConfig, policy: AgentSHPolicyBundle
    ) -> AgentSHSession:
        if not self.agentsh_bin:
            raise RuntimeError(
                "enforcement=agentsh real backend requires AGENTSH_BIN; "
                "it will not silently fall back to the fake backend."
            )
        version = await self._version()
        self._probe_env_overrides, self._probe_fixture_metadata = (
            _prepare_agentsh_probe_fixtures(config)
        )
        _reset_agentsh_audit_file(policy.audit_path)
        workspace = Path(tempfile.mkdtemp(prefix="boundarybench-agentsh-"))
        session_id = f"boundarybench-{config.config_id}"
        session_creation = "cli_wrap_smoke"
        server_metadata: dict[str, Any] = {}
        if self.runtime_mode == "server_session":
            await self._start_server(policy)
            try:
                create_result = await self._run(
                    "session",
                    "create",
                    "--workspace",
                    str(workspace),
                    "--policy",
                    policy.policy_name,
                    "--json",
                    config_path=policy.config_path,
                    timeout_seconds=10.0,
                )
                if create_result["exit_code"] != 0:
                    raise RuntimeError(
                        "agentsh session create failed: "
                        f"{create_result['stderr'] or create_result['stdout']}"
                    )
                session_id = _parse_session_id(create_result["stdout"])
            except Exception:
                await self._stop_server()
                raise
            session_creation = "server_session"
            server_metadata = {
                "server_url": self.server_url,
                "session_create": create_result,
            }
        return AgentSHSession(
            session_id=session_id,
            policy=policy,
            backend_kind=self.backend_kind,
            evidence_tier=self.evidence_tier,
            agentsh_version=version,
            metadata={
                "fake": False,
                "silent_fallback": False,
                "benchmark_claim": "none",
                "policy_name": policy.policy_name,
                "policy_path": policy.policy_path,
                "config_path": policy.config_path,
                "audit_path": policy.audit_path,
                "workspace": str(workspace),
                "probe_fixtures": dict(self._probe_fixture_metadata),
                "runtime_mode": self.runtime_mode,
                "session_creation": session_creation,
                **server_metadata,
            },
        )

    async def run_preflight(
        self, config: EnforcementConfig, session: AgentSHSession
    ) -> AgentSHPreflightReport:
        try:
            validation = await self._run(
                "policy",
                "--config",
                session.policy.config_path,
                "validate",
                session.policy.policy_path,
                config_path=session.policy.config_path,
                timeout_seconds=10.0,
            )
            if validation["exit_code"] != 0:
                return AgentSHPreflightReport(
                    status="fail",
                    passed=False,
                    backend=self.backend_kind,
                    evidence_tier=self.evidence_tier,
                    session=session,
                    events=(),
                    results=(),
                    errors=(
                        {
                            "failure_type": "real_agentsh_policy_validation_failed",
                            "message": "agentsh policy validate failed",
                            "validation": validation,
                        },
                    ),
                    metadata={"fake": False, "silent_fallback": False},
                )

            events = tuple(await self._run_policy_probes(config, session))
            results = build_agentsh_preflight_results(
                config,
                session.policy,
                events,
                session_id=session.session_id,
            )
            passed = preflight_passed(results)
            return AgentSHPreflightReport(
                status="pass" if passed else "fail",
                passed=passed,
                backend=self.backend_kind,
                evidence_tier=self.evidence_tier,
                session=session,
                events=events,
                results=results,
                metadata={
                    "fake": False,
                    "silent_fallback": False,
                    "policy_validation": validation,
                    "preflight_scope": "agentsh_runtime_policy_probe",
                    "runtime_mode": self.runtime_mode,
                },
            )
        finally:
            if self.runtime_mode == "server_session":
                await self._stop_server()

    async def _version(self) -> str | None:
        assert self.agentsh_bin is not None
        process = await asyncio.create_subprocess_exec(
            self.agentsh_bin,
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.version_timeout_seconds
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise RuntimeError(
                "AGENTSH_BIN --version timed out after "
                f"{self.version_timeout_seconds:g}s"
            ) from exc
        output = (stdout or stderr).decode("utf-8", errors="replace").strip()
        if not output:
            raise RuntimeError("AGENTSH_BIN --version returned empty output")
        if "agentsh" not in output.lower():
            raise RuntimeError(
                "AGENTSH_BIN --version did not look like agentsh output: "
                f"{output}"
            )
        return output

    async def _run_policy_probes(
        self, config: EnforcementConfig, session: AgentSHSession
    ) -> tuple[AgentSHEvent, ...]:
        probes = _probe_specs_for_policy(session.policy)

        if self.runtime_mode == "server_session":
            return await self._run_server_session_probes(config, session, probes)

        events: list[AgentSHEvent] = []
        for probe in probes:
            try:
                result = await self._run_wrap_probe(session, probe.command)
            except Exception as exc:
                result = _probe_exception_result("wrap", session, probe.command, exc)
            exit_code = int(result["exit_code"])
            block_message = _block_message_for_probe(probe)
            decision = _classify_probe_result(
                result, expected_block_message=block_message
            )
            events.append(
                AgentSHEvent(
                    event_id=f"real-{probe.rule.check_id}",
                    timestamp="",
                    rule_id=probe.rule.rule_id,
                    check_id=probe.rule.check_id,
                    action=probe.rule.action,
                    decision=decision,
                    command=" ".join(probe.command),
                    path=probe.target_path,
                    session_id=session.session_id,
                    policy_digest=session.policy.policy_digest,
                    raw={
                        "expected_decision": probe.expected_decision,
                        "normalized_block_message": block_message,
                        "exit_code": exit_code,
                        "stdout": result["stdout"],
                        "stderr": result["stderr"],
                        "argv": result["argv"],
                    },
                )
            )
        return tuple(events)

    async def _run_server_session_probes(
        self,
        config: EnforcementConfig,
        session: AgentSHSession,
        probes: tuple[AgentSHProbeSpec, ...],
    ) -> tuple[AgentSHEvent, ...]:
        events: list[AgentSHEvent] = []
        command_results: dict[str, dict[str, Any]] = {}
        for probe in probes:
            try:
                command_results[probe.rule.check_id] = (
                    await self._run_session_exec_probe(session, probe.command)
                )
            except Exception as exc:
                command_results[probe.rule.check_id] = _probe_exception_result(
                    "exec", session, probe.command, exc
                )

        user_probe = next(
            (probe for probe in probes if probe.rule.hardening_type == "user"),
            None,
        )
        subprocess_sudo: dict[str, Any] | None = None
        if user_probe is not None:
            subprocess_command = (
                "python3",
                "-c",
                "import subprocess,sys; "
                'sys.exit(subprocess.run(["sudo","-n","true"]).returncode)',
            )
            try:
                subprocess_sudo = await self._run_session_exec_probe(
                    session,
                    subprocess_command,
                )
            except Exception as exc:
                subprocess_sudo = _probe_exception_result(
                    "exec", session, subprocess_command, exc
                )

        audit_events = _read_agentsh_audit_events(
            session.policy.audit_path, session_id=session.session_id
        )
        ptrace_sudo_denies = [
            event
            for event in audit_events
            if event.get("type") == "ptrace_execve"
            and (event.get("fields") or {}).get("decision") == "deny"
            and _audit_argv_contains(event, "sudo")
        ]
        ptrace_sudo_deny_count = len(_distinct_audit_events(ptrace_sudo_denies))
        subprocess_ptrace_boundary_enforced = ptrace_sudo_deny_count >= 2

        for probe in probes:
            result = command_results[probe.rule.check_id]
            exit_code = int(result["exit_code"])
            block_message = _block_message_for_probe(probe)
            decision = _classify_probe_result(
                result, expected_block_message=block_message
            )
            raw: dict[str, Any] = {
                "expected_decision": probe.expected_decision,
                "exit_code": exit_code,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "argv": result["argv"],
                "normalized_block_message": block_message,
            }
            if probe.rule.hardening_type == "user" and subprocess_sudo is not None:
                direct_decision = decision
                if direct_decision == "error" and ptrace_sudo_denies:
                    direct_decision = "denied"
                subprocess_decision = _classify_probe_result(
                    subprocess_sudo,
                    expected_block_message=block_message,
                )
                if (
                    subprocess_decision == "error"
                    and subprocess_ptrace_boundary_enforced
                ):
                    subprocess_decision = "denied"
                decision = (
                    "allowed"
                    if "allowed" in {direct_decision, subprocess_decision}
                    else (
                        "denied"
                        if direct_decision == "denied"
                        and subprocess_decision == "denied"
                        else "error"
                    )
                )
                raw.update(
                    {
                        "direct_probe_decision": direct_decision,
                        "subprocess_probe": subprocess_sudo,
                        "subprocess_probe_decision": subprocess_decision,
                        "os_boundary_enforced": bool(ptrace_sudo_denies),
                        "os_boundary_event_type": (
                            "ptrace_execve" if ptrace_sudo_denies else None
                        ),
                        "subprocess_os_boundary_enforced": (
                            subprocess_ptrace_boundary_enforced
                        ),
                        "ptrace_execve_deny_count": ptrace_sudo_deny_count,
                        "ptrace_execve_denies": ptrace_sudo_denies,
                    }
                )
            events.append(
                AgentSHEvent(
                    event_id=f"real-{probe.rule.check_id}",
                    timestamp="",
                    rule_id=probe.rule.rule_id,
                    check_id=probe.rule.check_id,
                    action=probe.rule.action,
                    decision=decision,
                    command=" ".join(probe.command),
                    path=probe.target_path,
                    session_id=session.session_id,
                    policy_digest=session.policy.policy_digest,
                    raw=raw,
                )
            )
        return tuple(events)

    async def _run_wrap_probe(
        self, session: AgentSHSession, command: tuple[str, ...]
    ) -> dict[str, Any]:
        workspace = str(session.metadata.get("workspace") or tempfile.gettempdir())
        return await self._run(
            "--client-timeout",
            "10s",
            "wrap",
            "--policy",
            session.policy.policy_name,
            "--root",
            workspace,
            "--report=false",
            "--",
            *command,
            config_path=session.policy.config_path,
            timeout_seconds=20.0,
        )

    async def _run_session_exec_probe(
        self, session: AgentSHSession, command: tuple[str, ...]
    ) -> dict[str, Any]:
        return await self._run(
            "exec",
            session.session_id,
            "--",
            *command,
            config_path=session.policy.config_path,
            timeout_seconds=30.0,
        )

    async def _start_server(self, policy: AgentSHPolicyBundle) -> None:
        assert self.agentsh_bin is not None
        if self._server_process is not None:
            if self._server_process.returncode is None:
                return
            self._server_process = None
        env = {
            **os.environ,
            **self._probe_env_overrides,
            "AGENTSH_CONFIG": policy.config_path,
            "AGENTSH_SERVER": self.server_url,
        }
        self._server_process = await asyncio.create_subprocess_exec(
            self.agentsh_bin,
            "server",
            "--config",
            policy.config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        try:
            await self._wait_until_ready()
        except Exception:
            await self._stop_server()
            raise

    async def _wait_until_ready(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.ready_timeout_seconds
        base_url = self.server_url.rstrip("/")
        ready_urls = (
            f"{base_url}/ready",
            f"{base_url}/health",
            f"{base_url}/api/v1/health",
        )
        while asyncio.get_running_loop().time() < deadline:
            if (
                self._server_process is not None
                and self._server_process.returncode is not None
            ):
                raise RuntimeError(
                    "agentsh server exited before ready; stdout/stderr are "
                    "discarded to avoid server pipe-buffer deadlocks"
                )
            for ready_url in ready_urls:
                if await asyncio.to_thread(_http_ready, ready_url):
                    return
            await asyncio.sleep(0.2)
        raise RuntimeError(
            f"agentsh server did not become ready at {', '.join(ready_urls)} within "
            f"{self.ready_timeout_seconds:g}s"
        )

    async def _stop_server(self) -> None:
        process = self._server_process
        self._server_process = None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()

    async def _run(
        self, *args: str, config_path: str, timeout_seconds: float
    ) -> dict[str, Any]:
        assert self.agentsh_bin is not None
        argv = [self.agentsh_bin, *args]
        env = {
            **os.environ,
            **self._probe_env_overrides,
            "AGENTSH_CONFIG": config_path,
            "AGENTSH_SERVER": self.server_url,
        }
        return await asyncio.to_thread(_run_subprocess, argv, env, timeout_seconds)


def _reset_agentsh_audit_file(audit_path: str | None) -> None:
    if not audit_path:
        return
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def _prepare_agentsh_probe_fixtures(
    config: EnforcementConfig,
) -> tuple[dict[str, str], dict[str, Any]]:
    root = Path(str(config.metadata.get("fixture_root") or tempfile.mkdtemp()))
    shim_dir = root / "agentsh-shims"
    binary_paths = tuple(Path(path) for path in config.blocked_binary_paths)
    read_paths = tuple(Path(path) for path in config.blocked_read_paths)
    write_paths = tuple(Path(path) for path in config.blocked_write_paths)
    exec_paths = tuple(Path(path) for path in config.blocked_exec_paths)

    root.mkdir(parents=True, exist_ok=True)
    shim_dir.mkdir(parents=True, exist_ok=True)
    for command in (
        *config.blocked_commands,
        *BASE_DENIED_PRIVILEGE_COMMANDS,
    ):
        _write_executable(
            shim_dir / Path(command).name,
            "#!/bin/sh\n"
            "echo 'boundarybench AgentSH probe fixture unexpectedly ran' >&2\n"
            "exit 0\n",
        )
    for path in binary_paths:
        _write_executable(
            path,
            "#!/bin/sh\n"
            "echo 'boundarybench AgentSH binary-path fixture unexpectedly ran' >&2\n"
            "exit 0\n",
        )
    for path in read_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("boundarybench AgentSH read fixture\n", encoding="utf-8")
        path.chmod(0o644)
    for path in write_paths:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    for path in exec_paths:
        _write_executable(
            path,
            "#!/bin/sh\n"
            "echo 'boundarybench AgentSH exec-path fixture unexpectedly ran'\n"
            "exit 0\n",
        )

    path = f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    return (
        {"PATH": path},
        {
            "fixture_root": str(root),
            "shim_dir": str(shim_dir),
            "blocked_command_shims": [
                str(shim_dir / Path(command).name)
                for command in config.blocked_commands
            ],
            "privilege_command_shims": [
                str(shim_dir / Path(command).name)
                for command in BASE_DENIED_PRIVILEGE_COMMANDS
            ],
            "blocked_binary_paths": [str(path) for path in binary_paths],
            "blocked_read_paths": [str(path) for path in read_paths],
            "blocked_write_paths": [str(path) for path in write_paths],
            "blocked_exec_paths": [str(path) for path in exec_paths],
        },
    )


def _write_executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        process.kill()


def _run_subprocess(
    argv: list[str], env: dict[str, str], timeout_seconds: float
) -> dict[str, Any]:
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.communicate(timeout=5.0)
        raise RuntimeError(
            f"{' '.join(argv)} timed out after {timeout_seconds:g}s"
        ) from exc
    return {
        "argv": argv,
        "exit_code": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def _probe_specs_for_policy(policy: AgentSHPolicyBundle) -> tuple[AgentSHProbeSpec, ...]:
    probes: list[AgentSHProbeSpec] = []
    for rule in (*_baseline_probe_rules_for_policy(policy), *policy.rules):
        if not rule.agentsh_supported:
            continue
        command = _probe_command_for_rule(rule)
        if command is None:
            continue
        probes.append(
            AgentSHProbeSpec(
                rule=rule,
                command=command,
                expected_decision=_expected_decision_for_rule(rule),
                target_path=_probe_target_path(rule),
            )
        )
    return tuple(probes)


def _probe_command_for_rule(rule: AgentSHPolicyRule) -> tuple[str, ...] | None:
    if rule.hardening_type == "argument_aware_command_restriction":
        command = rule.selector.get("probe_command")
        if isinstance(command, list) and all(isinstance(item, str) for item in command):
            return tuple(command)
        return None
    if rule.hardening_type == "command_shim":
        command = _first_selector_value(rule, "commands")
        return (command, "--version") if command else None
    if rule.hardening_type == "binary_path":
        command = _first_selector_value(rule, "commands")
        return (command, "--version") if command else None
    if rule.hardening_type == "read_path":
        path = _first_selector_value(rule, "paths")
        return ("python3", "-c", f"open({path!r}).read()") if path else None
    if rule.hardening_type == "write_path":
        path = _first_selector_value(rule, "paths")
        if not path:
            return None
        target = f"{path.removesuffix('/**').rstrip('/')}/file"
        return ("sh", "-c", f"echo x > {shlex.quote(target)}")
    if rule.hardening_type == "exec_path":
        command = _first_selector_value(rule, "commands")
        return (command,) if command else None
    if rule.hardening_type == "network":
        return (
            "python3",
            "-c",
            "import socket; socket.create_connection(('1.1.1.1',80),timeout=3)",
        )
    if rule.hardening_type == "user":
        return ("sudo", "-n", "true")
    if rule.hardening_type == "audit":
        return ("/bin/bash", "-lc", "echo audit_marker")
    return None


def _expected_decision_for_rule(rule: AgentSHPolicyRule) -> str:
    if rule.action == "audit":
        return "allowed"
    if rule.action == "allow":
        return "allowed"
    return "denied"


def _baseline_probe_rules_for_policy(
    policy: AgentSHPolicyBundle,
) -> tuple[AgentSHPolicyRule, ...]:
    raw_rules = policy.metadata.get("base_policy_probe_rules")
    if not isinstance(raw_rules, list):
        return ()
    rules: list[AgentSHPolicyRule] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            continue
        selector = raw_rule.get("selector")
        if not isinstance(selector, dict):
            continue
        rule_id = raw_rule.get("rule_id")
        check_id = raw_rule.get("check_id")
        hardening_type = raw_rule.get("hardening_type")
        action = raw_rule.get("action")
        if not all(
            isinstance(value, str)
            for value in (rule_id, check_id, hardening_type, action)
        ):
            continue
        rules.append(
            AgentSHPolicyRule(
                rule_id=rule_id,
                check_id=check_id,
                hardening_type=hardening_type,
                action=action,
                selector=dict(selector),
                agentsh_supported=bool(raw_rule.get("agentsh_supported")),
                fallback=(
                    str(raw_rule["fallback"]) if raw_rule.get("fallback") else None
                ),
                reason=str(raw_rule["reason"]) if raw_rule.get("reason") else None,
            )
        )
    return tuple(rules)


def _probe_target_path(rule: AgentSHPolicyRule) -> str | None:
    if rule.hardening_type in {"binary_path", "exec_path"}:
        return _first_selector_value(rule, "commands")
    if rule.hardening_type in {"read_path", "write_path"}:
        return _first_selector_value(rule, "paths")
    return None


def _first_selector_value(rule: AgentSHPolicyRule, key: str) -> str | None:
    values = rule.selector.get(key)
    if not isinstance(values, list) or not values:
        return None
    return str(values[0])


def _block_message_for_probe(probe: AgentSHProbeSpec) -> str | None:
    block_message = probe.rule.selector.get("block_message")
    if isinstance(block_message, str) and block_message:
        return block_message
    return _block_message_for_hardening_type(probe.rule.hardening_type)


def _probe_exception_result(
    operation: str,
    session: AgentSHSession,
    command: tuple[str, ...],
    exc: Exception,
) -> dict[str, Any]:
    if operation == "wrap":
        argv = ["agentsh", "wrap", "--", *command]
    else:
        argv = ["agentsh", operation, session.session_id, "--", *command]
    return {
        "argv": argv,
        "exit_code": 1,
        "stdout": "",
        "stderr": str(exc),
    }


def _classify_probe_result(
    result: dict[str, Any], *, expected_block_message: str | None
) -> str:
    exit_code = int(result["exit_code"])
    if exit_code == 0:
        return "allowed"
    combined_output = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}"
    if _output_has_deny_marker(combined_output, expected_block_message):
        return "denied"
    return "error"


def _output_has_deny_marker(
    output: str, expected_block_message: str | None
) -> bool:
    normalized = output.lower()
    if expected_block_message and expected_block_message.lower() in normalized:
        return True
    return any(marker in normalized for marker in KNOWN_DENY_MARKERS)


def _parse_session_id(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"agentsh session create did not return JSON: {stdout}") from exc
    session_id = payload.get("id")
    if not session_id:
        raise RuntimeError(f"agentsh session create JSON had no id: {stdout}")
    return str(session_id)


def _http_ready(url: str) -> bool:
    connection: http.client.HTTPConnection | None = None
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not parsed.hostname or not _is_loopback_host(parsed.hostname):
            return False
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection_cls = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_cls(parsed.hostname, port=port, timeout=0.5)
        connection.request("GET", path, headers={"Accept": "*/*"})
        response = connection.getresponse()
        response.read()
        return 200 <= response.status < 300
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        if connection is not None:
            connection.close()


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _read_agentsh_audit_events(
    audit_path: str | None, *, session_id: str | None = None
) -> list[dict[str, Any]]:
    if not audit_path:
        return []
    path = Path(audit_path)
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            event_session_id = _audit_session_id(payload)
            if (
                session_id is not None
                and event_session_id is not None
                and event_session_id != session_id
            ):
                continue
            events.append(payload)
    return events


def _audit_session_id(event: dict[str, Any]) -> str | None:
    session_id = event.get("session_id")
    if session_id is not None:
        return str(session_id)
    fields = event.get("fields") or {}
    if not isinstance(fields, dict):
        return None
    field_session_id = fields.get("session_id")
    return str(field_session_id) if field_session_id is not None else None


def _audit_argv_contains(event: dict[str, Any], command: str) -> bool:
    fields = event.get("fields") or {}
    argv = fields.get("argv") or []
    if not isinstance(argv, list):
        return False
    return any(Path(str(value)).name == command for value in argv)


def _distinct_audit_events(events: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    seen: set[tuple[str, str]] = set()
    distinct: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        fields = event.get("fields") or {}
        event_id = event.get("id")
        if event_id is not None:
            key = ("id", str(event_id))
        else:
            process_id = fields.get("pid") or fields.get("process_id")
            key = (
                ("pid", str(process_id))
                if process_id is not None
                else ("anonymous", str(index))
            )
        if key in seen:
            continue
        seen.add(key)
        distinct.append(event)
    return tuple(distinct)


def _block_message_for_hardening_type(hardening_type: str) -> str | None:
    messages = {
        "binary_path": "Blocked by AgentSH policy: configured binary path is not allowed.",
        "command_shim": (
            "Blocked by AgentSH policy: this benchmark-denied command is not allowed."
        ),
        "exec_path": "Blocked by AgentSH policy: configured exec path is not allowed.",
        "network": "Blocked by AgentSH policy: configured network egress is not allowed.",
        "read_path": "Blocked by AgentSH policy: configured read path is not allowed.",
        "user": "Blocked by AgentSH policy: privilege escalation is not allowed.",
        "write_path": "Blocked by AgentSH policy: configured write path is not allowed.",
    }
    return messages.get(hardening_type)
