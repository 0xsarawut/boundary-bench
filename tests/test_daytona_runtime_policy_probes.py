from __future__ import annotations

from types import SimpleNamespace

from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaCommandResult,
    DaytonaPolicyHardening,
)
from boundarybench.daytona.hardening_config import DaytonaHardeningConfig
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    CANONICAL_INFRA_KEY_ENV_NAMES,
    build_daytona_config_from_axes,
)
from boundarybench.daytona.runtime_policy_probes import (
    RuntimePolicyProbe,
    RuntimeUnsupportedSurface,
    _observed_outcome,
    ensure_runtime_policy_probe_suite_passed,
    run_runtime_policy_probe_suite_in_sandbox,
    select_runtime_policy_probes,
)
from boundarybench.terminalbench.policies import POLICIES


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.event_output = ""

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        if command.startswith("cat /tmp/boundarybench-policy-events.jsonl"):
            return SimpleNamespace(exit_code=0, result=self.event_output)
        if command.startswith("rm -f /tmp/boundarybench-policy-events.jsonl"):
            self.event_output = ""
            return SimpleNamespace(exit_code=0, result="")
        return SimpleNamespace(exit_code=0, result="")


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()


def _config(**overrides) -> DaytonaHardeningConfig:
    values = {
        "name": "nist-linux-80053-high",
        "block_message": "Permission denied",
        "denied_exec_paths": ("/usr/bin/sudo",),
        "denied_command_names": ("sudo",),
        "denied_path_exact": ("/etc/shadow",),
        "denied_path_prefixes": ("/tmp/boundarybench-secret-link",),
        "tee_denied_patterns": ("/tmp/boundarybench-write-link*",),
        "child_network_command_names": ("python3",),
        "strip_env_vars": ("BOUNDARY_HARDENING_SECRET",),
        "egress_cidr_denylist": (),
        "egress_cidr_allowlist": (),
        "egress_cidr_default_action": "allow",
        "egress_cidr_command_names": (),
        "seccomp_block_syscalls": (),
    }
    values.update(overrides)
    return DaytonaHardeningConfig(**values)


def _hardening(config: DaytonaHardeningConfig) -> DaytonaPolicyHardening:
    return DaytonaPolicyHardening(
        asset_dir="/opt/h",
        policy_message_preload_so="/opt/h/policy.so",
        block_message_command="/opt/h/deny.sh",
        mount_real_path="/opt/h/mount.real",
        policy_bin_dir="/opt/h/bin",
        child_network_block_env="/opt/h/child_net",
        hardening_config=config,
    )


def test_runtime_probe_selection_covers_configured_daytona_surfaces():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(),
        agent_user="daytona",
        block_child_shell_network=True,
    )
    surfaces = {probe.surface for probe in probes}

    assert {
        "command_name_denial",
        "absolute_executable_path_denial",
        "exact_sensitive_path_denial",
        "prefix_sensitive_path_denial",
        "tee_write_denial",
        "environment_variable_stripping",
        "non_root_execution",
        "child_process_network_blocking",
        "workspace_allowed_control",
    } <= surfaces
    metadata = probes[0].to_metadata()
    assert metadata["probe_id"].startswith("nist-linux-80053-high.")
    assert metadata["expected_outcome"] == "blocked"
    assert metadata["execution_context"] == "daytona_sdk"
    assert metadata["claim_level"] == "runtime_helper"
    assert metadata["probe_type"] == "direct"
    assert metadata["adversarial_vector"] is None


def test_runtime_probe_selection_adds_adversarial_bypass_probes():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(
            denied_command_names=("sudo",),
            denied_exec_paths=("/usr/bin/sudo",),
            denied_path_exact=("/etc/shadow",),
            denied_path_prefixes=("/tmp/boundarybench-secret-link",),
            tee_denied_patterns=(),
            child_network_command_names=("bash", "python3"),
            strip_env_vars=("BOUNDARY_HARDENING_SECRET",),
            egress_domain_allowlist=("api.openrouter.ai",),
            egress_domain_default_action="deny",
            egress_cidr_allowlist=("127.0.0.0/8", "::1/128"),
            egress_cidr_default_action="deny",
            egress_cidr_denylist=("169.254.169.254/32",),
            egress_cidr_command_names=("python3",),
            seccomp_block_syscalls=("personality",),
        ),
        agent_user="daytona",
        block_child_shell_network=True,
    )

    adversarial = {
        probe.adversarial_vector: probe for probe in probes if probe.probe_type == "adversarial"
    }

    assert {
        "nested_shell_command_name",
        "env_path_command_name",
        "symlink_sensitive_path_read",
        "child_environment_inheritance",
        "nested_child_process_network",
        "cidr_alternate_port",
        "domain_direct_ip_alternate_port_bypass",
        "seccomp_child_process_inheritance",
    } <= set(adversarial)
    assert adversarial["nested_shell_command_name"].target == "sudo"
    assert "/usr/bin/env" in adversarial["env_path_command_name"].command
    assert adversarial["symlink_sensitive_path_read"].surface == (
        "prefix_sensitive_path_denial"
    )
    assert adversarial["child_environment_inheritance"].expected_outcome == "absent"
    assert "sh -c" in adversarial["nested_child_process_network"].command
    assert "443" in adversarial["cidr_alternate_port"].command
    assert "93.184.216.34" in adversarial[
        "domain_direct_ip_alternate_port_bypass"
    ].command
    assert adversarial["seccomp_child_process_inheritance"].target == "personality"


def test_runtime_probe_selection_includes_configured_seccomp_syscall():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(seccomp_block_syscalls=("personality",)),
        agent_user="daytona",
        block_child_shell_network=True,
    )

    seccomp_probe = next(
        probe for probe in probes if probe.surface == "seccomp_syscall_blocking"
    )
    assert seccomp_probe.target == "personality"
    assert seccomp_probe.expected_outcome == "blocked"
    assert seccomp_probe.enforcement_source == "seccomp"
    assert seccomp_probe.policy_evidence_required is False
    assert seccomp_probe.claim_level == "kernel_seccomp"
    assert "setarch" in seccomp_probe.command


def test_runtime_probe_selection_includes_each_configured_seccomp_syscall():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(
            seccomp_block_syscalls=(
                "personality",
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
            )
        ),
        agent_user="daytona",
        block_child_shell_network=True,
    )

    seccomp_probes = [
        probe
        for probe in probes
        if probe.surface == "seccomp_syscall_blocking" and probe.probe_type == "direct"
    ]

    assert [probe.target for probe in seccomp_probes] == [
        "personality",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
    ]
    assert all(probe.policy_evidence_required is False for probe in seccomp_probes)
    assert all(probe.claim_level == "kernel_seccomp" for probe in seccomp_probes)


def test_runtime_probe_report_metadata_includes_policy_alias():
    report = run_runtime_policy_probe_suite_in_sandbox(
        _FakeSandbox(),
        daytona_policy_hardening=_hardening(_config()),
        policy_id="nist-linux-80053-low",
        policy_name="nist-linux-80053-low",
        overlays=("blocked-surfaces",),
        agent_user="daytona",
        workspace="/workspace",
    )

    metadata = report.to_metadata()

    assert metadata["policy"] == "nist-linux-80053-low"
    assert metadata["policy_id"] == "nist-linux-80053-low"
    assert metadata["schema_version"] == 3


def test_runtime_probe_report_can_include_mac_capability_probe_metadata():
    mac_probe = {
        "engine": "apparmor",
        "status": "unsupported",
        "supported": False,
        "unsupported_reason": "apparmor_parser unavailable",
    }

    report = run_runtime_policy_probe_suite_in_sandbox(
        _FakeSandbox(),
        daytona_policy_hardening=_hardening(
            _config(
                denied_exec_paths=(),
                denied_command_names=(),
                denied_path_exact=(),
                denied_path_prefixes=(),
                tee_denied_patterns=(),
                child_network_command_names=(),
                strip_env_vars=(),
            )
        ),
        policy_id="nist-linux-80053-low",
        policy_name="nist-linux-80053-low",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/workspace",
        mac_capability_probe=mac_probe,
    )

    metadata = report.to_metadata()

    assert report.passed is True
    assert metadata["mac_capability_probe"] == mac_probe


def test_runtime_probe_suite_exercises_full_mac_enforcement(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )
    calls = []

    def fake_run(sandbox_arg, *, command, full_mac_enforcement=False, **kwargs):
        calls.append(
            {
                "command": command,
                "full_mac_enforcement": full_mac_enforcement,
                **kwargs,
            }
        )
        if "mac-read-status" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_enforce","surface":"full_mac_enforcement",'
                '"engine":"landlock","abi":4}\n'
            )
            return DaytonaCommandResult(
                exit_code=0,
                stdout=(
                    "mac-read-status=13\n"
                    "mac-child-status=13\n"
                    "mac-exec-status=13\n"
                    "mac-network-status=13\n"
                    "mac-agentsh-loopback-status=0\n"
                    "mac-workspace-write=ok\n"
                ),
            )
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("full-mac-enforcement",),
        agent_user="daytona",
        workspace="/tmp/probes",
        full_mac_enforcement=True,
    )

    mac_result = next(r for r in report.results if r.surface == "full_mac_enforcement")
    assert report.passed is True
    assert mac_result.status == "pass"
    assert mac_result.actual_outcome == "allowed"
    assert mac_result.evidence["policy_event_seen"] is True
    assert mac_result.policy_overlay == "full-mac-enforcement"
    assert mac_result.enforcement_source == "landlock_lsm"
    assert any(
        call["full_mac_enforcement"]
        and "mac-read-status" in call["command"]
        and "127.0.0.1" in call["command"]
        and "18080" in call["command"]
        for call in calls
    )


def test_runtime_probe_suite_requires_full_mac_enforcement_event(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_command_names=(),
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    def fake_run(_sandbox_arg, *, command, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "mac-read-status" in command:
            return DaytonaCommandResult(
                exit_code=0,
                stdout=(
                    "Permission denied\n"
                    "mac-read-status=13\n"
                    "mac-child-status=13\n"
                    "mac-exec-status=13\n"
                    "mac-network-status=13\n"
                    "mac-agentsh-loopback-status=0\n"
                    "mac-workspace-write=ok\n"
                ),
            )
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("full-mac-enforcement",),
        agent_user="daytona",
        workspace="/tmp/probes",
        full_mac_enforcement=True,
    )

    mac_result = next(r for r in report.results if r.surface == "full_mac_enforcement")
    assert report.passed is False
    assert mac_result.status == "fail"
    assert mac_result.actual_outcome == "error"
    assert mac_result.evidence["policy_event_seen"] is False


def test_runtime_probe_report_results_include_policy_overlay(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        child_network_command_names=("python3",),
        strip_env_vars=("BOUNDARY_HARDENING_SECRET",),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "id -u" in command:
            return DaytonaCommandResult(exit_code=0, stdout='{"uid":1000}')
        if "BOUNDARY_HARDENING_SECRET" in command:
            return DaytonaCommandResult(exit_code=0, stdout="")
        if "python3 -c" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network","target":"connect"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "adversarial-symlink" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"path",'
                '"target":"/tmp/boundarybench-secret-link-target"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "tee " in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"tee_write",'
                '"target":"/tmp/boundarybench-write-linkboundarybench-tee-probe"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "/tmp/boundarybench-secret-link-target" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"path",'
                '"target":"/tmp/boundarybench-secret-link-target"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "/etc/shadow" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"path","target":"/etc/shadow"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "sudo" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"command","command":"sudo"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-low",
        overlays=("nonroot-agent", "blocked-surfaces", "env-strip", "child-network"),
        agent_user="daytona",
        workspace="/tmp/probes",
        block_child_shell_network=True,
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="full_mac_enforcement",
                reason="Daytona hardening v1 does not expose SELinux/AppArmor policy.",
            ),
        ),
    )

    by_surface = {
        result["surface"]: result["policy_overlay"]
        for result in report.to_metadata()["results"]
    }

    assert report.passed is True
    assert by_surface["non_root_execution"] == "nonroot-agent"
    assert by_surface["environment_variable_stripping"] == "env-strip"
    assert by_surface["command_name_denial"] == "blocked-surfaces"
    assert by_surface["absolute_executable_path_denial"] == "blocked-surfaces"
    assert by_surface["exact_sensitive_path_denial"] == "blocked-surfaces"
    assert by_surface["prefix_sensitive_path_denial"] == "blocked-surfaces"
    assert by_surface["tee_write_denial"] == "blocked-surfaces"
    assert by_surface["child_process_network_blocking"] == "child-network"
    assert by_surface["workspace_allowed_control"] == "runtime-control-smoke-test"
    assert by_surface["full_mac_enforcement"] == "unsupported-gap"


def test_seccomp_probe_passes_on_eperm_without_policy_event(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        seccomp_block_syscalls=("personality",),
    )

    def fake_run(_sandbox_arg, *, command, **_kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "setarch" in command:
            return DaytonaCommandResult(exit_code=1, stdout="Operation not permitted")
        return DaytonaCommandResult(exit_code=0, stdout="ok")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("seccomp-syscall",),
        agent_user="daytona",
        workspace="/app",
    )

    seccomp_result = next(
        result for result in report.results if result.surface == "seccomp_syscall_blocking"
    )
    assert report.passed is True
    assert seccomp_result.actual_outcome == "blocked"
    assert seccomp_result.evidence["policy_event_seen"] is False


def test_seccomp_probe_does_not_treat_non_eperm_errno_as_denial(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        seccomp_block_syscalls=("ptrace",),
    )

    def fake_run(_sandbox_arg, *, command, **_kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "ptrace" in command:
            return DaytonaCommandResult(
                exit_code=1, stdout="ptrace errno=11: Resource temporarily unavailable"
            )
        return DaytonaCommandResult(exit_code=0, stdout="ok")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-medium",
        overlays=("seccomp-syscall",),
        agent_user="daytona",
        workspace="/app",
    )

    seccomp_result = next(
        result for result in report.results if result.surface == "seccomp_syscall_blocking"
    )
    assert report.passed is False
    assert seccomp_result.status == "fail"
    assert seccomp_result.actual_outcome == "error"


def test_runtime_probe_selection_adds_cidr_probe_when_configured():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-low",
        hardening_config=_config(
            denied_exec_paths=(),
            denied_command_names=(),
            denied_path_exact=(),
            denied_path_prefixes=(),
            tee_denied_patterns=(),
            child_network_command_names=(),
            strip_env_vars=(),
            egress_cidr_denylist=("169.254.169.254/32", "10.0.0.0/8"),
            egress_cidr_command_names=("python3",),
        ),
        agent_user="daytona",
    )

    cidr_probe = next(probe for probe in probes if probe.surface == "cidr_egress_policy")
    assert cidr_probe.target == "169.254.169.254/32"
    assert "169.254.169.254" in cidr_probe.command
    assert cidr_probe.enforcement_source == "ld_preload_cidr_socket_filter"


def test_runtime_probe_selection_adds_domain_proxy_and_direct_bypass_probes():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-low",
        hardening_config=_config(
            denied_exec_paths=(),
            denied_command_names=(),
            denied_path_exact=(),
            denied_path_prefixes=(),
            tee_denied_patterns=(),
            child_network_command_names=(),
            strip_env_vars=(),
            egress_domain_allowlist=("api.openrouter.ai",),
            egress_domain_default_action="deny",
            egress_cidr_allowlist=("127.0.0.0/8", "::1/128"),
            egress_cidr_default_action="deny",
            egress_cidr_command_names=("python3",),
        ),
        agent_user="daytona",
    )

    domain_probes = [probe for probe in probes if probe.surface == "domain_egress_policy"]
    assert {probe.enforcement_source for probe in domain_probes} == {
        "domain_egress_proxy",
        "ld_preload_cidr_default_deny",
    }
    assert any(
        probe.target == "blocked.boundarybench.invalid"
        and "blocked.boundarybench.invalid" in probe.command
        for probe in domain_probes
    )
    assert any(
        probe.target == "93.184.216.34/32" and "93.184.216.34" in probe.command
        for probe in domain_probes
    )


def test_runtime_probe_suite_reports_cidr_policy_evidence(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_cidr_denylist=("169.254.169.254/32",),
        egress_cidr_command_names=("python3",),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"network_cidr","target":"169.254.169.254"}\n'
        )
        return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-low",
        overlays=("cidr-egress",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    cidr_result = next(r for r in report.results if r.surface == "cidr_egress_policy")
    assert report.passed is True
    assert cidr_result.status == "pass"
    assert cidr_result.actual_outcome == "blocked"
    assert cidr_result.policy_overlay == "cidr-egress"
    assert cidr_result.evidence["policy_event_seen"] is True
    assert cidr_result.evidence["policy_events"][0]["surface"] == "network_cidr"


def test_child_network_probe_accepts_cidr_policy_evidence(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=("bash",),
        strip_env_vars=(),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"network_cidr",'
            '"target":"93.184.216.34"}\n'
        )
        return DaytonaCommandResult(
            exit_code=1,
            stdout="Permission denied\nbash: connect: Permission denied\n",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-low",
        overlays=("child-network",),
        agent_user="root",
        workspace="/tmp/probes",
        block_child_shell_network=True,
    )

    child_result = next(
        r for r in report.results if r.surface == "child_process_network_blocking"
    )
    assert report.passed is True
    assert child_result.status == "pass"
    assert child_result.actual_outcome == "blocked"
    assert child_result.evidence["policy_event_seen"] is True
    assert child_result.evidence["policy_events"][0]["surface"] == "network_cidr"


def test_runtime_probe_suite_reports_domain_policy_evidence(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_domain_allowlist=("api.openrouter.ai",),
        egress_domain_default_action="deny",
        egress_cidr_allowlist=("127.0.0.0/8", "::1/128"),
        egress_cidr_default_action="deny",
        egress_cidr_command_names=("python3",),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "blocked.boundarybench.invalid" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_domain",'
                '"target":"blocked.boundarybench.invalid"}\n'
            )
            return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")
        if "93.184.216.34" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_cidr",'
                '"target":"93.184.216.34"}\n'
            )
            return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-low",
        overlays=("domain-egress",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    domain_results = [r for r in report.results if r.surface == "domain_egress_policy"]
    assert report.passed is True
    assert len(domain_results) == 3
    assert {r.evidence["policy_events"][0]["surface"] for r in domain_results} == {
        "network_domain",
        "network_cidr",
    }


def test_adversarial_domain_direct_ip_bypass_fails_closed_when_allowed(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_domain_allowlist=("api.openrouter.ai",),
        egress_domain_default_action="deny",
        egress_cidr_allowlist=("127.0.0.0/8", "::1/128"),
        egress_cidr_default_action="deny",
        egress_cidr_command_names=("python3",),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "blocked.boundarybench.invalid" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_domain",'
                '"target":"blocked.boundarybench.invalid"}\n'
            )
            return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")
        if "93.184.216.34" in command and ", 80" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_cidr",'
                '"target":"93.184.216.34"}\n'
            )
            return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")
        if "93.184.216.34" in command and ", 443" in command:
            return DaytonaCommandResult(exit_code=0, stdout="connected")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("domain-egress",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    alt_bypass = next(
        result
        for result in report.results
        if result.adversarial_vector == "domain_direct_ip_alternate_port_bypass"
    )
    assert report.passed is False
    assert alt_bypass.probe_type == "adversarial"
    assert alt_bypass.status == "fail"
    assert alt_bypass.classification == "policy_miss"


def test_runtime_probe_selection_includes_coarse_non_loopback_block():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(
            denied_exec_paths=(),
            denied_command_names=(),
            denied_path_exact=(),
            denied_path_prefixes=(),
            tee_denied_patterns=(),
            child_network_command_names=(),
            strip_env_vars=(),
        ),
        agent_user="daytona",
        block_network=True,
    )

    coarse_probe = next(
        probe
        for probe in probes
        if probe.surface == "coarse_non_loopback_network_block"
    )
    loopback_probe = next(
        probe
        for probe in probes
        if probe.surface == "coarse_non_loopback_network_loopback_control"
    )
    assert coarse_probe.target == "1.1.1.1:80"
    assert "1.1.1.1" in coarse_probe.command
    assert coarse_probe.expected_outcome == "blocked"
    assert coarse_probe.configured_by == "block_network"
    assert coarse_probe.enforcement_source == "ld_preload_network_socket_filter"
    assert loopback_probe.target == "127.0.0.1:443"
    assert loopback_probe.expected_outcome == "allowed"
    assert "127.0.0.1" in loopback_probe.command
    assert "connect_ex" in loopback_probe.command
    assert "ECONNREFUSED" in loopback_probe.command
    assert loopback_probe.policy_evidence_required is False


def test_runtime_probe_suite_reports_coarse_network_policy_evidence(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    calls = []

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        calls.append({"command": command, **kwargs})
        if "coarse-loopback-control-ok" in command:
            return DaytonaCommandResult(
                exit_code=0, stdout="coarse-loopback-control-ok\n"
            )
        if "1.1.1.1" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network","target":"connect"}\n'
            )
            return DaytonaCommandResult(
                exit_code=126, stdout="", stderr="Permission denied"
            )
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("coarse-network-block",),
        agent_user="daytona",
        workspace="/tmp/probes",
        block_network=True,
        isolate_network=False,
    )

    coarse_result = next(
        r for r in report.results if r.surface == "coarse_non_loopback_network_block"
    )
    loopback_result = next(
        r
        for r in report.results
        if r.surface == "coarse_non_loopback_network_loopback_control"
    )
    assert report.passed is True
    assert coarse_result.status == "pass"
    assert coarse_result.actual_outcome == "blocked"
    assert coarse_result.evidence["policy_event_seen"] is True
    assert coarse_result.evidence["policy_events"][0]["surface"] == "network"
    assert coarse_result.policy_overlay == "coarse-network-block"
    assert loopback_result.status == "pass"
    assert loopback_result.actual_outcome == "allowed"
    assert loopback_result.policy_overlay == "coarse-network-block"
    assert any(
        call["block_network"] is True
        and call["isolate_network"] is False
        and "1.1.1.1" in call["command"]
        for call in calls
    )


def test_coarse_network_probe_accepts_cidr_event_for_same_target(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_cidr_default_action="deny",
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "coarse-loopback-control-ok" in command:
            return DaytonaCommandResult(
                exit_code=0, stdout="coarse-loopback-control-ok\n"
            )
        if "1.1.1.1" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_cidr",'
                '"target":"1.1.1.1"}\n'
            )
            return DaytonaCommandResult(
                exit_code=1, stdout="Permission denied", stderr=""
            )
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("coarse-network-block", "domain-egress"),
        agent_user="daytona",
        workspace="/tmp/probes",
        block_network=True,
        isolate_network=False,
    )

    coarse_result = next(
        r for r in report.results if r.surface == "coarse_non_loopback_network_block"
    )
    assert report.passed is True
    assert coarse_result.status == "pass"
    assert coarse_result.evidence["policy_event_seen"] is True
    assert coarse_result.evidence["policy_events"][0]["surface"] == "network_cidr"


def test_policy_event_log_is_prepared_for_cross_component_writers(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_domain_allowlist=("api.openrouter.ai",),
        egress_domain_default_action="deny",
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "blocked.boundarybench.invalid" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"network_domain",'
                '"target":"blocked.boundarybench.invalid"}\n'
            )
            return DaytonaCommandResult(exit_code=1, stdout="", stderr="")
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("domain-egress",),
        agent_user="daytona",
        workspace="/tmp/probes",
    )

    clear_commands = [
        command
        for command in sandbox.process.commands
        if "/tmp/boundarybench-policy-events.jsonl" in command
        and "chmod" in command
    ]
    assert clear_commands


def test_domain_egress_proxy_probe_accepts_block_without_policy_event(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
        egress_domain_allowlist=("api.openrouter.ai",),
        egress_domain_default_action="deny",
        egress_cidr_default_action="allow",
    )

    def fake_run(_sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "blocked.boundarybench.invalid" in command:
            return DaytonaCommandResult(
                exit_code=1,
                stdout="PermissionError: [Errno 13] Permission denied\n",
                stderr="",
            )
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-low",
        overlays=("domain-egress",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    domain_result = next(
        r for r in report.results if r.surface == "domain_egress_policy"
    )
    assert report.passed is True
    assert domain_result.status == "pass"
    assert domain_result.actual_outcome == "blocked"
    assert domain_result.evidence["policy_event_seen"] is False


def test_runtime_probe_selection_can_cover_every_configured_blockage():
    config = _config(
        denied_command_names=("sudo", "curl"),
        denied_exec_paths=("/usr/bin/sudo", "/usr/bin/curl"),
        denied_path_exact=("/etc/shadow", "/etc/sudoers"),
        denied_path_prefixes=("/tmp/inspect-a", "/tmp/inspect-b/"),
        tee_denied_patterns=("/tmp/inspect-a*", "/tmp/inspect-b*"),
        child_network_command_names=("bash", "sh", "dash", "python3", "curl"),
        strip_env_vars=("SECRET_ONE", "SECRET_TWO"),
    )

    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-low",
        hardening_config=config,
        agent_user="daytona",
        block_child_shell_network=True,
        probe_scope="all",
    )

    direct_targets = {
        configured_by: {
            probe.target
            for probe in probes
            if probe.configured_by == configured_by
            and probe.unsupported is None
            and probe.probe_type == "direct"
        }
        for configured_by in (
            "denied_command_names",
            "denied_exec_paths",
            "denied_path_exact",
            "denied_path_prefixes",
            "tee_denied_patterns",
            "strip_env_vars",
            "child_network_command_names",
        )
    }

    assert direct_targets["denied_command_names"] == {"sudo", "curl"}
    assert direct_targets["denied_exec_paths"] == {"/usr/bin/sudo", "/usr/bin/curl"}
    assert direct_targets["denied_path_exact"] == {"/etc/shadow", "/etc/sudoers"}
    assert len(direct_targets["denied_path_prefixes"]) == 2
    assert len(direct_targets["tee_denied_patterns"]) == 2
    assert direct_targets["strip_env_vars"] == {"SECRET_ONE", "SECRET_TWO"}
    assert direct_targets["child_network_command_names"] == {
        "bash",
        "sh",
        "dash",
        "python3",
    }
    child_network_commands = {
        probe.target: probe.command
        for probe in probes
        if probe.configured_by == "child_network_command_names"
        and probe.unsupported is None
    }
    assert "/dev/tcp" in child_network_commands["bash"]
    for shell in ("sh", "dash"):
        assert "/dev/tcp" not in child_network_commands[shell]
        assert "python3 -c" in child_network_commands[shell]
        assert "socket.create_connection" in child_network_commands[shell]
    for probe in probes:
        if probe.target in {"sh", "dash"}:
            assert "command -v python3" in (probe.setup_command or "")
    shadowed = {
        probe.target: probe
        for probe in probes
        if probe.configured_by == "child_network_command_names"
        and probe.unsupported is not None
    }
    assert shadowed["curl"].unsupported.reason == (
        "child-process network probe is shadowed by command-name denial"
    )


def test_nist_terminalbench_policies_use_exhaustive_runtime_probes():
    for policy_name in (
        "high-nist",
        "high-nist",
        "moderate-nist",
        "low-nist",
    ):
        assert POLICIES[policy_name].runtime_probe_scope == "all"


def test_runtime_probe_selection_covers_read_only_root_carveouts():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(
            read_only_root=True,
            writable_path_prefixes=("/home/daytona/", "/tmp/"),
        ),
        agent_user="daytona",
        block_child_shell_network=True,
    )
    by_surface = {probe.surface: probe for probe in probes}

    assert "read_only_write_denial" in by_surface
    assert by_surface["read_only_write_denial"].target == (
        "/etc/boundarybench-read-only-probe"
    )
    assert by_surface["read_only_write_denial"].policy_evidence_required is True
    assert "read_only_allowed_write" in by_surface
    assert by_surface["read_only_allowed_write"].expected_outcome == "allowed"
    assert by_surface["read_only_allowed_write"].policy_evidence_required is False
    assert "read_only_allowed_app_write" in by_surface
    assert "read_only_allowed_home_write" in by_surface
    assert "read_only_allowed_claude_state_write" in by_surface
    assert "read_only_allowed_tmp_claude_write" in by_surface
    assert 'rm -rf "$(dirname "$tmp")"' not in by_surface[
        "read_only_allowed_app_write"
    ].command
    assert "trap 'rm -f \"$tmp\"' EXIT" in by_surface[
        "read_only_allowed_home_write"
    ].command


def test_runtime_probe_suite_reports_pass_with_compact_policy_evidence(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )
    calls = []

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        calls.append(kwargs)
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"command","command":"sudo"}\n'
        )
        return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    assert report.passed is True
    assert "chmod 1777 /tmp/probes" in sandbox.process.commands[0]
    command_result = next(r for r in report.results if r.surface == "command_name_denial")
    assert command_result.status == "pass"
    assert command_result.actual_outcome == "blocked"
    assert command_result.evidence["policy_event_seen"] is True
    assert report.to_metadata()["results"][0]["compact_evidence"]["exit_code"] in {
        0,
        126,
    }
    assert calls
    assert all(call["short_command"] is True for call in calls)


def test_runtime_probe_suite_fails_closed_when_policy_event_is_missing(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    def fake_run(_sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/app",
    )

    failed = next(r for r in report.results if r.surface == "command_name_denial")
    assert report.passed is False
    assert failed.status == "fail"
    assert "no runtime policy event" in failed.message


def test_runtime_probe_suite_ignores_unmatched_policy_events(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"command","command":"curl"}\n'
        )
        return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    failed = next(r for r in report.results if r.surface == "command_name_denial")
    assert failed.status == "fail"
    assert failed.evidence["policy_event_seen"] is False
    assert failed.evidence["unmatched_policy_events"][0]["command"] == "curl"


def test_symlink_adversarial_probe_accepts_symlink_path_policy_event(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=("/etc/sudoers.d/",),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )
    protected_target = "/etc/sudoers.d/.boundarybench-prefix-probe"
    link_target = (
        "/tmp/boundarybench-runtime-policy-probes/"
        "adversarial-symlink-etc_sudoers_d_boundarybench_prefix_probe"
    )

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        if "adversarial-symlink" in command:
            sandbox_arg.process.event_output = (
                '{"event_type":"policy_block","surface":"path",'
                f'"target":"{link_target}"}}\n'
            )
            return DaytonaCommandResult(exit_code=1, stdout="", stderr="")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"path",'
            f'"target":"{protected_target}"}}\n'
        )
        return DaytonaCommandResult(exit_code=1, stdout="", stderr="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-medium",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    symlink_result = next(
        r for r in report.results if r.adversarial_vector == "symlink_sensitive_path_read"
    )
    assert report.passed is True
    assert symlink_result.status == "pass"
    assert symlink_result.actual_outcome == "blocked"
    assert symlink_result.evidence["policy_event_seen"] is True
    assert symlink_result.evidence["policy_events"][0]["target"] == link_target


def test_missing_configured_probe_target_is_reported_not_applicable(monkeypatch):
    class MissingPathProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            self.commands.append(command)
            if command.startswith("cat /tmp/boundarybench-policy-events.jsonl"):
                return SimpleNamespace(exit_code=0, result=self.event_output)
            if command.startswith("rm -f /tmp/boundarybench-policy-events.jsonl"):
                self.event_output = ""
                return SimpleNamespace(exit_code=0, result="")
            if command == "test -x /missing/tool":
                return SimpleNamespace(exit_code=1, result="missing")
            return SimpleNamespace(exit_code=0, result="")

    sandbox = _FakeSandbox()
    sandbox.process = MissingPathProcess()
    config = _config(
        denied_exec_paths=("/missing/tool",),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    not_applicable = next(
        r for r in report.results if r.surface == "absolute_executable_path_denial"
    )
    assert report.passed is True
    assert not_applicable.status == "not_applicable"
    assert not_applicable.actual_outcome == "not_applicable"


def test_probe_fixture_setup_failure_fails_closed(monkeypatch):
    class FailingFixtureProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            self.commands.append(command)
            if command.startswith("cat /tmp/boundarybench-policy-events.jsonl"):
                return SimpleNamespace(exit_code=0, result=self.event_output)
            if command.startswith("rm -f /tmp/boundarybench-policy-events.jsonl"):
                self.event_output = ""
                return SimpleNamespace(exit_code=0, result="")
            if "boundarybench-secret-link-target" in command:
                return SimpleNamespace(exit_code=1, result="setup failed")
            return SimpleNamespace(exit_code=0, result="")

    sandbox = _FakeSandbox()
    sandbox.process = FailingFixtureProcess()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=("/tmp/boundarybench-secret-link",),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/tmp/probes",
    )

    failed = next(r for r in report.results if r.surface == "prefix_sensitive_path_denial")
    assert report.passed is False
    assert failed.status == "fail"
    assert failed.classification == "setup_failure"


def test_runtime_probe_suite_keeps_configured_unsupported_surfaces_visible(
    monkeypatch,
):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high-derived",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/app",
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="full_mac_enforcement",
                reason="Daytona hardening v1 does not expose SELinux/AppArmor policy.",
                missing_surface="MAC runtime policy engine",
                verification_hint="Must be preserved as unsupported.",
            ),
        ),
    )

    unsupported = next(r for r in report.results if r.status == "unsupported")
    assert report.unsupported_count == 1
    assert report.passed is True
    assert unsupported.surface == "full_mac_enforcement"
    assert unsupported.probe_type == "unsupported"
    assert unsupported.evidence["unsupported"]["missing_surface"] == (
        "MAC runtime policy engine"
    )


def test_kernel_sysctl_service_state_surface_adds_baseline_audit_probes():
    probes = select_runtime_policy_probes(
        policy_id="nist-linux-80053-high",
        hardening_config=_config(
            denied_exec_paths=(),
            denied_command_names=(),
            denied_path_exact=(),
            denied_path_prefixes=(),
            tee_denied_patterns=(),
            child_network_command_names=(),
            strip_env_vars=(),
        ),
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="kernel_sysctl_service_state",
                reason="Daytona v1 command denials do not prove starting posture.",
                missing_surface="kernel/sysctl/service-state posture audit",
            ),
        ),
    )

    audit_probes = [
        probe
        for probe in probes
        if probe.surface == "kernel_sysctl_service_state"
        and probe.runner == "daytona_controller_exec"
    ]

    assert {probe.target for probe in audit_probes} == {
        "sysctl:kernel.randomize_va_space",
        "service_manager:systemd",
        "daemon_listener:ssh",
        "kernel_module_tooling:modprobe",
    }
    assert all(probe.claim_level == "baseline_posture_audit" for probe in audit_probes)
    assert all(probe.policy_evidence_required is False for probe in audit_probes)
    assert any(probe.runner == "unsupported" for probe in probes)


def test_kernel_sysctl_service_state_audit_reports_pass_and_not_applicable(
    monkeypatch,
):
    class PostureAuditProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            self.commands.append(command)
            if command.startswith("cat /tmp/boundarybench-policy-events.jsonl"):
                return SimpleNamespace(exit_code=0, result=self.event_output)
            if command.startswith("rm -f /tmp/boundarybench-policy-events.jsonl"):
                self.event_output = ""
                return SimpleNamespace(exit_code=0, result="")
            if "kernel.randomize_va_space" in command:
                return SimpleNamespace(
                    exit_code=0,
                    result='{"observed":"2","expected":"1_or_2"}',
                )
            if "service_manager:systemd" in command:
                return SimpleNamespace(
                    exit_code=2,
                    result='{"reason":"systemd is not exposed in this container"}',
                )
            if "daemon_listener:ssh" in command:
                return SimpleNamespace(exit_code=0, result='{"listening":false}')
            if "kernel_module_tooling:modprobe" in command:
                return SimpleNamespace(
                    exit_code=2,
                    result='{"reason":"module tooling is not present"}',
                )
            return SimpleNamespace(exit_code=0, result="")

    sandbox = _FakeSandbox()
    sandbox.process = PostureAuditProcess()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/app",
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="kernel_sysctl_service_state",
                reason="Daytona v1 command denials do not prove starting posture.",
                missing_surface="kernel/sysctl/service-state posture audit",
            ),
        ),
    )

    sysctl = next(
        r
        for r in report.results
        if r.probe_id.endswith(".baseline.sysctl.kernel_randomize_va_space")
    )
    service = next(
        r
        for r in report.results
        if r.probe_id.endswith(".baseline.service_manager.systemd")
    )
    ssh = next(
        r for r in report.results if r.probe_id.endswith(".baseline.daemon.ssh")
    )

    assert report.passed is True
    assert sysctl.status == "pass"
    assert sysctl.actual_outcome == "compliant"
    assert sysctl.evidence["policy_event_seen"] is False
    assert service.status == "not_applicable"
    assert service.actual_outcome == "not_applicable"
    assert ssh.status == "pass"
    assert ssh.actual_outcome == "absent"
    assert report.unsupported_count == 1


def test_kernel_sysctl_service_state_audit_fails_closed_when_meaningful_check_fails(
    monkeypatch,
):
    class FailingPostureAuditProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            self.commands.append(command)
            if command.startswith("cat /tmp/boundarybench-policy-events.jsonl"):
                return SimpleNamespace(exit_code=0, result=self.event_output)
            if command.startswith("rm -f /tmp/boundarybench-policy-events.jsonl"):
                self.event_output = ""
                return SimpleNamespace(exit_code=0, result="")
            if "kernel.randomize_va_space" in command:
                return SimpleNamespace(
                    exit_code=1,
                    result='{"observed":"0","expected":"1_or_2"}',
                )
            if "service_manager:systemd" in command:
                return SimpleNamespace(exit_code=2, result="not applicable")
            if "daemon_listener:ssh" in command:
                return SimpleNamespace(exit_code=0, result='{"listening":false}')
            if "kernel_module_tooling:modprobe" in command:
                return SimpleNamespace(exit_code=2, result="not applicable")
            return SimpleNamespace(exit_code=0, result="")

    sandbox = _FakeSandbox()
    sandbox.process = FailingPostureAuditProcess()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/app",
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="kernel_sysctl_service_state",
                reason="Daytona v1 command denials do not prove starting posture.",
                missing_surface="kernel/sysctl/service-state posture audit",
            ),
        ),
    )

    sysctl = next(
        r
        for r in report.results
        if r.probe_id.endswith(".baseline.sysctl.kernel_randomize_va_space")
    )
    assert report.passed is False
    assert report.required_failed_count == 1
    assert sysctl.status == "fail"
    assert sysctl.actual_outcome == "non_compliant"
    assert sysctl.classification == "baseline_posture_mismatch"


def test_required_unsupported_surface_fails_the_suite(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        lambda *_args, **_kwargs: DaytonaCommandResult(exit_code=0, stdout="ok"),
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high-derived",
        overlays=("blocked-surfaces",),
        agent_user="root",
        workspace="/app",
        unsupported_surfaces=(
            RuntimeUnsupportedSurface(
                surface="seccomp_syscall_policy",
                reason="No seccomp compiler/runtime target exists.",
                required=True,
            ),
        ),
    )

    assert report.passed is False
    assert report.required_failed_count == 1
    try:
        ensure_runtime_policy_probe_suite_passed(report)
    except Exception as exc:
        assert "policy hardening runtime probe suite failed" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("required unsupported surface should fail closed")


def test_env_probe_injects_secret_through_env_channel(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=("BOUNDARY_HARDENING_SECRET",),
    )
    captured = {}

    def fake_run(_sandbox_arg, *, env=None, **kwargs):
        if env:
            captured["env"] = env
        return DaytonaCommandResult(exit_code=0, stdout="")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("env-strip",),
        agent_user="root",
        workspace="/app",
    )

    assert report.passed is True
    assert captured["env"] == {
        "BOUNDARY_HARDENING_SECRET": "boundarybench-runtime-probe-secret"
    }
    env_result = next(
        r for r in report.results if r.surface == "environment_variable_stripping"
    )
    assert env_result.actual_outcome == "absent"
    assert env_result.evidence["env_vars_injected"] == [
        "BOUNDARY_HARDENING_SECRET"
    ]


def test_probe_commands_are_wrapped_for_child_network_env_prefix(monkeypatch):
    sandbox = _FakeSandbox()
    config = _config(
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )
    commands: list[str] = []

    def fake_run(_sandbox_arg, *, command, **kwargs):
        commands.append(command)
        return DaytonaCommandResult(exit_code=0, stdout='{"uid":1000}')

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(config),
        policy_id="nist-linux-80053-high",
        overlays=("nonroot-agent",),
        agent_user="daytona",
        workspace="/tmp/probes",
        block_child_shell_network=True,
    )

    assert report.passed is True
    assert commands
    assert all(command.startswith("/bin/bash.real -c ") for command in commands)


def _native_config(**overrides) -> DaytonaHardeningConfig:
    """A native-enforcement config: native fields on, legacy denylists empty."""
    values = {
        "name": "high-nist",
        "block_message": None,
        "denied_exec_paths": (),
        "denied_command_names": (),
        "denied_path_exact": (),
        "denied_path_prefixes": (),
        "tee_denied_patterns": (),
        "child_network_command_names": (),
        "strip_env_vars": (),
        "egress_cidr_denylist": (),
        "egress_cidr_command_names": (),
        "native_egress_reject": True,
        "secret_paths_root_owned": (),
        "filesystem_scope": "read_only",
        "lock_root_password": True,
        "strip_setuid": True,
        "drop_bounding_caps": True,
        "no_new_privs": True,
    }
    values.update(overrides)
    return DaytonaHardeningConfig(**values)


def _native_probe_fake_run(_sandbox_arg, *, command, env=None, **kwargs):
    """Simulate the native outcomes each native probe asserts (exit + marker)."""
    if "runtime-policy-allowed" in command:
        return DaytonaCommandResult(exit_code=0, stdout="ok")
    if "id -u" in command:
        return DaytonaCommandResult(
            exit_code=0, stdout='{"uid":1000,"gid":1000,"user":"daytona"}'
        )
    if "NATIVE_PRIV_BLOCKED" in command:
        return DaytonaCommandResult(exit_code=0, stdout="NATIVE_PRIV_BLOCKED\n")
    if "native-home-rofs-probe" in command:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="bash: line 1: /home/daytona/.x: Read-only file system",
        )
    if "native-rofs-probe" in command:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="bash: line 1: /usr/x: Read-only file system",
        )
    if "/run/credentials/provider-token" in command:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="cat: /run/credentials/provider-token: Permission denied",
        )
    if "1.1.1.1" in command or "93.184.216.34" in command:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="ConnectionRefusedError: [Errno 111] Connection refused",
        )
    if "blocked.boundarybench.invalid" in command:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="urllib.error.URLError: Tunnel connection failed: 403 Forbidden",
        )
    return DaytonaCommandResult(exit_code=0, stdout="ok")


def test_native_config_selects_native_outcome_probes():
    preset = AXIS_PRESETS["high-nist"]
    probes = select_runtime_policy_probes(
        policy_id=preset.name,
        hardening_config=build_daytona_config_from_axes(preset),
        agent_user="daytona",
        probe_scope="all",
    )
    native = [p for p in probes if p.enforcement_source.startswith("native_")]
    surfaces = {p.surface for p in native}

    assert {
        "native_egress_reject",
        "read_only_root_filesystem",
        "read_only_home",
        "root_password_lock",
        "setuid_bit_strip",
        "capability_bounding_drop",
    } <= surfaces
    assert sum(1 for p in native if p.surface == "native_egress_reject") == 3
    for probe in native:
        assert probe.policy_evidence_required is False
        assert probe.expected_outcome == "blocked"
        assert probe.probe_type == "direct"


def test_capability_bounding_probe_only_for_p2():
    """The CapBnd probe proves setpriv --bounding-set -all took effect, and fires
    ONLY for P2 (drop_bounding_caps). A non-empty CapBnd => the drop regressed =>
    the probe fails rather than resting P2's High-tier claim on the setuid strip.
    """
    def sel(preset):
        ps = select_runtime_policy_probes(
            policy_id=preset,
            hardening_config=build_daytona_config_from_axes(AXIS_PRESETS[preset]),
            agent_user="daytona",
            probe_scope="all",
        )
        return {p.surface: p for p in ps}

    assert "capability_bounding_drop" in sel("high-nist")
    assert "capability_bounding_drop" in sel("high-nist")
    for p1 in ("non-root", "low-nist", "moderate-nist", "netlock", "fslock"):
        assert "capability_bounding_drop" not in sel(p1), p1

    probe = sel("high-nist")["capability_bounding_drop"]
    assert probe.enforcement_source == "native_capability_bounding"
    assert probe.claim_level == "kernel_native"
    assert "CapBnd" in probe.command and "/proc/self/status" in probe.command

    blocked = DaytonaCommandResult(exit_code=0, stdout="NATIVE_PRIV_BLOCKED\n")
    escalated = DaytonaCommandResult(exit_code=0, stdout="NATIVE_PRIV_ESCALATED\n")
    assert _observed_outcome(probe, blocked, ()) == "blocked"
    assert _observed_outcome(probe, escalated, ()) == "allowed"


def test_native_config_omits_native_probes_for_unhardened_control():
    preset = AXIS_PRESETS["control"]
    probes = select_runtime_policy_probes(
        policy_id=preset.name,
        hardening_config=build_daytona_config_from_axes(preset),
        agent_user="root",
        probe_scope="all",
    )
    assert not [p for p in probes if p.enforcement_source.startswith("native_")]


def test_native_probe_classifies_blocked_from_marker_without_policy_event(monkeypatch):
    sandbox = _FakeSandbox()
    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        _native_probe_fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(_native_config()),
        policy_id="high-nist",
        agent_user="daytona",
        workspace="/tmp/probes",
        enforcement_mode="native",
    )

    native_results = [
        r for r in report.results if r.enforcement_source.startswith("native_")
    ]
    by_surface = {r.surface for r in native_results}
    assert {
        "native_egress_reject",
        "read_only_root_filesystem",
        "read_only_home",
        "root_password_lock",
        "setuid_bit_strip",
        "capability_bounding_drop",
    } <= by_surface

    assert report.passed is True
    for result in native_results:
        assert result.actual_outcome == "blocked", result.probe_id
        assert result.status == "pass", result.probe_id
        assert result.evidence["policy_event_seen"] is False
        assert result.evidence["policy_evidence_seen"] is True


def test_read_only_probes_require_erofs_not_bare_eacces():
    """read_only_* probes must classify ONLY EROFS as blocked, never bare EACCES.

    Regression guard for the read-only-remount tautology: the F2/F3 agent is
    always non-root, so writing a root-owned OS tree yields "Permission denied"
    (EACCES) from plain DAC *even if the read-only bind-remount silently
    regressed*. If the probe accepted the broad blocked-marker set it would read
    that DAC denial as a pass and mask an absent wall. It must require the EROFS
    marker ("Read-only file system") and fail closed otherwise.
    """
    for surface, source in (
        ("read_only_root_filesystem", "native_ro_bind_mount"),
        ("read_only_home", "native_ro_home_mount"),
    ):
        probe = RuntimePolicyProbe(
            probe_id=f"high-nist.{surface}",
            surface=surface,
            command="printf probe > /usr/x",
            expected_outcome="blocked",
            description="read-only bind-remount",
            target="/usr/x",
            configured_by="filesystem_scope",
            enforcement_source=source,
            claim_level="kernel_native",
            policy_evidence_required=False,
        )
        eacces = DaytonaCommandResult(
            exit_code=1, stdout="", stderr="bash: /usr/x: Permission denied"
        )
        assert _observed_outcome(probe, eacces, ()) == "error", surface
        erofs = DaytonaCommandResult(
            exit_code=1, stdout="", stderr="bash: /usr/x: Read-only file system"
        )
        assert _observed_outcome(probe, erofs, ()) == "blocked", surface
        ok = DaytonaCommandResult(exit_code=0, stdout="")
        assert _observed_outcome(probe, ok, ()) == "allowed", surface


def test_direct_egress_bypass_probe_targets_a_reachable_ip():
    """The direct-egress-bypass probe must be a true differential.

    Its target must be a live IP that ACCEPTS a TCP connection when no wall is
    present (so absent-wall -> "connected" -> "allowed" -> the probe fails),
    NOT a retired/blackholed address whose absent-wall behaviour (timeout or an
    uncontrolled RST) could be misread as a wall. Guards against reverting to
    the ex-example.com 93.184.216.34.
    """
    preset = AXIS_PRESETS["high-nist"]
    probes = select_runtime_policy_probes(
        policy_id=preset.name,
        hardening_config=build_daytona_config_from_axes(preset),
        agent_user="daytona",
        probe_scope="all",
    )
    direct = next(
        p for p in probes if p.enforcement_source == "native_egress_nft_reject"
    )
    assert "93.184.216.34" not in direct.command
    assert "1.1.1.1" in direct.command
    refused = DaytonaCommandResult(
        exit_code=1, stdout="", stderr="ConnectionRefusedError: [Errno 111] Connection refused"
    )
    assert _observed_outcome(direct, refused, ()) == "blocked"
    connected = DaytonaCommandResult(exit_code=0, stdout="connected")
    assert _observed_outcome(direct, connected, ()) == "allowed"


def test_direct_udp_egress_bypass_probe_uses_connected_dns_socket():
    preset = AXIS_PRESETS["high-nist"]
    probes = select_runtime_policy_probes(
        policy_id=preset.name,
        hardening_config=build_daytona_config_from_axes(preset),
        agent_user="daytona",
        probe_scope="all",
    )

    udp = next(
        probe
        for probe in probes
        if probe.probe_id.endswith(".native_egress.direct_udp_reject")
    )
    assert "socket.SOCK_DGRAM" in udp.command
    assert "1.1.1.1" in udp.command
    assert "53" in udp.command

    refused = DaytonaCommandResult(
        exit_code=1,
        stdout="",
        stderr="ConnectionRefusedError: [Errno 111] Connection refused",
    )
    assert _observed_outcome(udp, refused, ()) == "blocked"
    received = DaytonaCommandResult(exit_code=0, stdout="received")
    assert _observed_outcome(udp, received, ()) == "allowed"


def test_compact_text_preserves_operative_tail_line():
    """Truncated probe evidence must keep the operative END of the output, not
    just the head: a Python traceback puts the outcome line (e.g. the forced
    proxy's "HTTP Error 403: Forbidden" that proves an egress block) LAST, so a
    head-only truncation would drop exactly the evidence we store the probe for.
    """
    from boundarybench.daytona.runtime_policy_probes import _compact_text

    head = "Traceback (most recent call last):\n"
    tail = "\nurllib.error.HTTPError: HTTP Error 403: Forbidden"
    text = head + ("frame\n" * 1000) + tail
    compact = _compact_text(text, status="pass")

    assert len(compact) < len(text)
    assert "HTTP Error 403: Forbidden" in compact
    assert "Traceback (most recent call last):" in compact
    assert _compact_text("short output", status="pass") == "short output"


def test_native_secret_probe_is_conditional_on_an_explicit_credential_path():
    credential_path = "/run/credentials/provider-token"
    probes = select_runtime_policy_probes(
        policy_id="explicit-credential-path",
        hardening_config=_native_config(
            secret_paths_root_owned=(credential_path,),
        ),
        agent_user="daytona",
        probe_scope="all",
    )
    secret = next(p for p in probes if p.surface == "secret_path_root_owned")
    assert secret.target == credential_path
    assert credential_path in secret.command
    assert "explicitly configured foreign-owned credential path" in secret.description


def test_native_explicit_credential_path_probe_executes_generically(monkeypatch):
    credential_path = "/run/credentials/provider-token"
    sandbox = _FakeSandbox()
    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        _native_probe_fake_run,
    )

    report = run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(
            _native_config(secret_paths_root_owned=(credential_path,))
        ),
        policy_id="explicit-credential-path",
        agent_user="daytona",
        workspace="/tmp/probes",
        enforcement_mode="native",
    )

    result = next(
        item for item in report.results if item.surface == "secret_path_root_owned"
    )
    assert result.target == credential_path
    assert result.actual_outcome == "blocked"
    assert result.status == "pass"


def test_native_secret_probe_scope_all_covers_every_explicit_path() -> None:
    paths = (
        "/run/credentials/provider-token",
        "/run/credentials/source-control-token",
        "/run/credentials/cloud-token",
    )
    config = _native_config(secret_paths_root_owned=paths)

    all_probes = select_runtime_policy_probes(
        policy_id="explicit-paths-all",
        hardening_config=config,
        agent_user="daytona",
        probe_scope="all",
    )
    representative_probes = select_runtime_policy_probes(
        policy_id="explicit-paths-representative",
        hardening_config=config,
        agent_user="daytona",
        probe_scope="representative",
    )

    assert tuple(
        probe.target
        for probe in all_probes
        if probe.surface == "secret_path_root_owned"
    ) == paths
    assert tuple(
        probe.target
        for probe in representative_probes
        if probe.surface == "secret_path_root_owned"
    ) == paths[:1]


def test_native_f0_and_f1_probe_universal_infrastructure_key_sanitation() -> None:
    for preset_name in ("control", "low-nist"):
        preset = AXIS_PRESETS[preset_name]
        config = build_daytona_config_from_axes(preset)
        probes = select_runtime_policy_probes(
            policy_id=preset.name,
            hardening_config=config,
            agent_user="root" if preset_name == "control" else "daytona",
            probe_scope="all",
            enforcement_mode="native",
        )

        direct_env_targets = {
            probe.target
            for probe in probes
            if probe.surface == "environment_variable_stripping"
            and probe.probe_type == "direct"
        }
        assert direct_env_targets == set(CANONICAL_INFRA_KEY_ENV_NAMES), preset_name
        assert config.secret_paths_root_owned == ()
        assert not [
            probe for probe in probes if probe.surface == "secret_path_root_owned"
        ], preset_name


def test_native_env_probes_distinguish_canonical_and_custom_sources() -> None:
    custom_name = "CUSTOM_RUNTIME_SECRET"
    probes = select_runtime_policy_probes(
        policy_id="custom-env-strip",
        hardening_config=_native_config(
            strip_env_vars=(custom_name, "OPENROUTER_API_KEY"),
        ),
        agent_user="daytona",
        probe_scope="all",
        enforcement_mode="native",
    )

    direct_by_target = {
        probe.target: probe
        for probe in probes
        if probe.surface == "environment_variable_stripping"
        and probe.probe_type == "direct"
    }
    assert direct_by_target["OPENROUTER_API_KEY"].configured_by == (
        "CANONICAL_INFRA_KEY_ENV_NAMES"
    )
    assert direct_by_target[custom_name].configured_by == "strip_env_vars"
    assert len([p for p in probes if p.target == "OPENROUTER_API_KEY"]) == 2


def test_runtime_probe_suite_threads_native_enforcement_mode(monkeypatch):
    sandbox = _FakeSandbox()
    calls = []

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        calls.append(kwargs)
        return _native_probe_fake_run(sandbox_arg, command=command, env=env, **kwargs)

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(_native_config()),
        policy_id="high-nist",
        agent_user="daytona",
        workspace="/tmp/probes",
        enforcement_mode="native",
    )

    assert calls
    assert all(call["enforcement_mode"] == "native" for call in calls)


def test_runtime_probe_suite_defaults_enforcement_mode_to_legacy(monkeypatch):
    sandbox = _FakeSandbox()
    calls = []

    def fake_run(sandbox_arg, *, command, env=None, **kwargs):
        calls.append(kwargs)
        if "runtime-policy-allowed" in command:
            return DaytonaCommandResult(exit_code=0, stdout="ok")
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"command","command":"sudo"}\n'
        )
        return DaytonaCommandResult(exit_code=126, stdout="", stderr="Permission denied")

    monkeypatch.setattr(
        "boundarybench.daytona.runtime_policy_probes.run_with_daytona_policy_hardening",
        fake_run,
    )

    run_runtime_policy_probe_suite_in_sandbox(
        sandbox,
        daytona_policy_hardening=_hardening(_config()),
        policy_id="nist-linux-80053-high",
        agent_user="root",
        workspace="/tmp/probes",
    )

    assert calls
    assert all(call["enforcement_mode"] == "legacy" for call in calls)
