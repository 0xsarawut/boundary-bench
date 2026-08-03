from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaCommandResult,
    DaytonaPolicyHardening,
)
from boundarybench.daytona.hardening_config import DEFAULT_DAYTONA_HARDENING_CONFIG
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)
from boundarybench.daytona.runtime_policy_probes import (
    select_runtime_policy_probes,
)
from boundarybench.terminalbench.daytona_preflight import (
    PreflightFailedError,
    build_policy_proof_plan,
    preflight_fixture_commands,
    run_preflight,
)
from boundarybench.terminalbench.policies import HardeningPolicy, resolve_policy


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.event_output = ""

    def exec(self, command: str, *, timeout: int = 30, env: Any = None):
        self.commands.append(command)
        if "cat /tmp/boundarybench-policy-events.jsonl" in command:
            result = self.event_output
        else:
            result = ""
        if "rm -f /tmp/boundarybench-policy-events.jsonl" in command:
            self.event_output = ""
        return type("Result", (), {"exit_code": 0, "result": result})()


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()


def _config(**overrides: Any):
    values = {
        "name": "proof-test",
        "denied_command_names": (),
        "denied_exec_paths": (),
        "denied_path_exact": (),
        "denied_path_prefixes": (),
        "tee_denied_patterns": (),
        "child_network_command_names": (),
        "strip_env_vars": (),
        **overrides,
    }
    return replace(DEFAULT_DAYTONA_HARDENING_CONFIG, **values)


def _policy(**overrides: Any) -> HardeningPolicy:
    values = {
        "name": "proof-test",
        "config": _config(
            denied_command_names=("curl",),
            denied_exec_paths=("/usr/bin/sudo",),
            denied_path_exact=("/etc/boundary/secret-read.txt",),
            denied_path_prefixes=("/tmp/boundarybench-secret-link",),
            tee_denied_patterns=("/usr/bin/boundary-denied-probe*",),
            child_network_command_names=("python3",),
            strip_env_vars=("SECRET_TOKEN",),
        ),
        "overlays": ("nonroot-agent", "blocked-surfaces", "env-strip", "child-network"),
        "agent_user": "daytona",
        "isolate_network": False,
        "block_network": False,
        "block_child_shell_network": True,
        **overrides,
    }
    return HardeningPolicy(**values)


def _hardening(policy: HardeningPolicy) -> DaytonaPolicyHardening:
    return DaytonaPolicyHardening(
        asset_dir="/opt/h",
        policy_message_preload_so="/opt/h/policy.so",
        block_message_command="/opt/h/deny.sh",
        mount_real_path="/opt/h/mount.real",
        policy_bin_dir="/opt/h/bin",
        child_network_block_env="/opt/h/child_net",
        hardening_config=policy.config,
    )


def test_proof_plan_is_empty_for_control_policy():
    plan = build_policy_proof_plan(resolve_policy("control"))

    assert plan.policy == "control"
    assert plan.rules == ()
    assert plan.probes == ()
    assert plan.to_metadata()["required_rule_count"] == 0


def test_proof_plan_is_derived_from_policy_config_rules():
    plan = build_policy_proof_plan(_policy())

    rule_ids = {rule.rule_id for rule in plan.rules}
    assert "nonroot-agent:daytona" in rule_ids
    assert "command-name:curl" in rule_ids
    assert "exec-path:/usr/bin/sudo" in rule_ids
    assert "path-exact:/etc/boundary/secret-read.txt" in rule_ids
    assert "path-prefix:/tmp/boundarybench-secret-link" in rule_ids
    assert "tee-pattern:/usr/bin/boundary-denied-probe*" in rule_ids
    assert "env-var:SECRET_TOKEN" in rule_ids
    assert "child-network:python3" in rule_ids

    assert all(rule.probe_ids for rule in plan.rules)
    assert {probe.rule_id for probe in plan.probes} == rule_ids
    assert any("SECRET_TOKEN" in probe.command for probe in plan.probes)
    assert any("socket" in probe.command for probe in plan.probes)
    assert any("bash -lc" in probe.command for probe in plan.probes)


def test_run_preflight_executes_generated_probes_with_policy_flags(monkeypatch, capsys):
    policy = _policy()
    calls: list[dict[str, Any]] = []

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        calls.append(kwargs)
        env = kwargs.get("env") or {}
        if "SECRET_TOKEN" in env:
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        if 'test "$(id -u)" != "0"' in kwargs["command"]:
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        return DaytonaCommandResult(
            exit_code=1,
            stdout="BOUNDARY_POLICY_BLOCK: blocked by policy",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    assert result.passed is True
    assert result.proof_plan.policy == "proof-test"
    assert calls
    assert all(call["block_child_shell_network"] is True for call in calls)
    assert all(call["isolate_network"] is False for call in calls)
    assert all(call["block_network"] is False for call in calls)
    assert all(call["run_as_root"] is False for call in calls)
    assert all(call["short_command"] is True for call in calls)
    assert any((call.get("env") or {}).get("SECRET_TOKEN") for call in calls)
    captured = capsys.readouterr()
    assert "phase_timing component=terminalbench_daytona" in captured.out
    assert "phase=policy_preflight_probe" in captured.out
    assert "id=command-name:curl:probe" in captured.out
    assert "rule_id=command-name:curl" in captured.out
    assert "surface=command" in captured.out


def test_happy_probe_outputs_pass_when_policy_hardening_is_installed(
    monkeypatch,
):
    policy = _policy(
        config=_config(
            denied_command_names=("curl",),
            denied_path_exact=("/etc/boundary/secret-read.txt",),
            child_network_command_names=("python3",),
            strip_env_vars=("BOUNDARY_HARDENING_SECRET",),
        ),
        overlays=("nonroot-agent", "blocked-surfaces", "env-strip", "child-network"),
        agent_user="daytona",
        block_child_shell_network=True,
    )

    def fake_hardened_probe(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        command = kwargs["command"]
        env = kwargs.get("env") or {}
        if command == 'test "$(id -u)" != "0" 2>&1':
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        if env.get("BOUNDARY_HARDENING_SECRET"):
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        return DaytonaCommandResult(
            exit_code=1,
            stdout="BOUNDARY_POLICY_BLOCK: blocked by policy",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_hardened_probe,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    outcomes = {probe.metadata["rule_id"]: probe for probe in result.results}
    assert result.passed is True
    assert set(outcomes) == {
        "nonroot-agent:daytona",
        "command-name:curl",
        "path-exact:/etc/boundary/secret-read.txt",
        "env-var:BOUNDARY_HARDENING_SECRET",
        "child-network:python3",
    }
    assert outcomes["nonroot-agent:daytona"].observed == "allowed"
    assert outcomes["command-name:curl"].observed == "blocked"
    assert outcomes["path-exact:/etc/boundary/secret-read.txt"].observed == "blocked"
    assert outcomes["env-var:BOUNDARY_HARDENING_SECRET"].observed == "absent"
    assert outcomes["child-network:python3"].observed == "blocked"
    assert outcomes["child-network:python3"].policy_evidence_seen is True


def test_sad_probe_outputs_fail_when_policy_hardening_is_missing(
    monkeypatch,
):
    policy = _policy(
        config=_config(
            denied_command_names=("curl",),
            denied_path_exact=("/etc/boundary/secret-read.txt",),
            child_network_command_names=("python3",),
            strip_env_vars=("BOUNDARY_HARDENING_SECRET",),
        ),
        overlays=("blocked-surfaces", "env-strip", "child-network"),
        agent_user="daytona",
        block_child_shell_network=True,
    )

    def fake_unhardened_probe(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        command = kwargs["command"]
        env = kwargs.get("env") or {}
        if command == "curl --version 2>&1":
            return DaytonaCommandResult(exit_code=0, stdout="curl 7.88.1", stderr="")
        if "secret-read.txt" in command:
            return DaytonaCommandResult(exit_code=0, stdout="read allowed", stderr="")
        if env.get("BOUNDARY_HARDENING_SECRET"):
            return DaytonaCommandResult(exit_code=1, stdout="", stderr="")
        if "socket" in command:
            return DaytonaCommandResult(exit_code=0, stdout="connected", stderr="")
        raise AssertionError(f"unexpected probe command: {command}")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_unhardened_probe,
    )

    with pytest.raises(PreflightFailedError) as exc_info:
        run_preflight(
            _FakeSandbox(),
            policy=policy,
            daytona_policy_hardening=_hardening(policy),
            setup_fixtures=False,
        )

    metadata = exc_info.value.to_metadata()
    results = {probe["metadata"]["rule_id"]: probe for probe in metadata["all_probes"]}
    assert metadata["preflight_passed"] is False
    assert metadata["failed_count"] == 4
    assert metadata["failed_rule_ids"] == [
        "command-name:curl",
        "path-exact:/etc/boundary/secret-read.txt",
        "env-var:BOUNDARY_HARDENING_SECRET",
        "child-network:python3",
    ]
    assert results["command-name:curl"]["observed"] == "allowed"
    assert (
        results["path-exact:/etc/boundary/secret-read.txt"]["observed"] == "allowed"
    )
    assert results["env-var:BOUNDARY_HARDENING_SECRET"]["observed"] == "blocked"
    assert results["child-network:python3"]["observed"] == "allowed"
    assert results["command-name:curl"]["stdout"] == "curl 7.88.1"
    assert (
        results["path-exact:/etc/boundary/secret-read.txt"]["stdout"]
        == "read allowed"
    )
    assert results["child-network:python3"]["stdout"] == "connected"


def test_policy_evidence_rejects_generic_non_policy_failures(monkeypatch):
    policy = _policy(
        config=_config(denied_path_exact=("/tmp/missing-policy-target",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="",
            stderr="Input/output error reading /tmp/missing-policy-target",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    with pytest.raises(PreflightFailedError) as exc_info:
        run_preflight(
            _FakeSandbox(),
            policy=policy,
            daytona_policy_hardening=_hardening(policy),
            setup_fixtures=False,
        )

    failed = exc_info.value.result.failed_probes[0]
    assert failed.observed == "blocked"
    assert failed.policy_evidence_seen is False
    assert failed.message == "expected matching policy evidence, but none was found"


def test_unavailable_probe_targets_do_not_fail_preflight(monkeypatch):
    policy = _policy(
        config=_config(denied_command_names=("missing-policy-command",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=127,
            stdout="",
            stderr="/usr/bin/env: 'missing-policy-command': No such file or directory",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    assert result.passed is True
    probe = result.results[0]
    assert probe.observed == "not_applicable"
    assert probe.status == "not_applicable"
    assert probe.message == "probe target was not available in this task image"


def test_preflight_accepts_generic_denial_when_policy_event_matches(monkeypatch):
    policy = _policy(
        config=_config(denied_command_names=("sudo",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )
    sandbox = _FakeSandbox()

    def fake_run_with_hardening(
        sandbox_arg: _FakeSandbox, *args: Any, **kwargs: Any
    ) -> DaytonaCommandResult:
        sandbox_arg.process.event_output = (
            '{"event_type":"policy_block","surface":"command","command":"sudo"}\n'
        )
        return DaytonaCommandResult(
            exit_code=126,
            stdout="",
            stderr="Permission denied",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        sandbox,
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    probe = result.results[0]
    assert result.passed is True
    assert probe.policy_evidence_seen is True
    assert probe.policy_evidence_id == "policy_block"
    assert probe.metadata["execution"]["policy_events"][0]["command"] == "sudo"


def test_preflight_reports_missing_exec_path_as_not_applicable(monkeypatch):
    policy = _policy(
        config=_config(denied_exec_paths=("/usr/bin/missing-policy-tool",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=127,
            stdout="/usr/bin/env: '/usr/bin/missing-policy-tool': No such file or directory\n",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    probe = result.results[0]
    assert result.passed is True
    assert probe.required_for_benchmark is False
    assert probe.observed == "not_applicable"
    assert probe.status == "not_applicable"


def test_generic_permission_denied_counts_as_policy_evidence(monkeypatch):
    policy = _policy(
        config=_config(denied_command_names=("wget",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=126, stdout="Permission denied\n", stderr=""
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    assert result.passed is True
    assert result.results[0].policy_evidence_seen is True


def test_preflight_fixtures_are_derived_from_generated_probe_targets(monkeypatch):
    policy = _policy(
        config=_config(
            denied_path_exact=(
                "/custom/secret-read.txt",
                "/etc/sudoers",
                "/proc/self/environ",
            ),
            denied_path_prefixes=("/tmp/custom-prefix/",),
            tee_denied_patterns=("/tmp/custom-write*",),
        ),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )
    sandbox = _FakeSandbox()

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="BOUNDARY_POLICY_BLOCK: blocked by policy",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        sandbox,
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
    )

    assert result.passed is True
    setup_command = sandbox.process.commands[0]
    assert "mkdir -p /custom" in setup_command
    assert "if [ ! -e /custom/secret-read.txt ]; then" in setup_command
    assert "# boundarybench-preflight" in setup_command
    assert "> /custom/secret-read.txt" in setup_command
    assert "if [ ! -e /etc/sudoers ]; then" in setup_command
    assert "> /etc/sudoers" in setup_command
    assert "/proc/self/environ" not in setup_command
    assert "mkdir -p /tmp/custom-prefix" in setup_command
    assert "> /tmp/custom-prefix/boundarybench-preflight" in setup_command
    assert "rm -f /tmp/custom-writeboundarybench-preflight" in setup_command


def test_preflight_fixtures_do_not_corrupt_system_or_virtual_paths():
    policy = _policy(
        config=_config(
            denied_path_exact=(
                "/etc/sudoers",
                "/proc/1/environ",
                "/proc/self/environ",
            ),
            denied_path_prefixes=(
                "/etc/sudoers.d/",
                "/proc/self/",
            ),
        ),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    commands = preflight_fixture_commands(build_policy_proof_plan(policy))
    setup_command = " && ".join(commands)

    assert "/proc/1/environ" not in setup_command
    assert "/proc/self/environ" not in setup_command
    assert "/proc/self/boundarybench-preflight" not in setup_command
    assert "if [ ! -e /etc/sudoers ]; then" in setup_command
    assert "> /etc/sudoers;" in setup_command
    assert "if [ ! -e /etc/sudoers.d/boundarybench-preflight ]; then" in (
        setup_command
    )
    assert "# boundarybench-preflight" in setup_command
    assert "'boundarybench-preflight' > /etc/sudoers" not in setup_command


def test_unsupported_child_network_probe_is_reported_without_blocking_preflight():
    policy = _policy(
        config=_config(child_network_command_names=("unsupported-child-net",)),
        overlays=("child-network",),
        agent_user="daytona",
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    metadata = result.to_metadata()
    assert result.passed is True
    assert metadata["failed_rule_ids"] == []
    unsupported = metadata["all_probes"][0]
    assert unsupported["required_for_benchmark"] is False
    assert unsupported["observed"] == "unsupported"
    assert unsupported["status"] == "unsupported"
    assert unsupported["metadata"]["proof"]["unsupported_reason"]


@pytest.mark.parametrize(
    ("policy_name", "expected_native_surfaces"),
    [
        (
            "moderate-nist",
            {
                "native_egress_reject",
                "read_only_root_filesystem",
                "root_password_lock",
            },
        ),
        (
            "low-nist",
            {
                "native_egress_reject",
                "read_only_root_filesystem",
                "root_password_lock",
            },
        ),
    ],
)
def test_nist_moderate_low_native_presets_cover_supported_surfaces(
    monkeypatch,
    policy_name: str,
    expected_native_surfaces: set[str],
):
    policy = resolve_policy(policy_name)
    assert policy.enforcement_mode == "native"

    called = False

    def fail_if_probed(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        nonlocal called
        called = True
        raise AssertionError("native presets run no legacy proof-plan probes")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fail_if_probed,
    )
    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )
    assert result.passed is True
    assert result.proof_plan.rules == ()
    assert result.proof_plan.probes == ()
    assert called is False

    probes = select_runtime_policy_probes(
        policy_id=policy.name,
        hardening_config=build_daytona_config_from_axes(AXIS_PRESETS[policy.name]),
        agent_user=policy.agent_user,
        probe_scope=policy.runtime_probe_scope,
    )
    native_probes = [
        probe for probe in probes if probe.enforcement_source.startswith("native_")
    ]
    assert {probe.surface for probe in native_probes} == expected_native_surfaces
    for probe in native_probes:
        assert probe.expected_outcome == "blocked"
        assert probe.policy_evidence_required is False


def test_child_network_probe_for_denied_command_name_is_not_required():
    policy = _policy(
        config=_config(
            denied_command_names=("curl",),
            child_network_command_names=("curl", "python3"),
        ),
        overlays=("blocked-surfaces", "child-network"),
        agent_user="daytona",
    )

    probes = {
        probe.rule_id: probe
        for probe in build_policy_proof_plan(policy).probes
        if probe.rule_id.startswith("child-network:")
    }

    assert probes["child-network:curl"].required_for_benchmark is False
    assert probes["child-network:curl"].policy_evidence_required is False
    assert probes["child-network:python3"].required_for_benchmark is True
    assert probes["child-network:python3"].policy_evidence_required is True


def test_compact_preflight_metadata_omits_probe_output_on_success(monkeypatch):
    policy = _policy(
        config=_config(denied_command_names=("curl",)), overlays=("blocked-surfaces",)
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(
            exit_code=1,
            stdout="BOUNDARY_POLICY_BLOCK: blocked by policy",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    compact = result.to_compact_metadata()
    assert compact["preflight_passed"] is True
    assert compact["probe_count"] == 1
    assert compact["all_probes"][0]["probe_id"] == "command-name:curl:probe"
    assert compact["all_probes"][0]["policy_evidence_seen"] is True
    assert "stdout" not in compact["all_probes"][0]
    assert "stderr" not in compact["all_probes"][0]


def _passing_probe_fake(calls: list[dict[str, Any]]):
    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        calls.append(kwargs)
        env = kwargs.get("env") or {}
        if "SECRET_TOKEN" in env:
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        if 'test "$(id -u)" != "0"' in kwargs["command"]:
            return DaytonaCommandResult(exit_code=0, stdout="", stderr="")
        return DaytonaCommandResult(
            exit_code=1,
            stdout="BOUNDARY_POLICY_BLOCK: blocked by policy",
            stderr="",
        )

    return fake_run_with_hardening


def test_run_preflight_threads_native_enforcement_mode_from_policy(monkeypatch):
    policy = _policy(enforcement_mode="native")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        _passing_probe_fake(calls),
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    assert result.passed is True
    assert calls
    assert all(call["enforcement_mode"] == "native" for call in calls)


def test_run_preflight_defaults_to_legacy_enforcement_mode(monkeypatch):
    policy = _policy()
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        _passing_probe_fake(calls),
    )

    result = run_preflight(
        _FakeSandbox(),
        policy=policy,
        daytona_policy_hardening=_hardening(policy),
        setup_fixtures=False,
    )

    assert result.passed is True
    assert calls
    assert all(call["enforcement_mode"] == "legacy" for call in calls)


def test_run_preflight_failure_reports_failed_rules(monkeypatch):
    policy = _policy(
        config=_config(denied_command_names=("curl",)),
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )

    def fake_run_with_hardening(*args: Any, **kwargs: Any) -> DaytonaCommandResult:
        return DaytonaCommandResult(exit_code=0, stdout="curl allowed", stderr="")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_preflight.run_with_daytona_policy_hardening",
        fake_run_with_hardening,
    )

    with pytest.raises(PreflightFailedError) as exc_info:
        run_preflight(
            _FakeSandbox(),
            policy=policy,
            daytona_policy_hardening=_hardening(policy),
            setup_fixtures=False,
        )

    metadata = exc_info.value.to_metadata()
    assert metadata["preflight_passed"] is False
    assert metadata["failed_rule_ids"] == ["command-name:curl"]
    assert metadata["proof_plan"]["required_rule_count"] == 1
    assert metadata["failed_count"] == 1
