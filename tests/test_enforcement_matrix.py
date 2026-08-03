"""Unit tests for the probe-only native-enforcement matrix (no real sandbox).

These exercise the STRICT wall-set contract and the assertion logic against
hand-built probe reports (mirroring the fakes in
``tests/test_terminalbench_daytona_eval.py``), plus a drift guard that the
contract table matches what ``select_runtime_policy_probes`` actually emits.
No Daytona sandbox, credentials, or Harbor dataset is required.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from boundarybench.daytona.runtime_policy_probes import (
    DAYTONA_HARDENING_RUNTIME_TARGET,
    RUNTIME_POLICY_PROBE_WORKSPACE,
    DaytonaRuntimeProbeSuiteError,
    RuntimePolicyProbeReport,
    RuntimePolicyProbeResult,
    select_runtime_policy_probes,
)
from boundarybench.terminalbench import enforcement_matrix as em
from boundarybench.terminalbench.enforcement_matrix import (
    EXPECTED_NATIVE_WALLS,
    EnforcementMatrixError,
    assert_enforcement_matrix,
    expected_native_walls,
    native_walls_proven,
)
from boundarybench.terminalbench.policies import resolve_policy


_NATIVE_SOURCE_BY_SURFACE = {
    "native_egress_reject": "native_egress_nft_reject",
    "secret_path_root_owned": "native_dac_owner",
    "read_only_root_filesystem": "native_ro_bind_mount",
    "read_only_home": "native_ro_home_mount",
    "root_password_lock": "native_no_sudoers",
    "setuid_bit_strip": "native_setuid_strip",
    "capability_bounding_drop": "native_capability_bounding",
}

_EIGHT_PRESETS = {
    "control",
    "non-root",
    "low-nist",
    "moderate-nist",
    "high-nist",
    "high-nist",
    "netlock",
    "fslock",
}


def _result(
    surface: str,
    *,
    enforcement_source: str,
    status: str = "pass",
    required: bool = True,
    expected_outcome: str = "blocked",
    actual_outcome: str = "blocked",
) -> RuntimePolicyProbeResult:
    return RuntimePolicyProbeResult(
        policy_id="test-policy",
        policy_name="test-policy",
        runtime_target=DAYTONA_HARDENING_RUNTIME_TARGET,
        probe_id=f"test-policy.{surface}",
        surface=surface,
        expected_outcome=expected_outcome,
        actual_outcome=actual_outcome,
        status=status,
        classification="policy_enforced" if status == "pass" else "policy_miss",
        required=required,
        target=surface,
        command=f"probe {surface}",
        configured_by=surface,
        enforcement_source=enforcement_source,
        claim_level="kernel_native",
        execution_context="daytona_sdk",
        runner="daytona_policy_hardening",
        message=f"{surface}: {status}",
    )


def _native_result(surface: str, *, status: str = "pass") -> RuntimePolicyProbeResult:
    return _result(
        surface,
        enforcement_source=_NATIVE_SOURCE_BY_SURFACE[surface],
        status=status,
        actual_outcome="blocked" if status == "pass" else "allowed",
    )


def _control_result(status: str = "pass") -> RuntimePolicyProbeResult:
    return _result(
        "workspace_allowed_control",
        enforcement_source="none",
        status=status,
        expected_outcome="allowed",
        actual_outcome="allowed" if status == "pass" else "blocked",
    )


def _report(
    policy_name: str, results: list[RuntimePolicyProbeResult]
) -> RuntimePolicyProbeReport:
    return RuntimePolicyProbeReport(
        policy_id=policy_name,
        policy_name=policy_name,
        runtime_target=DAYTONA_HARDENING_RUNTIME_TARGET,
        hardening_config={"name": policy_name},
        overlays=(),
        agent_user="daytona",
        workspace=RUNTIME_POLICY_PROBE_WORKSPACE,
        results=tuple(results),
    )


def _passing_report(policy_name: str) -> RuntimePolicyProbeReport:
    results = [_native_result(s) for s in sorted(EXPECTED_NATIVE_WALLS[policy_name])]
    results.append(_control_result())
    return _report(policy_name, results)


def test_contract_covers_exactly_the_eight_native_presets():
    assert set(EXPECTED_NATIVE_WALLS) == _EIGHT_PRESETS
    for name in EXPECTED_NATIVE_WALLS:
        assert resolve_policy(name).enforcement_mode == "native"


def test_default_presets_expect_no_secret_path_wall_without_explicit_paths():
    for walls in EXPECTED_NATIVE_WALLS.values():
        assert "secret_path_root_owned" not in walls


@pytest.mark.parametrize("policy_name", sorted(EXPECTED_NATIVE_WALLS))
def test_contract_matches_generated_probes(policy_name):
    policy = resolve_policy(policy_name)
    assert policy.name == policy_name
    probes = select_runtime_policy_probes(
        policy_id=policy.name,
        hardening_config=policy.config,
        agent_user=policy.agent_user,
        block_network=policy.block_network,
        block_child_shell_network=policy.block_child_shell_network,
        unsupported_surfaces=policy.unsupported_surfaces,
        probe_scope=policy.runtime_probe_scope,
        full_mac_enforcement=policy.full_mac_enforcement,
    )
    generated = {
        probe.surface
        for probe in probes
        if probe.enforcement_source.startswith("native_")
    }
    assert generated == set(EXPECTED_NATIVE_WALLS[policy_name]), (
        f"{policy_name}: generated native surfaces {sorted(generated)} "
        f"!= contract {sorted(EXPECTED_NATIVE_WALLS[policy_name])}"
    )


def test_expected_native_walls_unknown_policy_raises():
    with pytest.raises(EnforcementMatrixError):
        expected_native_walls("does-not-exist")


@pytest.mark.parametrize("policy_name", sorted(EXPECTED_NATIVE_WALLS))
def test_passing_report_proves_exact_walls(policy_name):
    report = _passing_report(policy_name)
    assert native_walls_proven(report) == set(EXPECTED_NATIVE_WALLS[policy_name])
    assert_enforcement_matrix(policy_name, report)


def test_control_proves_no_native_walls():
    report = _passing_report("control")
    assert native_walls_proven(report) == set()
    assert_enforcement_matrix("control", report)


@pytest.mark.parametrize(
    "policy_name",
    [
        "non-root",
        "low-nist",
        "moderate-nist",
        "high-nist",
        "high-nist",
        "fslock",
    ],
)
def test_missing_wall_raises(policy_name):
    expected = sorted(EXPECTED_NATIVE_WALLS[policy_name])
    dropped = expected[0]
    results = [_native_result(s) for s in expected if s != dropped]
    results.append(_control_result())
    report = _report(policy_name, results)
    with pytest.raises(EnforcementMatrixError) as exc:
        assert_enforcement_matrix(policy_name, report)
    assert dropped in str(exc.value)


def test_extra_wall_fails_control():
    report = _report(
        "control",
        [_native_result("root_password_lock"), _control_result()],
    )
    with pytest.raises(EnforcementMatrixError) as exc:
        assert_enforcement_matrix("control", report)
    assert "root_password_lock" in str(exc.value)


@pytest.mark.parametrize("policy_name", ["low-nist", "high-nist", "netlock"])
def test_failing_probe_raises(policy_name):
    expected = sorted(EXPECTED_NATIVE_WALLS[policy_name])
    failed = expected[0]
    results = [
        _native_result(s, status="fail" if s == failed else "pass") for s in expected
    ]
    results.append(_control_result())
    report = _report(policy_name, results)
    with pytest.raises(DaytonaRuntimeProbeSuiteError):
        assert_enforcement_matrix(policy_name, report)


@pytest.mark.parametrize("policy_name", ["low-nist", "high-nist"])
def test_not_applicable_wall_fails_closed(policy_name):
    expected = sorted(EXPECTED_NATIVE_WALLS[policy_name])
    degraded = expected[0]
    results = [
        _native_result(s, status="not_applicable" if s == degraded else "pass")
        for s in expected
    ]
    results.append(_control_result())
    report = _report(policy_name, results)
    with pytest.raises(EnforcementMatrixError) as exc:
        assert_enforcement_matrix(policy_name, report)
    assert degraded in str(exc.value)


def test_cli_rejects_unknown_policy():
    assert em.main(["--policy", "bogus-preset"]) == 2


def test_cli_requires_policy():
    with pytest.raises(SystemExit):
        em.build_parser().parse_args([])


def test_non_native_enforcement_mode_raises(monkeypatch):
    monkeypatch.setattr(
        em,
        "resolve_policy",
        lambda name: SimpleNamespace(name="legacy-x", enforcement_mode="legacy"),
    )
    with pytest.raises(EnforcementMatrixError):
        em.run_enforcement_probe("legacy-x")


def test_run_enforcement_matrix_all_aggregates_failures(monkeypatch, capsys):
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona.load_terminalbench_daytona_bundle",
        lambda **_: SimpleNamespace(),
    )
    attempted: list[str] = []

    def fake_probe(policy, **_):
        attempted.append(policy)
        if policy == "high-nist":
            raise EnforcementMatrixError("wall-set mismatch on high-nist")
        return SimpleNamespace()

    monkeypatch.setattr(em, "run_enforcement_probe", fake_probe)
    rc = em.run_enforcement_matrix_all()
    out = capsys.readouterr().out
    assert rc == 1
    assert set(attempted) == set(em.EXPECTED_NATIVE_WALLS)
    assert "FAIL high-nist" in out
    assert "PASS control" in out


def test_run_enforcement_matrix_all_passes(monkeypatch):
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona.load_terminalbench_daytona_bundle",
        lambda **_: SimpleNamespace(),
    )
    monkeypatch.setattr(em, "run_enforcement_probe", lambda p, **_: SimpleNamespace())
    assert em.run_enforcement_matrix_all() == 0


def test_cli_all_and_policy_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        em.build_parser().parse_args(["--all", "--policy", "control"])
