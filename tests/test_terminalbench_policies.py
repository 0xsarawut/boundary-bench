from __future__ import annotations

import pytest

from boundarybench.benchmarks.common.policies import (
    resolve_run_policy as resolve_common_run_policy,
)
from boundarybench.daytona.policy_axes import AXIS_PRESETS
from boundarybench.terminalbench.policies import (
    DEBUG_POLICY_OPT_IN_ENV,
    DEFAULT_POLICY_NAME,
    POLICIES,
    HardeningPolicy,
    resolve_policy,
    resolve_policy_for_run,
)


_EXPECTED_PRESET_NAMES = {
    "control",
    "non-root",
    "low-nist",
    "moderate-nist",
    "high-nist",
    "high-nist",
    "netlock",
    "fslock",
}


def test_control_is_the_default_native_policy():
    assert DEFAULT_POLICY_NAME == "control"
    p = resolve_policy(None)
    assert p.name == "control"
    assert p.agent_user == "root"
    assert p.run_agent_as_root is True
    assert p.enforcement_mode == "native"
    assert p.overlays == ()


def test_registry_exposes_exactly_the_eight_axis_presets():
    assert set(AXIS_PRESETS) == _EXPECTED_PRESET_NAMES
    assert _EXPECTED_PRESET_NAMES == set(POLICIES)

    for name in AXIS_PRESETS:
        policy = resolve_policy(name)
        assert policy.name == name
        assert policy.enforcement_mode == "native"

    assert len(POLICIES) == len(AXIS_PRESETS)


def test_tuple_ids_are_not_resolvable():
    for tuple_id in ("n1-f1-p1", "n2-f1-p1", "n5-f2-p2", "n0-f0-p0", "n2-f2-p2"):
        with pytest.raises(ValueError, match="unknown hardening policy"):
            resolve_policy(tuple_id)


def test_axis_presets_carry_native_enforcement_and_expected_agent_user():
    assert POLICIES["low-nist"].enforcement_mode == "native"
    assert POLICIES["control"].agent_user == "root"
    assert POLICIES["low-nist"].agent_user == "daytona"
    for name, preset in AXIS_PRESETS.items():
        expected_user = "root" if name == "control" else "daytona"
        assert POLICIES[name].agent_user == expected_user


def test_axis_presets_are_native_with_no_overlays_or_unsupported_surfaces():
    for name in AXIS_PRESETS:
        p = POLICIES[name]
        assert p.enforcement_mode == "native"
        assert p.overlays == ()
        assert p.unsupported_surfaces == ()
        assert p.runtime_probe_scope == "all"
        assert p.debug_only is False
        assert p.agentsh_policy_config is None
        assert p.block_child_shell_network is False
        assert p.description


def test_control_preset_is_unhardened_root_baseline():
    p = resolve_policy("control")
    assert p.name == "control"
    assert p.agent_user == "root"
    assert p.run_agent_as_root is True
    assert p.config.native_egress_reject is False
    assert p.config.egress_domain_allowlist == ()
    assert p.config.lock_root_password is False
    assert p.config.denied_command_names == ()
    assert p.config.denied_exec_paths == ()


def test_low_nist_preset_wires_native_network_privilege_filesystem():
    p = resolve_policy("low-nist")
    assert p.agent_user == "daytona"
    assert p.config.native_egress_reject is True
    assert p.config.egress_domain_default_action == "deny"
    assert p.config.egress_domain_allowlist
    assert p.config.lock_root_password is True
    assert p.config.secret_paths_root_owned == ()
    assert p.config.strip_env_vars == ()
    assert p.config.denied_command_names == ()
    assert p.config.denied_exec_paths == ()


def test_high_nist_preset_is_full_lockdown():
    p = resolve_policy("high-nist")
    assert p.agent_user == "daytona"
    assert p.config.native_egress_reject is True
    assert p.config.filesystem_scope == "read_only"
    assert p.config.no_new_privs is True
    assert p.config.drop_bounding_caps is True
    assert p.config.strip_setuid is True


def test_applies_hardening_is_false_only_for_the_unhardened_control_cell():
    assert POLICIES["control"].applies_hardening is False
    for name in (
        "non-root",
        "low-nist",
        "moderate-nist",
        "high-nist",
        "high-nist",
        "netlock",
        "fslock",
    ):
        assert POLICIES[name].applies_hardening is True, name


def test_applies_hardening_falls_back_to_overlays_for_legacy_policies():
    control_config = resolve_policy("control").config
    legacy_bare = HardeningPolicy(name="legacy-bare", config=control_config)
    assert legacy_bare.enforcement_mode == "legacy"
    assert legacy_bare.applies_hardening is False
    legacy_overlaid = HardeningPolicy(
        name="legacy-overlaid",
        config=control_config,
        overlays=("nonroot-agent",),
    )
    assert legacy_overlaid.applies_hardening is True


def test_common_run_policy_resolves_nist_medium_and_low():
    medium = resolve_common_run_policy("nist-linux-80053-medium")
    low = resolve_common_run_policy("nist-linux-80053-low")

    assert medium.name == "nist-linux-80053-medium"
    assert medium.applies_hardening is True
    assert medium.hardening_config is not None
    assert medium.hardening_config.name == "gate-trusted-change-controlled"
    assert low.name == "nist-linux-80053-low"
    assert low.applies_hardening is True
    assert low.hardening_config is not None
    assert low.hardening_config.name == "gate-trusted-workspace-dev"


def test_hardening_policy_defaults_to_legacy_enforcement_mode():
    policy = HardeningPolicy(name="x", config=resolve_policy("control").config)
    assert policy.enforcement_mode == "legacy"


def test_hardening_policy_accepts_native_enforcement_mode():
    policy = HardeningPolicy(
        name="native-x",
        config=resolve_policy("control").config,
        enforcement_mode="native",
    )
    assert policy.enforcement_mode == "native"


def test_hardening_policy_rejects_unknown_enforcement_mode():
    with pytest.raises(ValueError, match="enforcement_mode"):
        HardeningPolicy(
            name="bad-mode",
            config=resolve_policy("control").config,
            enforcement_mode="hybrid",
        )


def test_resolve_policy_for_run_allows_every_axis_preset_without_debug_optin(
    monkeypatch,
):
    monkeypatch.delenv(DEBUG_POLICY_OPT_IN_ENV, raising=False)
    for name in AXIS_PRESETS:
        assert resolve_policy_for_run(name).name == name


def test_resolve_unknown_policy_raises_with_known_names():
    with pytest.raises(ValueError, match="unknown hardening policy"):
        resolve_policy("does-not-exist")


def test_removed_policy_names_are_rejected():
    removed = (
        "none",
        "nonroot",
        "basic-only",
        "nist-linux-80053-low",
        "nist-linux-80053-medium",
        "nist-linux-80053-high",
        "gate-offline-tools-read-only",
        "gate-trusted-change-controlled",
        "gate-trusted-workspace-dev",
        "default",
        "enterprise-1",
    )
    for removed_policy in removed:
        assert removed_policy not in POLICIES
        with pytest.raises(ValueError, match="unknown hardening policy"):
            resolve_policy(removed_policy)
