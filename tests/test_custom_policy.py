from __future__ import annotations

import pytest

from boundarybench.daytona.hardening_config import DEFAULT_DOMAIN_EGRESS_ALLOWLIST
from boundarybench.terminalbench.custom_policy import (
    EGRESS_CUSTOM,
    EGRESS_TASK_ONLY,
    SURFACE_KEYS,
    CustomPolicyError,
    applies_hardening,
    compile_custom_policy,
    normalize_surface_keys,
)


def test_empty_selection_compiles_to_control():
    compiled = compile_custom_policy("")
    assert compiled.policy_id == "control"
    assert compiled.surfaces == ()
    assert compiled.policy.agent_user == "root"
    assert applies_hardening("") is False


def test_prerequisites_are_added_automatically():
    compiled = compile_custom_policy("freeze-home")
    assert compiled.surfaces == ("freeze-home", "non-root", "readonly-os")
    assert set(compiled.added_for_coherence) == {"non-root", "readonly-os"}
    assert compiled.policy.agent_user == "daytona"
    assert compiled.policy.config.filesystem_scope == "read_only"


def test_network_hardening_forces_non_root():
    compiled = compile_custom_policy("restrict-egress")
    assert "non-root" in compiled.surfaces
    assert "non-root" in compiled.added_for_coherence
    assert compiled.policy.config.native_egress_reject is True
    assert compiled.policy.config.egress_domain_default_action == "deny"


def test_no_escalation_implies_full_privilege_lockdown():
    compiled = compile_custom_policy("no-escalation")
    assert "non-root" in compiled.surfaces
    assert compiled.policy.agent_user == "daytona"


def test_policy_id_is_surface_based_and_order_independent():
    a = compile_custom_policy("restrict-egress,non-root,readonly-os")
    b = compile_custom_policy("readonly-os,restrict-egress")
    assert a.policy_id == b.policy_id == "custom:non-root+readonly-os+restrict-egress"


def test_custom_egress_includes_model_plane_and_user_domains():
    compiled = compile_custom_policy(
        "restrict-egress",
        egress_mode=EGRESS_CUSTOM,
        egress_domains="pypi.org, files.pythonhosted.org",
    )
    allowlist = compiled.policy.config.egress_domain_allowlist
    for model_domain in DEFAULT_DOMAIN_EGRESS_ALLOWLIST:
        assert model_domain in allowlist
    assert "pypi.org" in allowlist
    assert "files.pythonhosted.org" in allowlist


def test_custom_egress_requires_at_least_one_domain():
    with pytest.raises(CustomPolicyError, match="bring your own"):
        compile_custom_policy(
            "restrict-egress", egress_mode=EGRESS_CUSTOM, egress_domains=""
        )


def test_task_only_egress_drops_the_curated_list():
    trusted = compile_custom_policy("restrict-egress")
    task_only = compile_custom_policy("restrict-egress", egress_mode=EGRESS_TASK_ONLY)
    assert len(task_only.policy.config.egress_domain_allowlist) < len(
        trusted.policy.config.egress_domain_allowlist
    )
    for model_domain in DEFAULT_DOMAIN_EGRESS_ALLOWLIST:
        assert model_domain in task_only.policy.config.egress_domain_allowlist


def test_unknown_surface_is_rejected():
    with pytest.raises(CustomPolicyError, match="unknown hardening surface"):
        compile_custom_policy("make-it-secure")


def test_unknown_egress_mode_is_rejected():
    with pytest.raises(CustomPolicyError, match="unknown egress mode"):
        compile_custom_policy("restrict-egress", egress_mode="whatever")


def test_normalize_accepts_iterable_and_string():
    assert normalize_surface_keys("non-root, readonly-os") == [
        "non-root",
        "readonly-os",
    ]
    assert normalize_surface_keys(["restrict-egress"]) == ["restrict-egress"]


def test_every_catalog_surface_compiles():
    compiled = compile_custom_policy(",".join(SURFACE_KEYS))
    assert set(compiled.surfaces) == set(SURFACE_KEYS)
    assert compiled.policy.agent_user == "daytona"
    assert compiled.policy.config.native_egress_reject is True
