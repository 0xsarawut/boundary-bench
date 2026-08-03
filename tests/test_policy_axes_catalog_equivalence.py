"""Strict axes<->catalog equivalence gate (the drift-killer).

For every one of the 8 native presets this asserts that the catalog compiler
faithfully round-trips ``runtime_mappings_for_preset(preset)`` back to the same
native fields ``build_daytona_config_from_axes(preset)`` produces. Both
generators read the SAME per-level ``ConfigContribution`` in ``policy_axes`` and
this test feeds the emitted mappings through the *catalog compiler* — so it
proves catalog CLAIMS can never ship ahead of native ENFORCEMENT.

The exception set is empty: every emitted surface must correspond to an active
config field, and every value-carrying surface's values must match the config.
The single documented lossy point is ``filesystem_scope`` — F1 (``guarded``)
emits no scope-bearing surface, so the compiler cannot distinguish it from F0
(``open``). That is asserted explicitly, not whitelisted away.
"""

from __future__ import annotations

from typing import Any

import pytest

from boundarybench.daytona.hardening_config import DEFAULT_CIDR_EGRESS_DENYLIST
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    _resolve_domain_allowlist,
    build_daytona_config_from_axes,
    runtime_mappings_for_preset,
)
from boundarybench.policy_catalog.catalog.capabilities import (
    SUPPORTED_DAYTONA_SURFACES,
)
from boundarybench.policy_catalog.catalog.compiler_contract import (
    _apply_supported_mapping,
)

PRESET_NAMES = tuple(AXIS_PRESETS)

_NATIVE_SURFACES = frozenset(
    {
        "native_egress_reject",
        "domain_egress_policy",
        "cidr_egress_denylist",
        "writable_path_carveout_prefix",
        "read_only_root_filesystem",
        "root_password_lock",
        "no_new_privileges",
        "capability_bounding_drop",
        "setuid_bit_strip",
    }
)


def _fresh_hardening_config() -> dict[str, Any]:
    """A hardening_config dict pre-seeded with every key the native surfaces
    mutate, mirroring the compiler's init so ``_apply_supported_mapping`` can run
    in isolation without a full pack compile."""
    return {
        "egress_domain_allowlist": [],
        "egress_domain_default_action": "allow",
        "egress_cidr_denylist": [],
        "strip_env_vars": [],
        "native_egress_reject": False,
        "filesystem_scope": "open",
        "writable_path_prefixes": [],
        "secret_paths_root_owned": [],
        "lock_root_password": False,
        "no_new_privs": False,
        "drop_bounding_caps": False,
        "strip_setuid": False,
    }


def _expected_surface_set(config: Any) -> set[str]:
    """The set of native surfaces implied by a config's active mechanisms,
    derived INDEPENDENTLY from the config fields (not from the mappings) so
    drift in either direction is caught."""
    expected: set[str] = set()
    if config.native_egress_reject:
        expected.add("native_egress_reject")
        expected.add("domain_egress_policy")
        if config.egress_cidr_denylist:
            expected.add("cidr_egress_denylist")
    if config.filesystem_scope in ("workspace", "read_only"):
        expected.add("writable_path_carveout_prefix")
    if config.filesystem_scope == "read_only":
        expected.add("read_only_root_filesystem")
    if config.lock_root_password:
        expected.add("root_password_lock")
    if config.no_new_privs:
        expected.add("no_new_privileges")
    if config.drop_bounding_caps:
        expected.add("capability_bounding_drop")
    if config.strip_setuid:
        expected.add("setuid_bit_strip")
    return expected


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_emitted_surface_is_a_supported_compiler_surface(preset_name: str) -> None:
    mappings = runtime_mappings_for_preset(AXIS_PRESETS[preset_name])
    for mapping in mappings:
        assert mapping.surface in SUPPORTED_DAYTONA_SURFACES, mapping.surface


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_applying_preset_mappings_raises_nothing(preset_name: str) -> None:
    hardening_config = _fresh_hardening_config()
    execution: dict[str, Any] = {"agent_user": "root", "overlays": []}
    for mapping in runtime_mappings_for_preset(AXIS_PRESETS[preset_name]):
        _apply_supported_mapping(
            mapping.surface, mapping.values, hardening_config, execution
        )


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_no_spurious_surfaces(preset_name: str) -> None:
    preset = AXIS_PRESETS[preset_name]
    config = build_daytona_config_from_axes(preset)
    emitted = {m.surface for m in runtime_mappings_for_preset(preset)}
    assert emitted == _expected_surface_set(config)


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_per_surface_correspondence(preset_name: str) -> None:
    preset = AXIS_PRESETS[preset_name]
    config = build_daytona_config_from_axes(preset)
    by_surface = {m.surface: m.values for m in runtime_mappings_for_preset(preset)}

    assert ("native_egress_reject" in by_surface) == bool(config.native_egress_reject)
    if "domain_egress_policy" in by_surface:
        default_action, selector = by_surface["domain_egress_policy"]
        assert config.egress_domain_default_action == default_action
        assert config.egress_domain_allowlist == _resolve_domain_allowlist(selector, ())
    else:
        assert config.egress_domain_default_action == "allow"
    assert ("cidr_egress_denylist" in by_surface) == bool(config.egress_cidr_denylist)
    if "cidr_egress_denylist" in by_surface:
        assert config.egress_cidr_denylist == DEFAULT_CIDR_EGRESS_DENYLIST

    assert ("writable_path_carveout_prefix" in by_surface) == (
        config.filesystem_scope in ("workspace", "read_only")
    )
    if "writable_path_carveout_prefix" in by_surface:
        assert by_surface["writable_path_carveout_prefix"] == config.writable_path_prefixes
    assert ("read_only_root_filesystem" in by_surface) == (
        config.filesystem_scope == "read_only"
    )
    assert config.secret_paths_root_owned == ()
    assert config.strip_env_vars == ()
    assert "secret_path_root_owned" not in by_surface
    assert "honeytoken_env_strip" not in by_surface

    assert ("root_password_lock" in by_surface) == bool(config.lock_root_password)
    assert ("no_new_privileges" in by_surface) == bool(config.no_new_privs)
    assert ("capability_bounding_drop" in by_surface) == bool(config.drop_bounding_caps)
    assert ("setuid_bit_strip" in by_surface) == bool(config.strip_setuid)


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_compiler_round_trips_mappings_back_to_config_fields(preset_name: str) -> None:
    """The compiler, fed the preset's mappings, reproduces the config's native
    fields. filesystem_scope is the single documented lossy field: F1
    (``guarded``) collapses to ``open`` because it emits no scope surface."""
    preset = AXIS_PRESETS[preset_name]
    config = build_daytona_config_from_axes(preset)
    hardening_config = _fresh_hardening_config()
    execution: dict[str, Any] = {"agent_user": "root", "overlays": []}
    for mapping in runtime_mappings_for_preset(preset):
        _apply_supported_mapping(
            mapping.surface, mapping.values, hardening_config, execution
        )

    assert hardening_config["native_egress_reject"] == config.native_egress_reject
    assert tuple(hardening_config["egress_domain_allowlist"]) == config.egress_domain_allowlist
    assert hardening_config["egress_domain_default_action"] == config.egress_domain_default_action
    assert tuple(hardening_config["egress_cidr_denylist"]) == config.egress_cidr_denylist
    assert tuple(hardening_config["writable_path_prefixes"]) == config.writable_path_prefixes
    assert tuple(hardening_config["secret_paths_root_owned"]) == config.secret_paths_root_owned
    assert tuple(hardening_config["strip_env_vars"]) == config.strip_env_vars
    assert hardening_config["lock_root_password"] == config.lock_root_password
    assert hardening_config["no_new_privs"] == config.no_new_privs
    assert hardening_config["drop_bounding_caps"] == config.drop_bounding_caps
    assert hardening_config["strip_setuid"] == config.strip_setuid

    expected_scope = (
        "open" if config.filesystem_scope == "guarded" else config.filesystem_scope
    )
    assert hardening_config["filesystem_scope"] == expected_scope
