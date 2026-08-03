"""The generated ``boundary-native`` catalog pack.

Guards that the committed ``pack.yaml`` stays in lock-step with its generator
(``build_native_policy_pack``), validates through the pack loader, and — the
pack-level drift-killer — that each policy compiles back to exactly the native
config ``build_daytona_config_from_axes`` produces for the same preset.
"""

from __future__ import annotations

import pytest

from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
    runtime_mappings_for_preset,
)
from boundarybench.policy_catalog import (
    list_policy_pack_ids,
    load_policy_pack,
    validate_policy_pack,
)
from boundarybench.policy_catalog.catalog import compile_policy_variant_from_pack
from boundarybench.policy_catalog.native_pack import (
    NATIVE_PACK_ID,
    build_native_policy_pack,
    native_variant_id,
)

_ENFORCING_PRESETS = tuple(
    name for name, preset in AXIS_PRESETS.items() if runtime_mappings_for_preset(preset)
)


def test_native_pack_is_registered() -> None:
    assert NATIVE_PACK_ID in list_policy_pack_ids()


def test_committed_pack_is_up_to_date_with_generator() -> None:
    committed = load_policy_pack(NATIVE_PACK_ID)
    generated = build_native_policy_pack()
    assert committed.to_dict() == generated.to_dict()


def test_native_pack_validates() -> None:
    assert validate_policy_pack(load_policy_pack(NATIVE_PACK_ID)).passed


def test_native_pack_covers_exactly_the_enforcing_presets() -> None:
    pack = load_policy_pack(NATIVE_PACK_ID)
    policy_ids = {policy.policy_id for policy in pack.policies}
    assert "control" not in policy_ids
    assert policy_ids == set(_ENFORCING_PRESETS)


@pytest.mark.parametrize("preset_name", _ENFORCING_PRESETS)
def test_each_native_policy_compiles_back_to_its_config(preset_name: str) -> None:
    pack = load_policy_pack(NATIVE_PACK_ID)
    config = build_daytona_config_from_axes(AXIS_PRESETS[preset_name])
    result = compile_policy_variant_from_pack(
        pack=pack,
        policy_id=preset_name,
        variant_id=native_variant_id(preset_name),
    )
    hc = result.plan.hardening_config

    assert hc["native_egress_reject"] == config.native_egress_reject
    assert tuple(hc["egress_domain_allowlist"]) == config.egress_domain_allowlist
    assert hc["egress_domain_default_action"] == config.egress_domain_default_action
    assert tuple(hc["egress_cidr_denylist"]) == config.egress_cidr_denylist
    assert tuple(hc["writable_path_prefixes"]) == config.writable_path_prefixes
    assert tuple(hc["secret_paths_root_owned"]) == config.secret_paths_root_owned
    assert tuple(hc["strip_env_vars"]) == config.strip_env_vars
    assert hc["lock_root_password"] == config.lock_root_password
    assert hc["no_new_privs"] == config.no_new_privs
    assert hc["drop_bounding_caps"] == config.drop_bounding_caps
    assert hc["strip_setuid"] == config.strip_setuid

    expected_scope = (
        "open" if config.filesystem_scope == "guarded" else config.filesystem_scope
    )
    assert hc["filesystem_scope"] == expected_scope
