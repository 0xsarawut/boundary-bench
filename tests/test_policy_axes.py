from __future__ import annotations

import dataclasses
import json
import re
from importlib.resources import files
from pathlib import Path

import pytest

from boundarybench.daytona.hardening_config import (
    DEFAULT_CIDR_EGRESS_DENYLIST,
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
    DEFAULT_POLICY_BLOCK_MESSAGE,
    DaytonaHardeningConfig,
)
from boundarybench.daytona.runtime_gate_matrix import (
    _STRIP_ENV_VARS,
    _TRUSTED_DOMAIN_ALLOWLIST,
)
from boundarybench.daytona import policy_axes
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    NETWORK_LEVELS,
    PRESETS_BY_TUPLE_ID,
    CANONICAL_INFRA_KEY_ENV_NAMES,
    AxisPreset,
    Filesystem,
    Network,
    Privilege,
    build_daytona_config_from_axes,
    runtime_mappings_for_preset,
    task_egress_domains,
    validate_axis_presets,
)


EXPECTED_NAME_TO_TUPLE_ID = {
    "control": "n0-f0-p0",
    "non-root": "n0-f0-p1",
    "low-nist": "n1-f1-p1",
    "moderate-nist": "n2-f1-p1",
    "high-nist": "n5-f2-p2",
    "netlock": "n2-f0-p1",
    "fslock": "n0-f2-p1",
}

EXPECTED_PRIVILEGE_BOOLS = {
    "control": (False, False, False, False),
    "non-root": (True, False, False, False),
    "low-nist": (True, False, False, False),
    "moderate-nist": (True, False, False, False),
    "high-nist": (True, True, True, True),
    "netlock": (True, False, False, False),
    "fslock": (True, False, False, False),
}

EXPECTED_FILESYSTEM = {
    "control": "open",
    "non-root": "open",
    "low-nist": "workspace",
    "moderate-nist": "workspace",
    "high-nist": "read_only",
    "netlock": "open",
    "fslock": "read_only",
}

EXPECTED_NETWORK = {
    "control": (False, "allow"),
    "non-root": (False, "allow"),
    "low-nist": (True, "deny"),
    "moderate-nist": (True, "deny"),
    "high-nist": (True, "deny"),
    "netlock": (True, "deny"),
    "fslock": (False, "allow"),
}

LEGACY_EMPTY_TUPLE_FIELDS = (
    "denied_exec_paths",
    "denied_command_names",
    "denied_path_exact",
    "denied_path_prefixes",
    "tee_denied_patterns",
    "child_network_command_names",
    "egress_cidr_allowlist",
    "egress_cidr_command_names",
    "seccomp_block_syscalls",
    "egress_domain_denylist",
)

_DOMAIN_RE = re.compile(
    r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)


def _expected_task_egress_map() -> dict[str, list[str]]:
    path = Path(__file__).parent / "fixtures" / "task_egress_allowlists_expected.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _packaged_task_egress_map() -> dict[str, list[str]]:
    path = files("boundarybench.daytona").joinpath(
        "data", "task_egress_allowlists.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {key: value for key, value in payload.items() if key != "_README"}


def _task_runtime_history() -> dict[str, object]:
    path = files("boundarybench.terminalbench").joinpath(
        "data", "task_runtime_history.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))


def _preset(tuple_id: str) -> AxisPreset:
    """Build a throwaway (possibly incoherent) preset from an ``nX-fY-pZ`` id."""
    net, fs, priv = tuple_id.split("-")
    return AxisPreset(
        name=f"test-{tuple_id}",
        tuple_id=tuple_id,
        network=Network[net.upper()],
        filesystem=Filesystem[fs.upper()],
        privilege=Privilege[priv.upper()],
        tier="test",
        nist_story="test preset",
    )


def test_all_eight_presets_present_with_exact_tuple_ids() -> None:
    assert list(AXIS_PRESETS) == list(EXPECTED_NAME_TO_TUPLE_ID)
    for name, tuple_id in EXPECTED_NAME_TO_TUPLE_ID.items():
        assert AXIS_PRESETS[name].tuple_id == tuple_id
        assert AXIS_PRESETS[name].name == name


def test_presets_by_tuple_id_is_exact_inverse() -> None:
    assert set(PRESETS_BY_TUPLE_ID) == set(EXPECTED_NAME_TO_TUPLE_ID.values())
    for name, preset in AXIS_PRESETS.items():
        assert PRESETS_BY_TUPLE_ID[preset.tuple_id] is preset
        assert PRESETS_BY_TUPLE_ID[preset.tuple_id].name == name


def test_tuple_id_matches_enum_triple() -> None:
    for preset in AXIS_PRESETS.values():
        expected = (
            f"{preset.network.value}-{preset.filesystem.value}-{preset.privilege.value}"
        ).lower()
        assert preset.tuple_id == expected


def test_validate_axis_presets_passes_for_shipped_roster() -> None:
    validate_axis_presets()
    validate_axis_presets(AXIS_PRESETS)


def test_validate_rejects_p0_collapse() -> None:
    bad = _preset("n4-f0-p0")
    with pytest.raises(ValueError) as exc:
        validate_axis_presets({bad.name: bad})
    message = str(exc.value)
    assert bad.name in message
    assert "P0" in message


def test_validate_rejects_f2_f3_under_root() -> None:
    bad = _preset("n0-f2-p0")
    with pytest.raises(ValueError) as exc:
        validate_axis_presets({bad.name: bad})
    message = str(exc.value)
    assert bad.name in message
    assert "F2" in message
    assert "non-root" in message


def test_validate_rejects_network_enforcement_under_root() -> None:
    bad = _preset("n1-f0-p0")
    with pytest.raises(ValueError) as exc:
        validate_axis_presets({bad.name: bad})
    message = str(exc.value)
    assert bad.name in message
    assert "N1" in message
    assert "non-root" in message


def test_validate_rejects_unbacked_network_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good_level = NETWORK_LEVELS[Network.N2]
    broken_contribution = dataclasses.replace(
        good_level.contribution,
        native_egress_reject=False,
        egress_allowlist_selector="none",
        egress_domain_default_action="allow",
    )
    broken_level = dataclasses.replace(good_level, contribution=broken_contribution)
    monkeypatch.setitem(NETWORK_LEVELS, Network.N2, broken_level)

    bad = _preset("n2-f0-p1")
    with pytest.raises(ValueError) as exc:
        validate_axis_presets({bad.name: bad})
    message = str(exc.value)
    assert bad.name in message
    assert "native_egress_reject" in message


@pytest.mark.parametrize("name", list(EXPECTED_NAME_TO_TUPLE_ID))
def test_build_config_privilege_fields(name: str) -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS[name])
    actual = (
        config.lock_root_password,
        config.no_new_privs,
        config.drop_bounding_caps,
        config.strip_setuid,
    )
    assert actual == EXPECTED_PRIVILEGE_BOOLS[name]


@pytest.mark.parametrize("name", list(EXPECTED_NAME_TO_TUPLE_ID))
def test_build_config_filesystem_fields(name: str) -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS[name])
    assert config.filesystem_scope == EXPECTED_FILESYSTEM[name]
    assert config.secret_paths_root_owned == ()
    assert config.strip_env_vars == ()


@pytest.mark.parametrize("name", list(EXPECTED_NAME_TO_TUPLE_ID))
def test_build_config_network_fields(name: str) -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS[name])
    reject, default_action = EXPECTED_NETWORK[name]
    assert config.native_egress_reject is reject
    assert config.egress_domain_default_action == default_action


@pytest.mark.parametrize("name", list(EXPECTED_NAME_TO_TUPLE_ID))
def test_build_config_identity_and_message(name: str) -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS[name])
    assert isinstance(config, DaytonaHardeningConfig)
    assert config.name == name
    assert config.block_message is None


def test_block_message_reflects_enforcement_mechanism() -> None:
    """Native presets carry None; legacy default keeps its steering message; a
    None block_message validates and round-trips through metadata as None."""

    for name in EXPECTED_NAME_TO_TUPLE_ID:
        assert build_daytona_config_from_axes(AXIS_PRESETS[name]).block_message is None

    assert DaytonaHardeningConfig().block_message == DEFAULT_POLICY_BLOCK_MESSAGE

    native = DaytonaHardeningConfig(name="native-none", block_message=None)
    native.validate()
    metadata = native.to_metadata()
    assert metadata["block_message"] is None
    assert DaytonaHardeningConfig.from_mapping(metadata) == native
    assert DaytonaHardeningConfig.from_mapping(metadata).block_message is None


@pytest.mark.parametrize("name", list(EXPECTED_NAME_TO_TUPLE_ID))
def test_build_config_leaves_legacy_fields_empty(name: str) -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS[name])
    for field in LEGACY_EMPTY_TUPLE_FIELDS:
        assert getattr(config, field) == (), f"{name}.{field} must stay empty"
    assert config.read_only_root is False


def test_build_config_no_boundary_or_ld_preload_strings() -> None:
    for name in EXPECTED_NAME_TO_TUPLE_ID:
        config = build_daytona_config_from_axes(AXIS_PRESETS[name])
        blob = repr(config.to_metadata())
        assert "BOUNDARY_" not in blob
        assert "LD_PRELOAD" not in blob


def test_low_nist_allowlist_is_trusted_base() -> None:
    config = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"])
    allowlist = config.egress_domain_allowlist
    assert allowlist == _TRUSTED_DOMAIN_ALLOWLIST
    assert len(allowlist) == 205
    assert set(DEFAULT_DOMAIN_EGRESS_ALLOWLIST).issubset(set(allowlist))
    assert config.egress_cidr_denylist == DEFAULT_CIDR_EGRESS_DENYLIST


def test_n1_is_model_plane_plus_trusted_base_plus_task_domains() -> None:
    task_domains = set(task_egress_domains("bn-fit-modify"))
    config = build_daytona_config_from_axes(
        AXIS_PRESETS["low-nist"], task_id="bn-fit-modify"
    )
    allowlist = set(config.egress_domain_allowlist)

    assert set(DEFAULT_DOMAIN_EGRESS_ALLOWLIST).issubset(allowlist)
    assert set(_TRUSTED_DOMAIN_ALLOWLIST).issubset(allowlist)
    assert task_domains.issubset(allowlist)


def test_task_domains_appended_for_n1_and_n2() -> None:
    seeds = {"archive.ubuntu.com", "ports.ubuntu.com", "security.ubuntu.com"}
    task_id = "adaptive-rejection-sampler"

    low = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"], task_id=task_id)
    moderate = build_daytona_config_from_axes(
        AXIS_PRESETS["moderate-nist"], task_id=task_id
    )

    assert seeds.issubset(set(low.egress_domain_allowlist))
    assert seeds.issubset(set(moderate.egress_domain_allowlist))
    assert len(low.egress_domain_allowlist) == 206
    assert len(moderate.egress_domain_allowlist) == 6


def test_unknown_and_none_task_id_yields_base_allowlist() -> None:
    base = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"])
    none_task = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"], task_id=None)
    unknown = build_daytona_config_from_axes(
        AXIS_PRESETS["low-nist"], task_id="does-not-exist"
    )
    assert none_task.egress_domain_allowlist == base.egress_domain_allowlist
    assert unknown.egress_domain_allowlist == base.egress_domain_allowlist
    assert len(base.egress_domain_allowlist) == 205


@pytest.mark.parametrize(
    ("network", "native_reject", "selector", "task_parameterized", "shipped"),
    (
        (Network.N0, False, policy_axes.SELECTOR_NONE, False, True),
        (Network.N1, True, policy_axes.SELECTOR_TRUSTED, True, True),
        (Network.N2, True, policy_axes.SELECTOR_MODEL_PLANE, True, True),
        (Network.N3, True, policy_axes.SELECTOR_MODEL_PLANE, True, False),
        (Network.N4, True, policy_axes.SELECTOR_NONE, True, False),
    ),
)
def test_network_level_selector_contract(
    network: Network,
    native_reject: bool,
    selector: str,
    task_parameterized: bool,
    shipped: bool,
) -> None:
    level = NETWORK_LEVELS[network]
    contribution = level.contribution

    assert contribution.native_egress_reject is native_reject
    assert contribution.egress_allowlist_selector == selector
    assert contribution.task_parameterized is task_parameterized
    assert contribution.egress_domain_default_action == (
        "deny" if native_reject else "allow"
    )
    assert level.shipped is shipped


def test_n5_contribution_disables_task_widening() -> None:
    contribution = NETWORK_LEVELS[Network["N5"]].contribution

    assert contribution.egress_allowlist_selector == policy_axes.SELECTOR_TRUSTED
    assert contribution.task_parameterized is False


@pytest.mark.parametrize(
    ("network", "expected_base"),
    (
        (Network.N0, ()),
        (Network.N1, _TRUSTED_DOMAIN_ALLOWLIST),
        (Network.N2, DEFAULT_DOMAIN_EGRESS_ALLOWLIST),
        (Network.N3, DEFAULT_DOMAIN_EGRESS_ALLOWLIST),
        (Network.N4, ()),
    ),
)
def test_unknown_task_base_is_pinned_for_every_network_level(
    network: Network,
    expected_base: tuple[str, ...],
) -> None:
    config = build_daytona_config_from_axes(
        _preset(f"{network.value.lower()}-f0-p1"),
        task_id="does-not-exist",
    )

    assert config.egress_domain_allowlist == expected_base


def test_n3_is_reserved_without_stronger_network_assurance_claims() -> None:
    n2 = NETWORK_LEVELS[Network.N2]
    n3 = NETWORK_LEVELS[Network.N3]

    assert n3.shipped is False
    assert n3.nist_citations == n2.nist_citations
    assert "SC-7(18)" not in n3.nist_citations
    assert "SC-7(21)" not in n3.nist_citations


def test_n2_allowlist_is_subset_of_n1_for_same_task() -> None:
    task_id = "adaptive-rejection-sampler"
    low = set(
        build_daytona_config_from_axes(
            AXIS_PRESETS["low-nist"], task_id=task_id
        ).egress_domain_allowlist
    )
    for name in ("moderate-nist", "high-nist", "netlock"):
        n2 = set(
            build_daytona_config_from_axes(
                AXIS_PRESETS[name], task_id=task_id
            ).egress_domain_allowlist
        )
        assert n2.issubset(low), f"{name} allowlist must be a subset of low-nist"


def test_high_nist_uses_fixed_trusted_allowlist() -> None:
    task_id = "adaptive-rejection-sampler"
    base = build_daytona_config_from_axes(AXIS_PRESETS["high-nist"])
    parameterized = build_daytona_config_from_axes(
        AXIS_PRESETS["high-nist"], task_id=task_id
    )

    assert base.egress_domain_allowlist == _TRUSTED_DOMAIN_ALLOWLIST
    assert len(base.egress_domain_allowlist) == 205
    assert set(DEFAULT_DOMAIN_EGRESS_ALLOWLIST).issubset(
        base.egress_domain_allowlist
    )
    assert parameterized.egress_domain_allowlist == base.egress_domain_allowlist


def test_runtime_mappings_agree_with_config_for_high_nist() -> None:
    preset = AXIS_PRESETS["high-nist"]
    config = build_daytona_config_from_axes(preset)
    mappings = runtime_mappings_for_preset(preset)
    by_surface = {m.surface: m for m in mappings}

    assert "read_only_root_filesystem" in by_surface
    assert config.filesystem_scope == "read_only"

    egress = by_surface["domain_egress_policy"]
    assert config.egress_domain_default_action in egress.values

    assert "capability_bounding_drop" in by_surface
    assert config.drop_bounding_caps is True
    assert "no_new_privileges" in by_surface
    assert config.no_new_privs is True
    assert "setuid_bit_strip" in by_surface
    assert config.strip_setuid is True


def test_runtime_mappings_carry_axis_nist_citations() -> None:
    mappings = runtime_mappings_for_preset(AXIS_PRESETS["high-nist"])
    by_surface = {m.surface: m for m in mappings}
    assert "AC-4(4)" in by_surface["read_only_root_filesystem"].nist_refs
    assert "AC-6(3)" in by_surface["capability_bounding_drop"].nist_refs


def test_control_preset_emits_no_native_mappings() -> None:
    assert runtime_mappings_for_preset(AXIS_PRESETS["control"]) == ()


def test_task_egress_registry_matches_exact_contract() -> None:
    assert _packaged_task_egress_map() == _expected_task_egress_map()
    assert len(_expected_task_egress_map()) == 36


def test_task_egress_registry_is_normalized_and_in_inventory() -> None:
    history = _task_runtime_history()
    inventory = set(history["median_runtime_seconds"])
    for task_id, domains in _expected_task_egress_map().items():
        assert task_id in inventory
        assert domains
        assert domains == sorted(set(domains))
        assert all(domain == domain.lower() for domain in domains)
        assert all(_DOMAIN_RE.fullmatch(domain) for domain in domains)


def test_task_egress_domains_seed_entry() -> None:
    assert task_egress_domains("adaptive-rejection-sampler") == (
        "archive.ubuntu.com",
        "ports.ubuntu.com",
        "security.ubuntu.com",
    )


def test_task_egress_domains_none_and_unknown() -> None:
    assert task_egress_domains(None) == ()
    assert task_egress_domains("no-such-task") == ()
    assert task_egress_domains("_README") == ()


def test_canonical_infrastructure_env_name_constant_replaces_real_key_name() -> None:
    assert hasattr(policy_axes, "CANONICAL_INFRA_KEY_ENV_NAMES")
    assert not hasattr(policy_axes, "REAL_INFRA_KEY_ENV_VARS")


def test_canonical_infra_names_seed_from_strip_env_plus_additions() -> None:
    assert set(_STRIP_ENV_VARS).issubset(set(CANONICAL_INFRA_KEY_ENV_NAMES))
    for added in (
        "ANTHROPIC_API_KEY",
        "GH_TOKEN",
        "HF_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        assert added in CANONICAL_INFRA_KEY_ENV_NAMES


def test_credential_path_surface_is_conditional_not_a_ladder_level() -> None:
    labels = {level.label for level in policy_axes.FILESYSTEM_LEVELS.values()}
    assert labels == {"open", "workspace", "read_only"}
    for level in policy_axes.FILESYSTEM_LEVELS.values():
        assert level.enforcement_status == "enforced"
        assert "IA-5" not in level.nist_citations
    assert policy_axes.CREDENTIAL_PATH_SURFACE_NIST == (
        "AC-6(2)",
        "IA-5",
        "SC-28",
        "AC-2",
        "AC-5",
    )


def test_level_metadata_enforcement_and_shipped_flags() -> None:
    assert NETWORK_LEVELS[Network.N4].shipped is False
    assert NETWORK_LEVELS[Network.N0].shipped is True
    for preset in AXIS_PRESETS.values():
        assert NETWORK_LEVELS[preset.network].enforcement_status == "enforced"


def test_level_native_errors_are_bare_native_strings() -> None:
    assert "EROFS" in policy_axes.FILESYSTEM_LEVELS[Filesystem.F2].native_error
    assert "403" in NETWORK_LEVELS[Network.N1].native_error
    assert "sudoers" in policy_axes.PRIVILEGE_LEVELS[Privilege.P1].native_error
    for registry in (
        NETWORK_LEVELS,
        policy_axes.FILESYSTEM_LEVELS,
        policy_axes.PRIVILEGE_LEVELS,
    ):
        for level in registry.values():
            assert "BOUNDARY_" not in level.native_error
            assert "BOUNDARY_" not in level.native_mechanism
