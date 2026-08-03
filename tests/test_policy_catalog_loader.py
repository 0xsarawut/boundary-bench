from boundarybench.policy_catalog import (
    DAYTONA_HARDENING_V1,
    list_policy_pack_ids,
    list_runtime_targets,
    load_policy_pack,
    validate_policy_pack,
)


def test_loads_canonical_policy_pack_fixture():
    pack = load_policy_pack("boundary-contract-fixtures")

    assert pack.catalog_schema_version == 1
    assert pack.pack_id == "boundary-contract-fixtures"
    assert pack.source.framework == "native/boundary"
    assert pack.policies[0].policy_id == "contract-smoke-enterprise-shape"
    assert pack.policies[0].variants[0].fidelity == "runtime_enforced_partial"
    assert validate_policy_pack(pack).passed is True


def test_lists_canonical_policy_packs_and_runtime_targets():
    assert set(list_policy_pack_ids()) == {
        "boundary-contract-fixtures",
        "boundary-native",
        "nist-linux-security",
    }

    targets = list_runtime_targets()

    assert targets[0].target == DAYTONA_HARDENING_V1
    assert "command_name_denial" in targets[0].supported_surfaces
    assert "denied_path_exact" in targets[0].supported_surfaces
    assert "seccomp_syscall_policy" in targets[0].supported_surfaces
    assert "domain_egress_policy" in targets[0].supported_surfaces
    assert "domain_egress_policy" not in targets[0].unsupported_surfaces
    assert "seccomp_syscall_policy" not in targets[0].unsupported_surfaces
    assert "operation_specific_path_mode_policy" in targets[0].unsupported_surfaces


def test_loads_nist_catalog_as_source_derived_partial():
    pack = load_policy_pack("nist-linux-security")
    variant = pack.policies[0].variants[0]
    policy_ids = {policy.policy_id for policy in pack.policies}

    assert pack.source.upstream_commit == "671b07e07ec800f03c3bf94b873299f4d71c9b0f"
    assert "nist-linux-80053-high-derived" in policy_ids
    assert "nist-linux-80053-low" in policy_ids
    assert "nist-linux-80053-medium" in policy_ids
    assert "nist-linux-80053-high" in policy_ids
    assert variant.fidelity == "source_derived_partial"
    assert validate_policy_pack(pack).passed is True
    assert any(
        mapping.surface == "domain_egress_policy" and mapping.status == "unsupported"
        for rule in variant.rules
        for mapping in rule.runtime_mappings
    )


def test_loads_nist_runtime_variant_as_runtime_enforced_partial():
    pack = load_policy_pack("nist-linux-security")
    policy = next(
        candidate
        for candidate in pack.policies
        if candidate.policy_id == "nist-linux-80053-high"
    )
    variant = next(
        candidate
        for candidate in policy.variants
        if candidate.variant_id == "nist-linux-80053-high-daytona-v1"
    )

    assert policy.title == "NIST-derived High benchmark policy"
    assert variant.fidelity == "runtime_enforced_partial"
    assert any(
        mapping.surface == "command_name_denial" and mapping.status == "enforced"
        for rule in variant.rules
        for mapping in rule.runtime_mappings
    )
    assert any(
        mapping.surface == "domain_egress_policy" and mapping.status == "enforced"
        for rule in variant.rules
        for mapping in rule.runtime_mappings
    )


def test_nist_runtime_variant_disposition_counts_match_mappings():
    pack = load_policy_pack("nist-linux-security")
    for policy_id, variant_id in (
        ("nist-linux-80053-high", "nist-linux-80053-high-daytona-v1"),
        ("nist-linux-80053-medium", "nist-linux-80053-medium-daytona-v1"),
        ("nist-linux-80053-low", "nist-linux-80053-low-daytona-v1"),
    ):
        policy = next(
            candidate for candidate in pack.policies if candidate.policy_id == policy_id
        )
        variant = next(
            candidate
            for candidate in policy.variants
            if candidate.variant_id == variant_id
        )
        actual_counts = {
            "enforced": 0,
            "approximate": 0,
            "unsupported": 0,
            "representation_only": 0,
            "deferred": 0,
        }
        for rule in variant.rules:
            for mapping in rule.runtime_mappings:
                actual_counts[mapping.status] += 1

        expected_status_counts = {
            "denominator": "selected_runtime_mapping_items_in_this_variant"
        } | actual_counts
        expected_disposition_counts = {
            "denominator": "selected_runtime_mapping_items_in_this_variant",
            "enforced": actual_counts["enforced"],
            "approximated": actual_counts["approximate"],
            "metadata_only": 0,
            "monitoring_only": 0,
            "representation_only": actual_counts["representation_only"],
            "unsupported": actual_counts["unsupported"],
            "deferred": actual_counts["deferred"],
            "not_relevant_to_daytona": 0,
        }

        assert policy.metadata["compile_status_counts"] == expected_status_counts
        assert variant.metadata["compile_status_counts"] == expected_status_counts
        assert (
            policy.metadata["coverage_disposition_counts"]
            == expected_disposition_counts
        )
        assert (
            variant.metadata["coverage_disposition_counts"]
            == expected_disposition_counts
        )
