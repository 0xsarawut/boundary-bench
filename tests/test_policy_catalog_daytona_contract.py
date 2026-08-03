import pytest

from boundarybench.policy_catalog import (
    CATALOG_SCHEMA_VERSION,
    DAYTONA_HARDENING_V1,
    FidelityLevel,
    MappingStatus,
    PolicyDefinition,
    PolicyPack,
    PolicyRule,
    PolicyVariant,
    RuntimeMapping,
    RuntimeTargetBinding,
    SourceProvenance,
    compile_policy_variant,
    list_runtime_targets,
    load_policy_pack,
    validate_policy_pack,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)
from boundarybench.policy_catalog.catalog import compile_policy_variant_from_pack
from boundarybench.policy_catalog.catalog.capabilities import (
    UNSUPPORTED_DAYTONA_SURFACES,
)
from boundarybench.policy_catalog.cli import compile_main, validate_main


_FILESYSTEM_SCOPE_RANK = {
    "open": 0,
    "guarded": 1,
    "workspace": 2,
    "read_only": 3,
}


def _active_privilege_bools(config) -> frozenset[str]:
    active = {
        "lock_root_password": config.lock_root_password,
        "no_new_privs": config.no_new_privs,
        "drop_bounding_caps": config.drop_bounding_caps,
        "strip_setuid": config.strip_setuid,
    }
    return frozenset(name for name, on in active.items() if on)


NIST_RUNTIME_VARIANTS = (
    ("nist-linux-80053-high", "nist-linux-80053-high-daytona-v1"),
    ("nist-linux-80053-medium", "nist-linux-80053-medium-daytona-v1"),
    ("nist-linux-80053-low", "nist-linux-80053-low-daytona-v1"),
)
AGENTSH_POLICY_TARGET = "agentsh-policy-v1"


def test_compiles_contract_fixture_to_daytona_hardening_v1():
    result = compile_policy_variant(
        pack_id="boundary-contract-fixtures",
        policy_id="contract-smoke-enterprise-shape",
        variant_id="daytona-smoke-v1",
    )
    payload = result.to_dict()
    plan = payload["plan"]

    assert plan["target"] == "daytona-hardening-v1"
    assert plan["catalog_schema_version"] == 1
    assert len(plan["source_digest"]) == 64
    assert plan["execution"]["agent_user"] == "daytona"
    assert plan["execution"]["block_child_shell_network"] is True
    assert "curl" in plan["hardening_config"]["denied_command_names"]
    assert "/usr/bin/sudo" in plan["hardening_config"]["denied_exec_paths"]
    assert "/etc/shadow" in plan["hardening_config"]["denied_path_exact"]
    assert "OPENROUTER_API_KEY" in plan["hardening_config"]["strip_env_vars"]
    assert any(
        feature["surface"] == "domain_egress_policy"
        for feature in plan["unsupported_features"]
    )


def test_compiling_nist_fixture_keeps_unsupported_diagnostics():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-high-derived",
        variant_id="high-derived-daytona-contract-v1",
    )

    assert result.plan.fidelity == "source_derived_partial"
    assert result.plan.hardening_config["denied_command_names"] == []
    assert any(
        diagnostic.surface == "domain_egress_policy"
        and diagnostic.status == "unsupported"
        for diagnostic in result.diagnostics
    )
    assert any(
        diagnostic.surface == "command_name_denial"
        and diagnostic.status == "approximate"
        for diagnostic in result.diagnostics
    )


def test_compiling_nist_runtime_variant_emits_enforced_daytona_fields():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-high",
        variant_id="nist-linux-80053-high-daytona-v1",
    )

    assert result.plan.fidelity == "runtime_enforced_partial"
    hardening = result.plan.hardening_config
    execution = result.plan.execution

    assert "apt-get" in hardening["denied_command_names"]
    assert "sudo" in hardening["denied_command_names"]
    assert "curl" in hardening["denied_command_names"]
    assert "/usr/bin/sudo" in hardening["denied_exec_paths"]
    assert "/usr/bin/curl" in hardening["denied_exec_paths"]
    assert "/etc/shadow" in hardening["denied_path_exact"]
    assert "/root/.ssh/" in hardening["denied_path_prefixes"]
    assert "OPENROUTER_API_KEY" in hardening["strip_env_vars"]
    assert "bash" in hardening["child_network_command_names"]
    assert "curl" in hardening["child_network_command_names"]
    assert "python3" in hardening["child_network_command_names"]
    assert "python3" not in hardening["denied_command_names"]
    assert hardening["seccomp_block_syscalls"] == [
        "personality",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
    ]
    assert hardening["egress_cidr_denylist"] == [
        "169.254.169.254/32",
        "169.254.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fe80::/10",
        "fc00::/7",
    ]
    assert hardening["egress_cidr_default_action"] == "deny"
    assert {"127.0.0.0/8", "::1/128"} <= set(hardening["egress_cidr_allowlist"])
    assert hardening["egress_domain_default_action"] == "deny"
    assert {"api.openrouter.ai", "*.openrouter.ai", "openrouter.ai"} <= set(
        hardening["egress_domain_allowlist"]
    )
    assert execution["agent_user"] == "daytona"
    assert execution["block_child_shell_network"] is True
    assert execution["block_network"] is True
    assert execution["isolate_network"] is False
    assert "nonroot-agent" in execution["overlays"]
    assert "child-network" in execution["overlays"]
    assert "coarse-network-block" in execution["overlays"]
    assert "seccomp-syscall" in execution["overlays"]
    assert "domain-egress" in execution["overlays"]


def test_nist_runtime_variant_preserves_unsupported_and_enforced_network_coverage():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-high",
        variant_id="nist-linux-80053-high-daytona-v1",
    )

    coverage_statuses = {
        (item["surface"], item["status"]) for item in result.plan.coverage
    }
    diagnostic_statuses = {
        (diagnostic.surface, diagnostic.status) for diagnostic in result.diagnostics
    }

    assert ("domain_egress_policy", "enforced") in coverage_statuses
    assert ("cidr_egress_policy", "enforced") in coverage_statuses
    assert ("full_mac_enforcement", "unsupported") in coverage_statuses
    assert ("seccomp_syscall_policy", "enforced") in coverage_statuses
    assert ("coarse_non_loopback_network_block", "enforced") in coverage_statuses
    assert ("domain_egress_policy", "unsupported") not in diagnostic_statuses
    assert ("cidr_egress_policy", "unsupported") not in diagnostic_statuses
    assert ("seccomp_syscall_policy", "unsupported") not in diagnostic_statuses
    assert ("coarse_non_loopback_network_block", "deferred") not in diagnostic_statuses


def test_enforced_cidr_mapping_rejects_all_invalid_values():
    pack = PolicyPack(
        catalog_schema_version=CATALOG_SCHEMA_VERSION,
        pack_id="invalid-cidr-fixture",
        title="Invalid CIDR fixture",
        version="0.1.0",
        source=SourceProvenance(
            framework="test",
            provenance_note="test fixture for CIDR compiler validation",
        ),
        policies=(
            PolicyDefinition(
                policy_id="invalid-cidr-policy",
                family="test",
                title="Invalid CIDR policy",
                variants=(
                    PolicyVariant(
                        variant_id="invalid-cidr-daytona-v1",
                        title="Invalid CIDR Daytona v1",
                        fidelity=FidelityLevel.RUNTIME_ENFORCED_PARTIAL,
                        runtime_targets=(
                            RuntimeTargetBinding(
                                target=DAYTONA_HARDENING_V1,
                                capability_set=DAYTONA_HARDENING_V1,
                            ),
                        ),
                        rules=(
                            PolicyRule(
                                rule_id="invalid-cidr-rule",
                                title="Invalid CIDR rule",
                                description="Uses invalid CIDR values.",
                                intended_effect="Exercise compiler validation.",
                                runtime_mappings=(
                                    RuntimeMapping(
                                        target=DAYTONA_HARDENING_V1,
                                        surface="cidr_egress_policy",
                                        status=MappingStatus.ENFORCED,
                                        values=("metadata endpoint", "private network"),
                                        verification_hint="Probe CIDR socket denial.",
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ValueError,
        match=(
            "cidr_egress_policy values must be CIDRs; invalid values: "
            "'metadata endpoint', 'private network'"
        ),
    ):
        compile_policy_variant_from_pack(
            pack=pack,
            policy_id="invalid-cidr-policy",
            variant_id="invalid-cidr-daytona-v1",
        )


def test_enforced_domain_mapping_rejects_invalid_policy_values():
    pack = PolicyPack(
        catalog_schema_version=CATALOG_SCHEMA_VERSION,
        pack_id="invalid-domain-fixture",
        title="Invalid domain fixture",
        version="0.1.0",
        source=SourceProvenance(
            framework="test",
            provenance_note="test fixture for domain compiler validation",
        ),
        policies=(
            PolicyDefinition(
                policy_id="invalid-domain-policy",
                family="test",
                title="Invalid domain policy",
                variants=(
                    PolicyVariant(
                        variant_id="invalid-domain-daytona-v1",
                        title="Invalid domain Daytona v1",
                        fidelity=FidelityLevel.RUNTIME_ENFORCED_PARTIAL,
                        runtime_targets=(
                            RuntimeTargetBinding(
                                target=DAYTONA_HARDENING_V1,
                                capability_set=DAYTONA_HARDENING_V1,
                            ),
                        ),
                        rules=(
                            PolicyRule(
                                rule_id="invalid-domain-rule",
                                title="Invalid domain rule",
                                description="Uses invalid domain policy values.",
                                intended_effect="Exercise compiler validation.",
                                runtime_mappings=(
                                    RuntimeMapping(
                                        target=DAYTONA_HARDENING_V1,
                                        surface="domain_egress_policy",
                                        status=MappingStatus.ENFORCED,
                                        values=("default:block", "allow:https://example.com"),
                                        verification_hint="Probe domain egress denial.",
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ValueError,
        match="domain_egress_policy values must be default:allow, default:deny, allow:<domain>, or deny:<domain>",
    ):
        compile_policy_variant_from_pack(
            pack=pack,
            policy_id="invalid-domain-policy",
            variant_id="invalid-domain-daytona-v1",
        )


def test_nist_runtime_variant_does_not_compile_non_enforced_mappings():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-high",
        variant_id="nist-linux-80053-high-daytona-v1",
    )

    hardening = result.plan.hardening_config
    flattened_hardening_values = {
        value
        for values in hardening.values()
        if isinstance(values, list)
        for value in values
    }

    assert "apt-get install" not in flattened_hardening_values
    assert "live package or update repositories" not in flattened_hardening_values
    assert "non-loopback external networks" not in flattened_hardening_values
    assert "169.254.169.254/32" in flattened_hardening_values
    assert result.plan.execution["block_network"] is True
    assert result.plan.execution["isolate_network"] is False


def test_nist_runtime_variants_record_agentsh_argument_aware_mitigation():
    expected_counts = {
        "nist-linux-80053-high": (16, 5, 0),
        "nist-linux-80053-medium": (16, 5, 0),
        "nist-linux-80053-low": (11, 5, 0),
    }
    expected_values = {
        "nist-linux-80053-high": {
            "apt-get install",
            "sysctl -w",
            "systemctl restart",
        },
        "nist-linux-80053-medium": {
            "apt-get install",
            "sysctl -w",
            "systemctl restart",
        },
        "nist-linux-80053-low": {"sudo -i", "su -"},
    }

    pack = load_policy_pack("nist-linux-security")
    for policy_id, variant_id in NIST_RUNTIME_VARIANTS:
        result = compile_policy_variant(
            pack_id="nist-linux-security",
            policy_id=policy_id,
            variant_id=variant_id,
        )
        policy = next(
            candidate for candidate in pack.policies if candidate.policy_id == policy_id
        )
        variant = next(
            candidate
            for candidate in policy.variants
            if candidate.variant_id == variant_id
        )
        targets = {target.target for target in variant.runtime_targets}
        agentsh_items = [
            item
            for item in result.plan.coverage
            if item["target"] == AGENTSH_POLICY_TARGET
            and item["surface"] == "argument_aware_command_restriction"
        ]
        enforced, unsupported, deferred = expected_counts[policy_id]

        assert AGENTSH_POLICY_TARGET in targets
        assert len(agentsh_items) == 1
        assert agentsh_items[0]["status"] == "enforced"
        assert set(agentsh_items[0]["values"]) == expected_values[policy_id]
        assert "args_patterns" in agentsh_items[0]["verification_hint"]
        for metadata in (policy.metadata, variant.metadata):
            assert metadata["coverage_disposition_counts"]["enforced"] == enforced
            assert metadata["coverage_disposition_counts"]["unsupported"] == unsupported
            assert metadata["coverage_disposition_counts"]["deferred"] == deferred
            assert metadata["compile_status_counts"]["enforced"] == enforced
            assert metadata["compile_status_counts"]["unsupported"] == unsupported
            assert metadata["compile_status_counts"]["deferred"] == deferred


def test_nist_runtime_variants_record_agentsh_operation_specific_path_policy():
    expected_paths = {
        "nist-linux-80053-high": (
            {
                "/etc/gshadow",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/sudoers.d/",
                "/root/.ssh/",
            },
            {
                "/etc/sudoers",
                "/etc/sudoers.d/**",
                "/root/.ssh/**",
            },
        ),
        "nist-linux-80053-medium": (
            {
                "/etc/gshadow",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/sudoers.d/",
                "/root/.ssh/",
            },
            {
                "/etc/sudoers",
                "/etc/sudoers.d/**",
                "/root/.ssh/**",
            },
        ),
        "nist-linux-80053-low": (
            {
                "/etc/gshadow",
                "/etc/shadow",
                "/etc/sudoers",
            },
            {
                "/etc/sudoers",
            },
        ),
    }

    for policy_id, variant_id in NIST_RUNTIME_VARIANTS:
        result = compile_policy_variant(
            pack_id="nist-linux-security",
            policy_id=policy_id,
            variant_id=variant_id,
        )
        agentsh_items = [
            item
            for item in result.plan.coverage
            if item["target"] == AGENTSH_POLICY_TARGET
            and item["surface"] == "operation_specific_path_mode_policy"
        ]

        assert len(agentsh_items) == 2
        by_mode = {
            item["metadata"]["operation_mode"]: item for item in agentsh_items
        }
        expected_read_paths, expected_write_paths = expected_paths[policy_id]
        assert set(by_mode) == {"read", "write"}
        assert set(by_mode["read"]["values"]) == expected_read_paths
        assert by_mode["read"]["metadata"]["operations"] == [
            "read",
            "open",
            "stat",
            "list",
            "readlink",
            "access",
        ]
        assert by_mode["read"]["metadata"]["write_guard"] is True
        assert set(by_mode["write"]["values"]) == expected_write_paths
        assert by_mode["write"]["metadata"]["operations"] == [
            "write",
            "create",
            "mkdir",
            "symlink",
            "chmod",
            "chown",
            "rename",
            "link",
            "refer",
            "delete",
            "rmdir",
        ]
        assert by_mode["write"]["metadata"]["write_guard"] is False
        assert all(item["status"] == "enforced" for item in agentsh_items)


def test_catalog_lists_agentsh_argument_aware_runtime_capability():
    capabilities = {capability.target: capability for capability in list_runtime_targets()}

    agentsh = capabilities[AGENTSH_POLICY_TARGET]

    assert "argument_aware_command_restriction" in agentsh.supported_surfaces
    assert "operation_specific_path_mode_policy" in agentsh.supported_surfaces
    assert "operation_specific_path_mode_policy" not in agentsh.unsupported_surfaces
    assert "full_auditd_compliance_evidence" in agentsh.unsupported_surfaces
    assert "domain_egress_policy" in agentsh.unsupported_surfaces

    daytona = capabilities[DAYTONA_HARDENING_V1]
    assert "domain_egress_policy" in daytona.supported_surfaces
    assert "domain_egress_policy" not in daytona.unsupported_surfaces
    assert "seccomp_syscall_policy" in daytona.supported_surfaces
    assert "seccomp_syscall_policy" not in daytona.unsupported_surfaces


def test_compiling_nist_medium_variant_emits_enforced_daytona_fields():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-medium",
        variant_id="nist-linux-80053-medium-daytona-v1",
    )

    assert result.plan.fidelity == "runtime_enforced_partial"
    hardening = result.plan.hardening_config
    execution = result.plan.execution

    assert {"apt-get", "sudo", "sysctl", "systemctl", "curl", "ssh", "wget"} <= set(
        hardening["denied_command_names"]
    )
    assert {"insmod", "modprobe", "rmmod"}.isdisjoint(hardening["denied_command_names"])
    assert {"ftp", "nc", "ncat", "telnet"}.isdisjoint(hardening["denied_command_names"])
    assert {"/usr/bin/sudo", "/usr/bin/apt-get", "/usr/bin/curl"} <= set(
        hardening["denied_exec_paths"]
    )
    assert "/sbin/modprobe" not in hardening["denied_exec_paths"]
    assert "/etc/shadow" in hardening["denied_path_exact"]
    assert "/root/.ssh/" in hardening["denied_path_prefixes"]
    assert "OPENROUTER_API_KEY" in hardening["strip_env_vars"]
    assert hardening["seccomp_block_syscalls"] == ["personality", "ptrace"]
    assert {"bash", "curl", "python3", "ssh", "wget"} <= set(
        hardening["child_network_command_names"]
    )
    assert hardening["egress_domain_default_action"] == "deny"
    assert {"api.openrouter.ai", "*.openrouter.ai", "openrouter.ai"} <= set(
        hardening["egress_domain_allowlist"]
    )
    assert "ftp" not in hardening["child_network_command_names"]
    assert execution["agent_user"] == "daytona"
    assert execution["block_child_shell_network"] is True
    assert execution["block_network"] is True
    assert execution["isolate_network"] is False
    assert "nonroot-agent" in execution["overlays"]
    assert "child-network" in execution["overlays"]
    assert "seccomp-syscall" in execution["overlays"]
    assert "domain-egress" in execution["overlays"]
    assert "coarse-network-block" in execution["overlays"]


def test_compiling_nist_low_variant_emits_minimal_daytona_fields():
    result = compile_policy_variant(
        pack_id="nist-linux-security",
        policy_id="nist-linux-80053-low",
        variant_id="nist-linux-80053-low-daytona-v1",
    )

    assert result.plan.fidelity == "runtime_enforced_partial"
    hardening = result.plan.hardening_config
    execution = result.plan.execution

    assert set(hardening["denied_command_names"]) == {"passwd", "su", "sudo"}
    assert set(hardening["denied_exec_paths"]) == {
        "/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/sudo",
    }
    assert "apt-get" not in hardening["denied_command_names"]
    assert "curl" not in hardening["denied_command_names"]
    assert "/etc/shadow" in hardening["denied_path_exact"]
    assert "/etc/sudoers" in hardening["denied_path_exact"]
    assert hardening["denied_path_prefixes"] == []
    assert {"AWS_ACCESS_KEY_ID", "OPENROUTER_API_KEY"} <= set(
        hardening["strip_env_vars"]
    )
    assert "GITHUB_TOKEN" not in hardening["strip_env_vars"]
    assert hardening["child_network_command_names"] == []
    assert hardening["seccomp_block_syscalls"] == ["personality"]
    assert execution["agent_user"] == "daytona"
    assert execution["block_child_shell_network"] is False
    assert "nonroot-agent" in execution["overlays"]
    assert "child-network" not in execution["overlays"]
    assert "seccomp-syscall" in execution["overlays"]
    assert "domain-egress" in execution["overlays"]
    assert hardening["egress_domain_default_action"] == "deny"
    assert {"api.openrouter.ai", "*.openrouter.ai", "openrouter.ai"} <= set(
        hardening["egress_domain_allowlist"]
    )
    assert hardening["egress_cidr_default_action"] == "deny"
    assert {"127.0.0.0/8", "::1/128"} <= set(hardening["egress_cidr_allowlist"])


def test_native_nist_tiers_are_per_axis_monotone():
    """Restrictiveness over the co-monotone native ``-nist`` ladder.

    The roster is a lattice, so a single total order is meaningless; the
    three ``-nist`` tiers run low (n1-f1-p1) -> moderate (n2-f1-p1) ->
    high (n5-f2-p2). Filesystem and privilege are non-decreasing in
    restrictiveness; on the network axis every tier is default-deny and
    ``moderate`` is the narrowest task-id-less allowlist, while ``high``
    swaps the per-task N2 base for the fixed trusted N5 base (not a subset
    relation with moderate->high). Compiled from the native single source of
    truth via ``build_daytona_config_from_axes`` (task_id-less).
    """
    low = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"])
    moderate = build_daytona_config_from_axes(AXIS_PRESETS["moderate-nist"])
    high = build_daytona_config_from_axes(AXIS_PRESETS["high-nist"])

    low_domains = set(low.egress_domain_allowlist)
    moderate_domains = set(moderate.egress_domain_allowlist)
    high_domains = set(high.egress_domain_allowlist)
    assert moderate_domains < low_domains
    assert moderate_domains < high_domains
    assert (
        low.egress_domain_default_action
        == moderate.egress_domain_default_action
        == high.egress_domain_default_action
        == "deny"
    )

    low_rank = _FILESYSTEM_SCOPE_RANK[low.filesystem_scope]
    moderate_rank = _FILESYSTEM_SCOPE_RANK[moderate.filesystem_scope]
    high_rank = _FILESYSTEM_SCOPE_RANK[high.filesystem_scope]
    assert low_rank == moderate_rank < high_rank
    assert (low.filesystem_scope, moderate.filesystem_scope, high.filesystem_scope) == (
        "workspace",
        "workspace",
        "read_only",
    )

    low_priv = _active_privilege_bools(low)
    moderate_priv = _active_privilege_bools(moderate)
    high_priv = _active_privilege_bools(high)
    assert low_priv == moderate_priv == frozenset({"lock_root_password"})
    assert low_priv < high_priv
    assert high_priv == frozenset(
        {"lock_root_password", "no_new_privs", "drop_bounding_caps", "strip_setuid"}
    )


def test_nist_runtime_variants_preserve_required_coverage_count_shape():
    for policy_id, variant_id in NIST_RUNTIME_VARIANTS:
        pack = load_policy_pack("nist-linux-security")
        policy = next(
            candidate for candidate in pack.policies if candidate.policy_id == policy_id
        )
        variant = next(
            candidate
            for candidate in policy.variants
            if candidate.variant_id == variant_id
        )

        for metadata in (policy.metadata, variant.metadata):
            assert set(metadata["coverage_disposition_counts"]) == {
                "denominator",
                "enforced",
                "approximated",
                "metadata_only",
                "monitoring_only",
                "representation_only",
                "unsupported",
                "deferred",
                "not_relevant_to_daytona",
            }


def test_daytona_hardening_config_validates_seccomp_syscall_names():
    from boundarybench.daytona.hardening_config import DaytonaHardeningConfig

    config = DaytonaHardeningConfig.from_mapping(
        {
            "name": "seccomp-fixture",
            "block_message": "Permission denied",
            "seccomp_block_syscalls": ["personality", "process_vm_readv"],
        }
    )

    assert config.seccomp_block_syscalls == ("personality", "process_vm_readv")

    with pytest.raises(ValueError, match="invalid syscall name"):
        DaytonaHardeningConfig(seccomp_block_syscalls=("personality;rm -rf /",))


def test_nist_runtime_variant_never_marks_unsupported_surfaces_enforced():
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

    unsupported_mappings = [
        mapping
        for rule in variant.rules
        for mapping in rule.runtime_mappings
        if mapping.target == "daytona-hardening-v1"
        and mapping.surface in UNSUPPORTED_DAYTONA_SURFACES
    ]

    assert unsupported_mappings
    assert all(mapping.status != "enforced" for mapping in unsupported_mappings)


def test_nist_medium_low_never_marks_unsupported_surfaces_enforced():
    for policy_id, variant_id in NIST_RUNTIME_VARIANTS[1:]:
        pack = load_policy_pack("nist-linux-security")
        policy = next(
            candidate for candidate in pack.policies if candidate.policy_id == policy_id
        )
        variant = next(
            candidate
            for candidate in policy.variants
            if candidate.variant_id == variant_id
        )

        unsupported_mappings = [
            mapping
            for rule in variant.rules
            for mapping in rule.runtime_mappings
            if mapping.target == "daytona-hardening-v1"
            and mapping.surface in UNSUPPORTED_DAYTONA_SURFACES
        ]

        assert unsupported_mappings
        assert all(mapping.status != "enforced" for mapping in unsupported_mappings)


def test_nist_runtime_variant_uses_allowed_nist_derived_language():
    pack = load_policy_pack("nist-linux-security", validate=False)
    report = validate_policy_pack(pack)

    assert report.passed is True
    assert not [
        issue
        for issue in report.issues
        if "prohibited compliance claim" in issue.message
    ]


def test_validate_cli_reports_success(capsys):
    validate_main(["--pack-id", "boundary-contract-fixtures"])

    captured = capsys.readouterr()

    assert "boundary-contract-fixtures: passed" in captured.out


def test_compile_cli_outputs_json(capsys):
    compile_main(
        [
            "--pack-id",
            "boundary-contract-fixtures",
            "--policy-id",
            "contract-smoke-enterprise-shape",
            "--variant-id",
            "daytona-smoke-v1",
        ]
    )

    captured = capsys.readouterr()

    assert '"target": "daytona-hardening-v1"' in captured.out
    assert '"denied_command_names"' in captured.out


def test_compile_cli_outputs_nist_runtime_variant_json(capsys):
    compile_main(
        [
            "--pack-id",
            "nist-linux-security",
            "--policy-id",
            "nist-linux-80053-high",
            "--variant-id",
            "nist-linux-80053-high-daytona-v1",
        ]
    )

    captured = capsys.readouterr()

    assert '"policy_id": "nist-linux-80053-high"' in captured.out
    assert '"variant_id": "nist-linux-80053-high-daytona-v1"' in captured.out
    assert '"denied_command_names"' in captured.out
    assert '"apt-get"' in captured.out
    assert '"domain_egress_policy"' in captured.out


def test_compile_cli_outputs_nist_medium_and_low_runtime_variants_json(capsys):
    for policy_id, variant_id in NIST_RUNTIME_VARIANTS[1:]:
        compile_main(
            [
                "--pack-id",
                "nist-linux-security",
                "--policy-id",
                policy_id,
                "--variant-id",
                variant_id,
            ]
        )

    captured = capsys.readouterr()

    assert '"policy_id": "nist-linux-80053-medium"' in captured.out
    assert '"variant_id": "nist-linux-80053-medium-daytona-v1"' in captured.out
    assert '"policy_id": "nist-linux-80053-low"' in captured.out
    assert '"variant_id": "nist-linux-80053-low-daytona-v1"' in captured.out
    assert '"monitoring_only"' in captured.out


def test_validate_cli_unknown_pack_has_concise_error(capsys):
    try:
        validate_main(["--pack-id", "missing-pack"])
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("validate_main should exit for unknown packs")

    captured = capsys.readouterr()

    assert "error: " in captured.err
    assert "missing-pack" in captured.err
    assert "Traceback" not in captured.err


def test_compile_cli_unknown_variant_has_concise_error(capsys):
    try:
        compile_main(
            [
                "--pack-id",
                "boundary-contract-fixtures",
                "--policy-id",
                "contract-smoke-enterprise-shape",
                "--variant-id",
                "missing-variant",
            ]
        )
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("compile_main should exit for unknown variants")

    captured = capsys.readouterr()

    assert "error: " in captured.err
    assert "missing-variant" in captured.err
    assert "Traceback" not in captured.err
