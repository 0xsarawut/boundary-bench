from copy import deepcopy

from boundarybench.policy_catalog.catalog import policy_pack_from_mapping, validate_policy_pack


def test_validation_rejects_duplicate_rule_ids():
    payload = _valid_payload()
    rules = payload["policies"][0]["variants"][0]["rules"]
    rules.append(deepcopy(rules[0]))

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "duplicate rule_id")


def test_validation_rejects_missing_source_provenance_for_derived_pack():
    payload = _valid_payload()
    payload["source"] = {
        "framework": "NIST 800-53r5 via usnistgov/linux_security",
        "upstream_url": "https://github.com/usnistgov/linux_security",
        "provenance_note": "Derived fixture.",
    }
    payload["policies"][0]["variants"][0]["fidelity"] = "source_derived_partial"

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "upstream_commit or immutable_revision")


def test_validation_rejects_unsupported_surface_marked_enforced():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0] = {
        "target": "daytona-hardening-v1",
        "surface": "full_mac_enforcement",
        "status": "enforced",
        "values": ["SELinux"],
        "verification_hint": "configure SELinux",
    }

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "not enforceable by daytona-hardening-v1")


def test_validation_rejects_unknown_unsupported_feature_surface():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["unsupported_features"] = [
        {
            "surface": "domain_egress_polciy",
            "reason": "Typo should not satisfy explicit unsupported declaration.",
            "missing_surface": "domain egress policy",
            "verification_hint": "Validate the typo is rejected.",
        }
    ]

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "unknown unsupported Daytona surface")


def test_validation_rejects_empty_enforced_mapping_values():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0][
        "values"
    ] = []

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "requires at least one value")


def test_validation_rejects_approximate_mapping_without_reason():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0][
        "status"
    ] = "approximate"

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "approximate mappings require reason")
    assert _messages(report, "approximate mappings require missing_surface")


def test_validation_rejects_argument_value_as_command_name():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0][
        "values"
    ] = ["apt-get install"]

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "not argv")


def test_validation_rejects_prohibited_nist_claim_language():
    payload = _valid_payload()
    payload["description"] = "This fixture is NIST compliant."

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "prohibited compliance claim")


def test_validation_rejects_runtime_enforced_partial_without_enforced_mapping():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0] = {
        "target": "daytona-hardening-v1",
        "surface": "argument_aware_command_restriction",
        "status": "unsupported",
        "values": ["apt-get install"],
        "reason": "No argv parser.",
        "missing_surface": "argument-aware command policy",
        "verification_hint": "Do not compile.",
    }

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "runtime_enforced_partial requires")


def test_validation_rejects_native_exact_with_non_enforced_mapping():
    payload = _valid_payload()
    variant = payload["policies"][0]["variants"][0]
    variant["fidelity"] = "native_exact"
    variant["unsupported_features"] = [
        {
            "surface": "seccomp_syscall_policy",
            "reason": "No seccomp policy.",
            "missing_surface": "seccomp policy",
            "verification_hint": "Do not compile.",
        }
    ]
    variant["rules"][0]["runtime_mappings"][0] = {
        "target": "daytona-hardening-v1",
        "surface": "command_name_denial",
        "status": "approximate",
        "values": ["curl"],
        "reason": "Only command name is represented.",
        "missing_surface": "argument-aware command policy",
        "verification_hint": "curl --version",
    }

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "native_exact cannot declare unsupported_features")
    assert _messages(report, "native_exact requires enforced mappings")


def test_validation_rejects_native_exact_rule_unsupported_features():
    payload = _valid_payload()
    variant = payload["policies"][0]["variants"][0]
    variant["fidelity"] = "native_exact"
    variant["rules"][0]["unsupported_features"] = [
        {
            "surface": "seccomp_syscall_policy",
            "reason": "No seccomp policy.",
            "missing_surface": "seccomp policy",
            "verification_hint": "Do not compile.",
        }
    ]

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "native_exact cannot declare unsupported_features")


def test_validation_rejects_root_non_root_user_mapping():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0] = {
        "target": "daytona-hardening-v1",
        "surface": "non_root_user",
        "status": "enforced",
        "values": ["root"],
        "verification_hint": "id -u",
    }

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "non_root_user value cannot be root")


def test_validation_rejects_multiple_non_root_user_values():
    payload = _valid_payload()
    payload["policies"][0]["variants"][0]["rules"][0]["runtime_mappings"][0] = {
        "target": "daytona-hardening-v1",
        "surface": "non_root_user",
        "status": "enforced",
        "values": ["root", "daytona"],
        "verification_hint": "id -u",
    }

    report = validate_policy_pack(policy_pack_from_mapping(payload))

    assert report.passed is False
    assert _messages(report, "non_root_user requires exactly one value")
    assert _messages(report, "non_root_user value cannot be root")


def _messages(report, expected):
    return [
        issue.message
        for issue in report.issues
        if expected in issue.message
    ]


def _valid_payload():
    return {
        "catalog_schema_version": 1,
        "pack_id": "test-pack",
        "title": "Test Pack",
        "version": "0.1.0",
        "description": "Valid native fixture.",
        "source": {
            "framework": "native/boundary",
            "provenance_note": "Test fixture.",
        },
        "policies": [
            {
                "policy_id": "test-policy",
                "family": "native/boundary",
                "title": "Test Policy",
                "variants": [
                    {
                        "variant_id": "daytona-v1",
                        "title": "Daytona V1",
                        "fidelity": "runtime_enforced_partial",
                        "runtime_targets": [
                            {
                                "target": "daytona-hardening-v1",
                                "capability_set": "daytona-hardening-v1",
                            }
                        ],
                        "rules": [
                            {
                                "rule_id": "deny-curl",
                                "title": "Deny curl",
                                "description": "Deny curl command name.",
                                "intended_effect": "Prevent curl use.",
                                "runtime_mappings": [
                                    {
                                        "target": "daytona-hardening-v1",
                                        "surface": "command_name_denial",
                                        "status": "enforced",
                                        "values": ["curl"],
                                        "verification_hint": "curl --version",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
    }
