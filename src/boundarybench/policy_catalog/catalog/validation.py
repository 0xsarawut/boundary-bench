from __future__ import annotations

import re

from boundarybench.policy_catalog.catalog.capabilities import (
    ABSOLUTE_PATH_SURFACES,
    COMMAND_NAME_SURFACES,
    ENV_VAR_SURFACES,
    KNOWN_RUNTIME_TARGETS,
    KNOWN_SURFACES_BY_TARGET,
    SUPPORTED_SURFACES_BY_TARGET,
    SYSCALL_SURFACES,
    UNSUPPORTED_DAYTONA_SURFACES,
    UNSUPPORTED_SURFACES_BY_TARGET,
    WRITE_PATTERN_SURFACES,
)
from boundarybench.policy_catalog.catalog.schema import (
    AGENTSH_POLICY_V1,
    CATALOG_SCHEMA_VERSION,
    COMPILER_CONTRACT_VERSION,
    FidelityLevel,
    MappingStatus,
    PolicyPack,
    PolicyValidationError,
    RuntimeMapping,
    UnsupportedFeature,
    ValidationIssue,
    ValidationReport,
)
from boundarybench.policy_surfaces.operations import (
    AGENTSH_READ_PATH_OPERATIONS,
    AGENTSH_WRITE_PATH_OPERATIONS,
)


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_PROHIBITED_CLAIMS = (
    "nist compliant",
    "nist-compliant",
    "nist high enforced",
    "nist high runtime enforced",
    "nist high runtime-enforced",
)
_VALUE_REQUIRED_SURFACES = (
    COMMAND_NAME_SURFACES
    | ABSOLUTE_PATH_SURFACES
    | ENV_VAR_SURFACES
    | WRITE_PATTERN_SURFACES
    | SYSCALL_SURFACES
    | frozenset(
        {
            "argument_aware_command_restriction",
            "non_root_user",
            "operation_specific_path_mode_policy",
        }
    )
)


def validate_policy_pack(pack: PolicyPack) -> ValidationReport:
    issues: list[ValidationIssue] = []
    _validate_pack(pack, issues)
    _scan_prohibited_claims(pack, issues)
    return ValidationReport(pack_id=pack.pack_id or "<missing>", issues=tuple(issues))


def assert_valid_policy_pack(pack: PolicyPack) -> None:
    report = validate_policy_pack(pack)
    if not report.passed:
        raise PolicyValidationError(report)


def _validate_pack(pack: PolicyPack, issues: list[ValidationIssue]) -> None:
    if pack.catalog_schema_version != CATALOG_SCHEMA_VERSION:
        _error(
            issues,
            "catalog_schema_version",
            f"expected {CATALOG_SCHEMA_VERSION}",
        )
    _validate_slug(pack.pack_id, "pack_id", issues)
    _required(pack.title, "title", issues)
    _required(pack.version, "version", issues)
    _required(pack.source.framework, "source.framework", issues)
    _required(pack.source.provenance_note, "source.provenance_note", issues)
    source_derived = _source_is_derived(pack.source.framework)
    if source_derived and not (
        pack.source.upstream_commit or pack.source.immutable_revision
    ):
        _error(
            issues,
            "source",
            "source-derived packs require upstream_commit or immutable_revision",
        )
    if source_derived and not pack.source.upstream_url:
        _error(issues, "source.upstream_url", "source-derived packs require upstream_url")
    if not pack.policies:
        _error(issues, "policies", "at least one policy is required")

    policy_ids: set[str] = set()
    for policy_index, policy in enumerate(pack.policies):
        policy_path = f"policies[{policy_index}]"
        _validate_slug(policy.policy_id, f"{policy_path}.policy_id", issues)
        if policy.policy_id in policy_ids:
            _error(issues, f"{policy_path}.policy_id", "duplicate policy_id")
        policy_ids.add(policy.policy_id)
        _required(policy.family, f"{policy_path}.family", issues)
        _required(policy.title, f"{policy_path}.title", issues)
        if not policy.variants:
            _error(issues, f"{policy_path}.variants", "at least one variant is required")
        variant_ids: set[str] = set()
        for variant_index, variant in enumerate(policy.variants):
            variant_path = f"{policy_path}.variants[{variant_index}]"
            _validate_slug(variant.variant_id, f"{variant_path}.variant_id", issues)
            if variant.variant_id in variant_ids:
                _error(issues, f"{variant_path}.variant_id", "duplicate variant_id")
            variant_ids.add(variant.variant_id)
            _required(variant.title, f"{variant_path}.title", issues)
            if variant.fidelity not in FidelityLevel.VALUES:
                _error(issues, f"{variant_path}.fidelity", "unknown fidelity level")
            if source_derived and variant.fidelity == FidelityLevel.NATIVE_EXACT:
                _error(
                    issues,
                    f"{variant_path}.fidelity",
                    "source-derived packs cannot declare native_exact fidelity",
                )
            if not variant.runtime_targets:
                _error(
                    issues,
                    f"{variant_path}.runtime_targets",
                    "at least one runtime target binding is required",
                )
            for target_index, target in enumerate(variant.runtime_targets):
                target_path = f"{variant_path}.runtime_targets[{target_index}]"
                if target.target not in KNOWN_RUNTIME_TARGETS:
                    _error(issues, f"{target_path}.target", "unknown runtime target")
                if target.capability_set not in KNOWN_RUNTIME_TARGETS:
                    _error(
                        issues,
                        f"{target_path}.capability_set",
                        "unknown runtime capability set",
                    )
                elif target.capability_set != target.target:
                    _error(
                        issues,
                        f"{target_path}.capability_set",
                        "capability set must match runtime target",
                    )
                if target.compiler_contract_version != COMPILER_CONTRACT_VERSION:
                    _error(
                        issues,
                        f"{target_path}.compiler_contract_version",
                        f"expected {COMPILER_CONTRACT_VERSION}",
                    )
            _validate_unsupported_features(
                variant.unsupported_features,
                f"{variant_path}.unsupported_features",
                issues,
            )
            if (
                variant.fidelity == FidelityLevel.NATIVE_EXACT
                and variant.unsupported_features
            ):
                _error(
                    issues,
                    f"{variant_path}.unsupported_features",
                    "native_exact cannot declare unsupported_features",
                )
            if not variant.rules:
                _error(issues, f"{variant_path}.rules", "at least one rule is required")
            rule_ids: set[str] = set()
            enforced_mappings = 0
            for rule_index, rule in enumerate(variant.rules):
                rule_path = f"{variant_path}.rules[{rule_index}]"
                _validate_slug(rule.rule_id, f"{rule_path}.rule_id", issues)
                if rule.rule_id in rule_ids:
                    _error(issues, f"{rule_path}.rule_id", "duplicate rule_id")
                rule_ids.add(rule.rule_id)
                _required(rule.title, f"{rule_path}.title", issues)
                _required(rule.description, f"{rule_path}.description", issues)
                _required(rule.intended_effect, f"{rule_path}.intended_effect", issues)
                if not rule.runtime_mappings and not rule.unsupported_features:
                    _error(
                        issues,
                        rule_path,
                        "rules with intended effects require runtime_mappings or explicit unsupported_features",
                    )
                _validate_unsupported_features(
                    rule.unsupported_features,
                    f"{rule_path}.unsupported_features",
                    issues,
                )
                if (
                    variant.fidelity == FidelityLevel.NATIVE_EXACT
                    and rule.unsupported_features
                ):
                    _error(
                        issues,
                        f"{rule_path}.unsupported_features",
                        "native_exact cannot declare unsupported_features",
                    )
                for mapping_index, mapping in enumerate(rule.runtime_mappings):
                    mapping_path = f"{rule_path}.runtime_mappings[{mapping_index}]"
                    if _validate_mapping(mapping, mapping_path, issues):
                        if mapping.status == MappingStatus.ENFORCED:
                            enforced_mappings += 1
                    if (
                        variant.fidelity == FidelityLevel.NATIVE_EXACT
                        and mapping.status != MappingStatus.ENFORCED
                    ):
                        _error(
                            issues,
                            f"{mapping_path}.status",
                            "native_exact requires enforced mappings",
                        )
            if (
                variant.fidelity == FidelityLevel.RUNTIME_ENFORCED_PARTIAL
                and enforced_mappings == 0
            ):
                _error(
                    issues,
                    f"{variant_path}.fidelity",
                    "runtime_enforced_partial requires at least one enforced mapping",
                )


def _validate_mapping(
    mapping: RuntimeMapping,
    path: str,
    issues: list[ValidationIssue],
) -> bool:
    valid = True
    if mapping.target not in KNOWN_RUNTIME_TARGETS:
        _error(issues, f"{path}.target", "unknown runtime target")
        valid = False
        known_surfaces = frozenset()
        supported_surfaces = frozenset()
        unsupported_surfaces = frozenset()
    else:
        known_surfaces = KNOWN_SURFACES_BY_TARGET[mapping.target]
        supported_surfaces = SUPPORTED_SURFACES_BY_TARGET[mapping.target]
        unsupported_surfaces = UNSUPPORTED_SURFACES_BY_TARGET[mapping.target]
    if mapping.status not in MappingStatus.VALUES:
        _error(issues, f"{path}.status", "unknown mapping status")
        valid = False
    if mapping.surface not in known_surfaces:
        _error(
            issues,
            f"{path}.surface",
            f"unknown {mapping.target} runtime surface",
        )
        valid = False
    if (
        mapping.surface in unsupported_surfaces
        and mapping.status == MappingStatus.ENFORCED
    ):
        _error(
            issues,
            f"{path}.status",
            f"{mapping.surface} is not enforceable by {mapping.target}",
        )
        valid = False
    if (
        mapping.surface in supported_surfaces
        and mapping.status == MappingStatus.ENFORCED
        and not mapping.verification_hint
    ):
        _error(
            issues,
            f"{path}.verification_hint",
            "enforced mappings require a verification_hint",
        )
        valid = False
    if (
        mapping.surface in _VALUE_REQUIRED_SURFACES
        and mapping.status in {MappingStatus.ENFORCED, MappingStatus.APPROXIMATE}
        and not mapping.values
    ):
        _error(
            issues,
            f"{path}.values",
            f"{mapping.surface} requires at least one value",
        )
        valid = False
    if mapping.surface == "non_root_user" and mapping.status in {
        MappingStatus.ENFORCED,
        MappingStatus.APPROXIMATE,
    }:
        if mapping.values and len(mapping.values) != 1:
            _error(
                issues,
                f"{path}.values",
                "non_root_user requires exactly one value",
            )
            valid = False
        for value in mapping.values:
            if value.strip().lower() == "root":
                _error(
                    issues,
                    f"{path}.values",
                    "non_root_user value cannot be root",
                )
                valid = False
    if mapping.status in {
        MappingStatus.APPROXIMATE,
        MappingStatus.UNSUPPORTED,
        MappingStatus.REPRESENTATION_ONLY,
        MappingStatus.DEFERRED,
    }:
        for field_name, value in (
            ("reason", mapping.reason),
            ("missing_surface", mapping.missing_surface),
            ("verification_hint", mapping.verification_hint),
        ):
            if not value:
                _error(
                    issues,
                    f"{path}.{field_name}",
                    f"{mapping.status} mappings require {field_name}",
                )
                valid = False
    if mapping.surface in COMMAND_NAME_SURFACES:
        for value in mapping.values:
            if not value or "/" in value or any(char.isspace() for char in value):
                _error(
                    issues,
                    f"{path}.values",
                    f"{mapping.surface} value must be a command name, not argv: {value!r}",
                )
                valid = False
    if mapping.surface in ABSOLUTE_PATH_SURFACES:
        for value in mapping.values:
            if not value.startswith("/"):
                _error(
                    issues,
                    f"{path}.values",
                    f"{mapping.surface} values must be absolute paths: {value!r}",
                )
                valid = False
    if mapping.surface in ENV_VAR_SURFACES:
        for value in mapping.values:
            if not _valid_env_name(value):
                _error(issues, f"{path}.values", f"invalid env var name: {value!r}")
                valid = False
    if mapping.surface in WRITE_PATTERN_SURFACES:
        for value in mapping.values:
            if not _valid_shell_pattern(value):
                _error(
                    issues,
                    f"{path}.values",
                    f"invalid denied write pattern: {value!r}",
                )
                valid = False
    if mapping.surface in SYSCALL_SURFACES:
        for value in mapping.values:
            if not _valid_syscall_name(value):
                _error(issues, f"{path}.values", f"invalid syscall name: {value!r}")
                valid = False
    if (
        mapping.target == AGENTSH_POLICY_V1
        and mapping.surface == "argument_aware_command_restriction"
    ):
        for value in mapping.values:
            if not value or " " not in value.strip():
                _error(
                    issues,
                    f"{path}.values",
                    "argument-aware AgentSH values must include command and argv",
                )
                valid = False
    if (
        mapping.target == AGENTSH_POLICY_V1
        and mapping.surface == "operation_specific_path_mode_policy"
    ):
        valid = _validate_agentsh_operation_specific_path_mapping(
            mapping, path, issues
        ) and valid
    return valid


def _validate_agentsh_operation_specific_path_mapping(
    mapping: RuntimeMapping,
    path: str,
    issues: list[ValidationIssue],
) -> bool:
    valid = True
    operation_mode = mapping.metadata.get("operation_mode")
    if operation_mode not in {"read", "write"}:
        _error(
            issues,
            f"{path}.metadata.operation_mode",
            "AgentSH operation-specific path mappings require operation_mode read or write",
        )
        valid = False
    expected_operations = {
        "read": list(AGENTSH_READ_PATH_OPERATIONS),
        "write": list(AGENTSH_WRITE_PATH_OPERATIONS),
    }.get(str(operation_mode), [])
    operations = mapping.metadata.get("operations")
    if operations != expected_operations:
        _error(
            issues,
            f"{path}.metadata.operations",
            f"expected {expected_operations!r}",
        )
        valid = False
    write_guard = mapping.metadata.get("write_guard")
    if operation_mode == "read" and write_guard is not True:
        _error(
            issues,
            f"{path}.metadata.write_guard",
            "read-mode path mappings require write_guard true",
        )
        valid = False
    if operation_mode == "write" and write_guard is not False:
        _error(
            issues,
            f"{path}.metadata.write_guard",
            "write-mode path mappings require write_guard false",
        )
        valid = False
    for value in mapping.values:
        if not value.startswith("/"):
            _error(
                issues,
                f"{path}.values",
                f"operation-specific path values must be absolute paths: {value!r}",
            )
            valid = False
    return valid


def _validate_unsupported_features(
    features: tuple[UnsupportedFeature, ...],
    path: str,
    issues: list[ValidationIssue],
) -> None:
    for index, feature in enumerate(features):
        feature_path = f"{path}[{index}]"
        _required(feature.surface, f"{feature_path}.surface", issues)
        if feature.surface and feature.surface not in UNSUPPORTED_DAYTONA_SURFACES:
            _error(
                issues,
                f"{feature_path}.surface",
                "unknown unsupported Daytona surface",
            )
        for field_name, value in (
            ("reason", feature.reason),
            ("missing_surface", feature.missing_surface),
            ("verification_hint", feature.verification_hint),
        ):
            _required(value, f"{feature_path}.{field_name}", issues)


def _scan_prohibited_claims(pack: PolicyPack, issues: list[ValidationIssue]) -> None:
    def walk(value: object, path: str) -> None:
        if isinstance(value, str):
            lowered = value.lower()
            for claim in _PROHIBITED_CLAIMS:
                if claim in lowered:
                    _error(
                        issues,
                        path,
                        f"prohibited compliance claim {claim!r}; use NIST-derived/partial language",
                    )
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    walk(pack.to_dict(), "pack")


def _validate_slug(value: str, path: str, issues: list[ValidationIssue]) -> None:
    if not value:
        _error(issues, path, "required")
    elif not _SLUG_RE.match(value):
        _error(issues, path, "must be slug-safe lowercase text")


def _required(value: object, path: str, issues: list[ValidationIssue]) -> None:
    if value in {"", (), None}:
        _error(issues, path, "required")


def _source_is_derived(framework: str) -> bool:
    lowered = framework.lower()
    return "nist" in lowered or "usnistgov" in lowered or "derived" in lowered


def _valid_env_name(value: str) -> bool:
    return bool(value) and (value[0].isalpha() or value[0] == "_") and all(
        part.isalnum() or part == "_" for part in value
    )


def _valid_shell_pattern(pattern: str) -> bool:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-*?")
    return bool(pattern) and all(char in allowed for char in pattern)


def _valid_syscall_name(value: str) -> bool:
    return bool(value) and all(part.isalnum() or part == "_" for part in value)


def _error(issues: list[ValidationIssue], path: str, message: str) -> None:
    issues.append(ValidationIssue(path=path, message=message))
