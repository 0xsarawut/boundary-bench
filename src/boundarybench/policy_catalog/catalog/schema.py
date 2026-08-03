from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


CATALOG_SCHEMA_VERSION = 1
COMPILER_CONTRACT_VERSION = "daytona-hardening-compiler-v1"
DAYTONA_HARDENING_V1 = "daytona-hardening-v1"
AGENTSH_POLICY_V1 = "agentsh-policy-v1"


class FidelityLevel:
    NATIVE_EXACT = "native_exact"
    SOURCE_DERIVED_PARTIAL = "source_derived_partial"
    RUNTIME_ENFORCED_PARTIAL = "runtime_enforced_partial"
    REPRESENTATION_ONLY = "representation_only"

    VALUES = frozenset(
        {
            NATIVE_EXACT,
            SOURCE_DERIVED_PARTIAL,
            RUNTIME_ENFORCED_PARTIAL,
            REPRESENTATION_ONLY,
        }
    )


class MappingStatus:
    ENFORCED = "enforced"
    APPROXIMATE = "approximate"
    UNSUPPORTED = "unsupported"
    REPRESENTATION_ONLY = "representation_only"
    DEFERRED = "deferred"

    VALUES = frozenset(
        {
            ENFORCED,
            APPROXIMATE,
            UNSUPPORTED,
            REPRESENTATION_ONLY,
            DEFERRED,
        }
    )


@dataclass(frozen=True)
class SourceProvenance:
    framework: str
    provenance_note: str
    upstream_url: str = ""
    upstream_commit: str = ""
    immutable_revision: str = ""
    inspected_date: str = ""
    source_paths: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "provenance_note": self.provenance_note,
            "upstream_url": self.upstream_url,
            "upstream_commit": self.upstream_commit,
            "immutable_revision": self.immutable_revision,
            "inspected_date": self.inspected_date,
            "source_paths": list(self.source_paths),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class SourceReference:
    framework: str
    control_id: str
    title: str = ""
    url: str = ""
    path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "title": self.title,
            "url": self.url,
            "path": self.path,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RuntimeTargetBinding:
    target: str
    capability_set: str
    compiler_contract_version: str = COMPILER_CONTRACT_VERSION
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "capability_set": self.capability_set,
            "compiler_contract_version": self.compiler_contract_version,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class UnsupportedFeature:
    surface: str
    reason: str
    missing_surface: str
    verification_hint: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "reason": self.reason,
            "missing_surface": self.missing_surface,
            "verification_hint": self.verification_hint,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RuntimeMapping:
    target: str
    surface: str
    status: str
    values: tuple[str, ...] = ()
    reason: str = ""
    missing_surface: str = ""
    verification_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "surface": self.surface,
            "status": self.status,
            "values": list(self.values),
            "reason": self.reason,
            "missing_surface": self.missing_surface,
            "verification_hint": self.verification_hint,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    title: str
    description: str
    intended_effect: str
    source_refs: tuple[SourceReference, ...] = ()
    runtime_mappings: tuple[RuntimeMapping, ...] = ()
    unsupported_features: tuple[UnsupportedFeature, ...] = ()
    verification_hints: tuple[str, ...] = ()
    fidelity_notes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "intended_effect": self.intended_effect,
            "source_refs": [source_ref.to_dict() for source_ref in self.source_refs],
            "runtime_mappings": [
                mapping.to_dict() for mapping in self.runtime_mappings
            ],
            "unsupported_features": [
                feature.to_dict() for feature in self.unsupported_features
            ],
            "verification_hints": list(self.verification_hints),
            "fidelity_notes": list(self.fidelity_notes),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyVariant:
    variant_id: str
    title: str
    fidelity: str
    runtime_targets: tuple[RuntimeTargetBinding, ...]
    rules: tuple[PolicyRule, ...]
    description: str = ""
    unsupported_features: tuple[UnsupportedFeature, ...] = ()
    fidelity_notes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "title": self.title,
            "description": self.description,
            "fidelity": self.fidelity,
            "runtime_targets": [target.to_dict() for target in self.runtime_targets],
            "unsupported_features": [
                feature.to_dict() for feature in self.unsupported_features
            ],
            "fidelity_notes": list(self.fidelity_notes),
            "rules": [rule.to_dict() for rule in self.rules],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyDefinition:
    policy_id: str
    family: str
    title: str
    variants: tuple[PolicyVariant, ...]
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "variants": [variant.to_dict() for variant in self.variants],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyPack:
    catalog_schema_version: int
    pack_id: str
    title: str
    version: str
    source: SourceProvenance
    policies: tuple[PolicyDefinition, ...]
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    origin_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_schema_version": self.catalog_schema_version,
            "pack_id": self.pack_id,
            "title": self.title,
            "version": self.version,
            "description": self.description,
            "source": self.source.to_dict(),
            "policies": [policy.to_dict() for policy in self.policies],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ValidationReport:
    pack_id: str
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "passed": self.passed,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class PolicyValidationError(ValueError):
    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        messages = "; ".join(
            f"{issue.path}: {issue.message}" for issue in report.errors
        )
        super().__init__(messages or f"{report.pack_id} failed validation")


@dataclass(frozen=True)
class RuntimeTargetCapability:
    target: str
    contract_version: str
    supported_surfaces: tuple[str, ...]
    unsupported_surfaces: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "contract_version": self.contract_version,
            "supported_surfaces": list(self.supported_surfaces),
            "unsupported_surfaces": list(self.unsupported_surfaces),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class CompileDiagnostic:
    rule_id: str
    surface: str
    status: str
    message: str
    missing_surface: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "surface": self.surface,
            "status": self.status,
            "message": self.message,
            "missing_surface": self.missing_surface,
        }


@dataclass(frozen=True)
class DaytonaHardeningV1Plan:
    target: str
    compiler_contract_version: str
    catalog_schema_version: int
    pack_id: str
    policy_id: str
    variant_id: str
    fidelity: str
    source_digest: str
    hardening_config: dict[str, Any]
    execution: dict[str, Any]
    metadata: dict[str, Any]
    coverage: tuple[dict[str, Any], ...]
    unsupported_features: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "compiler_contract_version": self.compiler_contract_version,
            "catalog_schema_version": self.catalog_schema_version,
            "pack_id": self.pack_id,
            "policy_id": self.policy_id,
            "variant_id": self.variant_id,
            "fidelity": self.fidelity,
            "source_digest": self.source_digest,
            "hardening_config": dict(self.hardening_config),
            "execution": dict(self.execution),
            "metadata": dict(self.metadata),
            "coverage": [dict(item) for item in self.coverage],
            "unsupported_features": [dict(item) for item in self.unsupported_features],
        }


@dataclass(frozen=True)
class CompileResult:
    plan: DaytonaHardeningV1Plan
    diagnostics: tuple[CompileDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }
