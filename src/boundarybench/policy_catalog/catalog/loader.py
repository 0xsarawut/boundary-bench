from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from boundarybench.policy_catalog.catalog.schema import (
    CATALOG_SCHEMA_VERSION,
    COMPILER_CONTRACT_VERSION,
    DAYTONA_HARDENING_V1,
    PolicyDefinition,
    PolicyPack,
    PolicyRule,
    PolicyVariant,
    RuntimeMapping,
    RuntimeTargetBinding,
    SourceProvenance,
    SourceReference,
    UnsupportedFeature,
)
from boundarybench.policy_catalog.catalog.validation import assert_valid_policy_pack


def catalog_data_root() -> Path:
    return Path(str(files("boundarybench.policy_catalog") / "data" / "catalog"))


def catalog_packs_root() -> Path:
    return catalog_data_root() / "packs"


def list_policy_pack_ids() -> list[str]:
    root = catalog_packs_root()
    if not root.exists():
        return []
    return sorted(path.name for path in root.iterdir() if (path / "pack.yaml").is_file())


def load_policy_pack(
    pack_id: str,
    *,
    validate: bool = True,
) -> PolicyPack:
    path = catalog_packs_root() / pack_id / "pack.yaml"
    if not path.is_file():
        known = ", ".join(list_policy_pack_ids())
        raise KeyError(f"Unknown policy pack {pack_id!r}; known packs: {known}")
    return load_policy_pack_from_path(path, validate=validate)


def load_policy_pack_from_path(
    path: str | Path,
    *,
    validate: bool = True,
) -> PolicyPack:
    source = Path(path)
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{source} must contain a YAML mapping")
    pack = policy_pack_from_mapping(payload, origin_path=str(source))
    if validate:
        assert_valid_policy_pack(pack)
    return pack


def policy_pack_from_mapping(
    payload: dict[str, Any],
    *,
    origin_path: str = "",
) -> PolicyPack:
    source = dict(payload.get("source") or {})
    return PolicyPack(
        catalog_schema_version=int(
            payload.get("catalog_schema_version") or CATALOG_SCHEMA_VERSION
        ),
        pack_id=str(payload.get("pack_id") or ""),
        title=str(payload.get("title") or ""),
        version=str(payload.get("version") or ""),
        description=str(payload.get("description") or ""),
        source=SourceProvenance(
            framework=str(source.get("framework") or ""),
            upstream_url=str(source.get("upstream_url") or ""),
            upstream_commit=str(source.get("upstream_commit") or ""),
            immutable_revision=str(source.get("immutable_revision") or ""),
            inspected_date=str(source.get("inspected_date") or ""),
            provenance_note=str(source.get("provenance_note") or ""),
            source_paths=_string_tuple(source.get("source_paths")),
            metadata=dict(source.get("metadata") or {}),
        ),
        policies=tuple(
            _policy_from_mapping(policy) for policy in payload.get("policies") or []
        ),
        metadata=dict(payload.get("metadata") or {}),
        origin_path=origin_path,
    )


def _policy_from_mapping(payload: dict[str, Any]) -> PolicyDefinition:
    return PolicyDefinition(
        policy_id=str(payload.get("policy_id") or ""),
        family=str(payload.get("family") or ""),
        title=str(payload.get("title") or ""),
        description=str(payload.get("description") or ""),
        variants=tuple(
            _variant_from_mapping(variant) for variant in payload.get("variants") or []
        ),
        metadata=dict(payload.get("metadata") or {}),
    )


def _variant_from_mapping(payload: dict[str, Any]) -> PolicyVariant:
    return PolicyVariant(
        variant_id=str(payload.get("variant_id") or ""),
        title=str(payload.get("title") or ""),
        description=str(payload.get("description") or ""),
        fidelity=str(payload.get("fidelity") or ""),
        runtime_targets=tuple(
            _runtime_target_from_mapping(target)
            for target in payload.get("runtime_targets") or []
        ),
        unsupported_features=tuple(
            _unsupported_feature_from_mapping(feature)
            for feature in payload.get("unsupported_features") or []
        ),
        fidelity_notes=_string_tuple(payload.get("fidelity_notes")),
        rules=tuple(_rule_from_mapping(rule) for rule in payload.get("rules") or []),
        metadata=dict(payload.get("metadata") or {}),
    )


def _runtime_target_from_mapping(payload: dict[str, Any]) -> RuntimeTargetBinding:
    return RuntimeTargetBinding(
        target=str(payload.get("target") or DAYTONA_HARDENING_V1),
        capability_set=str(payload.get("capability_set") or DAYTONA_HARDENING_V1),
        compiler_contract_version=str(
            payload.get("compiler_contract_version") or COMPILER_CONTRACT_VERSION
        ),
        metadata=dict(payload.get("metadata") or {}),
    )


def _rule_from_mapping(payload: dict[str, Any]) -> PolicyRule:
    return PolicyRule(
        rule_id=str(payload.get("rule_id") or ""),
        title=str(payload.get("title") or ""),
        description=str(payload.get("description") or ""),
        intended_effect=str(payload.get("intended_effect") or ""),
        source_refs=tuple(
            _source_ref_from_mapping(source_ref)
            for source_ref in payload.get("source_refs") or []
        ),
        runtime_mappings=tuple(
            _runtime_mapping_from_mapping(mapping)
            for mapping in payload.get("runtime_mappings") or []
        ),
        unsupported_features=tuple(
            _unsupported_feature_from_mapping(feature)
            for feature in payload.get("unsupported_features") or []
        ),
        verification_hints=_string_tuple(payload.get("verification_hints")),
        fidelity_notes=_string_tuple(payload.get("fidelity_notes")),
        metadata=dict(payload.get("metadata") or {}),
    )


def _source_ref_from_mapping(payload: dict[str, Any]) -> SourceReference:
    return SourceReference(
        framework=str(payload.get("framework") or ""),
        control_id=str(payload.get("control_id") or ""),
        title=str(payload.get("title") or ""),
        url=str(payload.get("url") or ""),
        path=str(payload.get("path") or ""),
        metadata=dict(payload.get("metadata") or {}),
    )


def _runtime_mapping_from_mapping(payload: dict[str, Any]) -> RuntimeMapping:
    return RuntimeMapping(
        target=str(payload.get("target") or DAYTONA_HARDENING_V1),
        surface=str(payload.get("surface") or ""),
        status=str(payload.get("status") or ""),
        values=_string_tuple(payload.get("values")),
        reason=str(payload.get("reason") or ""),
        missing_surface=str(payload.get("missing_surface") or ""),
        verification_hint=str(payload.get("verification_hint") or ""),
        metadata=dict(payload.get("metadata") or {}),
    )


def _unsupported_feature_from_mapping(payload: dict[str, Any]) -> UnsupportedFeature:
    return UnsupportedFeature(
        surface=str(payload.get("surface") or ""),
        reason=str(payload.get("reason") or ""),
        missing_surface=str(payload.get("missing_surface") or ""),
        verification_hint=str(payload.get("verification_hint") or ""),
        metadata=dict(payload.get("metadata") or {}),
    )


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value)
