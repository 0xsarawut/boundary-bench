from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any

from boundarybench.daytona.hardening_config import (
    DEFAULT_CIDR_EGRESS_COMMAND_NAMES,
    DEFAULT_CIDR_EGRESS_DENYLIST,
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
    DEFAULT_DOMAIN_EGRESS_DIRECT_ALLOWLIST,
    normalize_domain_pattern,
)
from boundarybench.daytona.policy_axes import (
    SELECTOR_MODEL_PLANE,
    SELECTOR_NONE,
    SELECTOR_TRUSTED,
    _resolve_domain_allowlist,
)
from boundarybench.policy_catalog.catalog.capabilities import (
    SUPPORTED_DAYTONA_SURFACES,
    list_runtime_targets,
)
from boundarybench.policy_catalog.catalog.loader import load_policy_pack
from boundarybench.policy_catalog.catalog.schema import (
    COMPILER_CONTRACT_VERSION,
    DAYTONA_HARDENING_V1,
    CompileDiagnostic,
    CompileResult,
    DaytonaHardeningV1Plan,
    MappingStatus,
    PolicyPack,
    PolicyRule,
    UnsupportedFeature,
)
from boundarybench.policy_catalog.catalog.validation import (
    assert_valid_policy_pack,
)


def compile_policy_variant(
    *,
    pack_id: str,
    policy_id: str,
    variant_id: str,
    target: str = DAYTONA_HARDENING_V1,
) -> CompileResult:
    pack = load_policy_pack(pack_id)
    return compile_policy_variant_from_pack(
        pack=pack,
        policy_id=policy_id,
        variant_id=variant_id,
        target=target,
    )


def compile_policy_variant_from_pack(
    *,
    pack: PolicyPack,
    policy_id: str,
    variant_id: str,
    target: str = DAYTONA_HARDENING_V1,
) -> CompileResult:
    if target != DAYTONA_HARDENING_V1:
        raise ValueError(f"unsupported compile target: {target}")
    assert_valid_policy_pack(pack)
    policy = next(
        (candidate for candidate in pack.policies if candidate.policy_id == policy_id),
        None,
    )
    if policy is None:
        raise KeyError(f"Unknown policy_id {policy_id!r} in pack {pack.pack_id!r}")
    variant = next(
        (
            candidate
            for candidate in policy.variants
            if candidate.variant_id == variant_id
        ),
        None,
    )
    if variant is None:
        raise KeyError(f"Unknown variant_id {variant_id!r} in policy {policy_id!r}")

    hardening_config: dict[str, Any] = {
        "name": _hardening_config_name(
            policy.policy_id, variant.variant_id, variant.metadata
        ),
        "block_message": "Permission denied",
        "denied_exec_paths": [],
        "denied_command_names": [],
        "denied_path_exact": [],
        "denied_path_prefixes": [],
        "tee_denied_patterns": [],
        "child_network_command_names": [],
        "strip_env_vars": [],
        "egress_cidr_denylist": [],
        "egress_cidr_allowlist": [],
        "egress_cidr_default_action": "allow",
        "egress_cidr_command_names": [],
        "seccomp_block_syscalls": [],
        "egress_domain_denylist": [],
        "egress_domain_allowlist": [],
        "egress_domain_default_action": "allow",
        "native_egress_reject": False,
        "filesystem_scope": "open",
        "writable_path_prefixes": [],
        "secret_paths_root_owned": [],
        "lock_root_password": False,
        "no_new_privs": False,
        "drop_bounding_caps": False,
        "strip_setuid": False,
    }
    execution: dict[str, Any] = {
        "agent_user": "root",
        "isolate_network": False,
        "block_network": False,
        "block_child_shell_network": False,
        "overlays": [],
    }
    coverage: list[dict[str, Any]] = []
    diagnostics: list[CompileDiagnostic] = []
    unsupported_features: list[dict[str, Any]] = []

    for feature in variant.unsupported_features:
        unsupported_features.append(_unsupported_feature_to_coverage(feature))
    for rule in variant.rules:
        for feature in rule.unsupported_features:
            unsupported_features.append(
                {"rule_id": rule.rule_id, **_unsupported_feature_to_coverage(feature)}
            )
        _compile_rule(
            rule,
            hardening_config=hardening_config,
            execution=execution,
            coverage=coverage,
            diagnostics=diagnostics,
            unsupported_features=unsupported_features,
        )

    hardening_config = {
        key: _dedupe(value) if isinstance(value, list) else value
        for key, value in hardening_config.items()
    }
    execution["overlays"] = _dedupe(execution["overlays"])

    plan = DaytonaHardeningV1Plan(
        target=target,
        compiler_contract_version=COMPILER_CONTRACT_VERSION,
        catalog_schema_version=pack.catalog_schema_version,
        pack_id=pack.pack_id,
        policy_id=policy.policy_id,
        variant_id=variant.variant_id,
        fidelity=variant.fidelity,
        source_digest=_source_digest(pack),
        hardening_config=hardening_config,
        execution=execution,
        metadata={
            "policy": dict(policy.metadata),
            "variant": dict(variant.metadata),
        },
        coverage=tuple(coverage),
        unsupported_features=tuple(unsupported_features),
    )
    return CompileResult(plan=plan, diagnostics=tuple(diagnostics))


def _compile_rule(
    rule: PolicyRule,
    *,
    hardening_config: dict[str, Any],
    execution: dict[str, Any],
    coverage: list[dict[str, Any]],
    diagnostics: list[CompileDiagnostic],
    unsupported_features: list[dict[str, Any]],
) -> None:
    for mapping in rule.runtime_mappings:
        coverage_item = {
            "rule_id": rule.rule_id,
            "target": mapping.target,
            "surface": mapping.surface,
            "status": mapping.status,
            "values": list(mapping.values),
            "reason": mapping.reason,
            "missing_surface": mapping.missing_surface,
            "verification_hint": mapping.verification_hint,
            "metadata": dict(mapping.metadata),
        }
        coverage.append(coverage_item)
        if mapping.target != DAYTONA_HARDENING_V1:
            if mapping.status != MappingStatus.ENFORCED:
                unsupported_features.append(
                    {
                        "rule_id": rule.rule_id,
                        "surface": mapping.surface,
                        "status": mapping.status,
                        "reason": mapping.reason,
                        "missing_surface": mapping.missing_surface,
                        "verification_hint": mapping.verification_hint,
                    }
                )
                diagnostics.append(
                    CompileDiagnostic(
                        rule_id=rule.rule_id,
                        surface=mapping.surface,
                        status=mapping.status,
                        message=mapping.reason
                        or f"mapping is recorded for {mapping.target}",
                        missing_surface=mapping.missing_surface,
                    )
                )
            continue
        if mapping.status != MappingStatus.ENFORCED:
            unsupported_features.append(
                {
                    "rule_id": rule.rule_id,
                    "surface": mapping.surface,
                    "status": mapping.status,
                    "reason": mapping.reason,
                    "missing_surface": mapping.missing_surface,
                    "verification_hint": mapping.verification_hint,
                }
            )
            diagnostics.append(
                CompileDiagnostic(
                    rule_id=rule.rule_id,
                    surface=mapping.surface,
                    status=mapping.status,
                    message=mapping.reason
                    or "mapping is recorded but not compiled into Daytona hardening",
                    missing_surface=mapping.missing_surface,
                )
            )
            continue
        if mapping.surface not in SUPPORTED_DAYTONA_SURFACES:
            diagnostics.append(
                CompileDiagnostic(
                    rule_id=rule.rule_id,
                    surface=mapping.surface,
                    status=mapping.status,
                    message="surface is not compiled by daytona-hardening-v1",
                    missing_surface=mapping.missing_surface,
                )
            )
            continue
        _apply_supported_mapping(
            mapping.surface, mapping.values, hardening_config, execution
        )


def _apply_supported_mapping(
    surface: str,
    values: tuple[str, ...],
    hardening_config: dict[str, Any],
    execution: dict[str, Any],
) -> None:
    if surface == "command_name_denial":
        hardening_config["denied_command_names"].extend(values)
        execution["overlays"].append("blocked-surfaces")
    elif surface == "denied_exec_path":
        hardening_config["denied_exec_paths"].extend(values)
        execution["overlays"].append("blocked-surfaces")
    elif surface == "denied_path_exact":
        hardening_config["denied_path_exact"].extend(values)
        execution["overlays"].append("blocked-surfaces")
    elif surface == "denied_path_prefix":
        hardening_config["denied_path_prefixes"].extend(values)
        execution["overlays"].append("blocked-surfaces")
    elif surface == "denied_write_pattern":
        hardening_config["tee_denied_patterns"].extend(values)
        execution["overlays"].append("blocked-surfaces")
    elif surface == "env_var_strip":
        hardening_config["strip_env_vars"].extend(values)
        execution["overlays"].append("env-strip")
    elif surface == "child_process_network_block":
        hardening_config["child_network_command_names"].extend(values)
        execution["block_child_shell_network"] = True
        execution["overlays"].append("child-network")
    elif surface == "coarse_non_loopback_network_block":
        execution["block_network"] = True
        execution["isolate_network"] = False
        execution["overlays"].append("coarse-network-block")
    elif surface == "cidr_egress_policy":
        hardening_config["egress_cidr_denylist"].extend(
            _cidr_values_or_default(values)
        )
        if hardening_config["egress_cidr_default_action"] != "deny":
            hardening_config["egress_cidr_default_action"] = "allow"
        hardening_config["egress_cidr_command_names"].extend(
            DEFAULT_CIDR_EGRESS_COMMAND_NAMES
        )
    elif surface == "seccomp_syscall_policy":
        hardening_config["seccomp_block_syscalls"].extend(values)
        execution["overlays"].append("seccomp-syscall")
    elif surface == "domain_egress_policy":
        if _is_native_domain_egress_policy(values):
            default_action, selector = values
            hardening_config["egress_domain_default_action"] = default_action
            hardening_config["egress_domain_allowlist"].extend(
                _resolve_domain_allowlist(selector, ())
            )
        else:
            allowlist, denylist, default_action = _domain_policy_values_or_default(
                values
            )
            hardening_config["egress_domain_allowlist"].extend(allowlist)
            hardening_config["egress_domain_denylist"].extend(denylist)
            hardening_config["egress_domain_default_action"] = default_action
            hardening_config["egress_cidr_default_action"] = "deny"
            hardening_config["egress_cidr_allowlist"].extend(
                DEFAULT_DOMAIN_EGRESS_DIRECT_ALLOWLIST
            )
            hardening_config["egress_cidr_command_names"].extend(
                DEFAULT_CIDR_EGRESS_COMMAND_NAMES
            )
            execution["overlays"].append("domain-egress")
    elif surface == "non_root_user":
        execution["agent_user"] = values[0] if values else "daytona"
        execution["overlays"].append("nonroot-agent")
    elif surface == "native_egress_reject":
        hardening_config["native_egress_reject"] = True
    elif surface == "cidr_egress_denylist":
        hardening_config["egress_cidr_denylist"].extend(DEFAULT_CIDR_EGRESS_DENYLIST)
    elif surface == "writable_path_carveout_prefix":
        hardening_config["writable_path_prefixes"].extend(values)
        if hardening_config["filesystem_scope"] == "open":
            hardening_config["filesystem_scope"] = "workspace"
    elif surface == "read_only_root_filesystem":
        hardening_config["filesystem_scope"] = "read_only"
    elif surface == "secret_path_root_owned":
        hardening_config["secret_paths_root_owned"].extend(values)
    elif surface == "honeytoken_env_strip":
        hardening_config["strip_env_vars"].extend(values)
    elif surface == "root_password_lock":
        hardening_config["lock_root_password"] = True
    elif surface == "no_new_privileges":
        hardening_config["no_new_privs"] = True
    elif surface == "capability_bounding_drop":
        hardening_config["drop_bounding_caps"] = True
    elif surface == "setuid_bit_strip":
        hardening_config["strip_setuid"] = True


def _hardening_config_name(
    policy_id: str,
    variant_id: str,
    metadata: dict[str, Any],
) -> str:
    configured_name = metadata.get("hardening_config_name")
    if isinstance(configured_name, str) and configured_name:
        return configured_name
    return f"{policy_id}.{variant_id}"


def _cidr_values_or_default(values: tuple[str, ...]) -> tuple[str, ...]:
    cidrs: list[str] = []
    invalid_values: list[str] = []
    for value in values:
        try:
            cidrs.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            invalid_values.append(value)
    if invalid_values:
        raise ValueError(
            "cidr_egress_policy values must be CIDRs; invalid values: "
            + ", ".join(repr(value) for value in invalid_values)
        )
    return tuple(cidrs) or DEFAULT_CIDR_EGRESS_DENYLIST


_NATIVE_EGRESS_SELECTORS = frozenset(
    {SELECTOR_NONE, SELECTOR_TRUSTED, SELECTOR_MODEL_PLANE}
)


def _is_native_domain_egress_policy(values: tuple[str, ...]) -> bool:
    """True for the native axis shape ``(default_action, selector)``.

    Native ``domain_egress_policy`` mappings carry exactly two values — an
    ``allow``/``deny`` default action and one of the ``policy_axes`` selector
    names — none of which contain the ``:`` used by the legacy
    ``default:deny`` / ``allow:<domain>`` encoding, so the two shapes are
    unambiguous.
    """
    return (
        len(values) == 2
        and values[0] in ("allow", "deny")
        and values[1] in _NATIVE_EGRESS_SELECTORS
    )


def _domain_policy_values_or_default(
    values: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    raw_values = values or tuple(
        ("default:deny",)
        + tuple(f"allow:{value}" for value in DEFAULT_DOMAIN_EGRESS_ALLOWLIST)
    )
    allowlist: list[str] = []
    denylist: list[str] = []
    default_action = "deny"
    invalid_values: list[str] = []
    for value in raw_values:
        if value == "default:allow":
            default_action = "allow"
            continue
        if value == "default:deny":
            default_action = "deny"
            continue
        if value.startswith("allow:"):
            try:
                allowlist.append(normalize_domain_pattern(value.removeprefix("allow:")))
            except ValueError:
                invalid_values.append(value)
            continue
        if value.startswith("deny:"):
            try:
                denylist.append(normalize_domain_pattern(value.removeprefix("deny:")))
            except ValueError:
                invalid_values.append(value)
            continue
        invalid_values.append(value)
    if invalid_values:
        raise ValueError(
            "domain_egress_policy values must be default:allow, default:deny, "
            "allow:<domain>, or deny:<domain>; invalid values: "
            + ", ".join(repr(value) for value in invalid_values)
        )
    return tuple(allowlist), tuple(denylist), default_action


def _source_digest(pack: PolicyPack) -> str:
    payload = json.dumps(pack.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _unsupported_feature_to_coverage(feature: UnsupportedFeature) -> dict[str, Any]:
    return {
        "surface": feature.surface,
        "status": MappingStatus.UNSUPPORTED,
        "reason": feature.reason,
        "missing_surface": feature.missing_surface,
        "verification_hint": feature.verification_hint,
    }


def _dedupe(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


__all__ = [
    "compile_policy_variant",
    "compile_policy_variant_from_pack",
    "list_runtime_targets",
]
