from __future__ import annotations

from boundarybench.policy_catalog.catalog import (
    compile_policy_variant as _compile_policy_variant,
    list_policy_pack_ids as _list_policy_pack_ids,
    list_runtime_targets as _list_runtime_targets,
    load_policy_pack as _load_policy_pack,
    validate_policy_pack as _validate_policy_pack,
)
from boundarybench.policy_catalog.catalog.schema import (
    CompileResult,
    PolicyPack,
    RuntimeTargetCapability,
    ValidationReport,
)


def list_policy_pack_ids() -> list[str]:
    return _list_policy_pack_ids()


def list_runtime_targets() -> tuple[RuntimeTargetCapability, ...]:
    return _list_runtime_targets()


def load_policy_pack(pack_id: str, *, validate: bool = True) -> PolicyPack:
    return _load_policy_pack(pack_id, validate=validate)


def validate_policy_pack(pack: PolicyPack) -> ValidationReport:
    return _validate_policy_pack(pack)


def compile_policy_variant(
    *,
    pack_id: str,
    policy_id: str,
    variant_id: str,
    target: str = "daytona-hardening-v1",
) -> CompileResult:
    return _compile_policy_variant(
        pack_id=pack_id,
        policy_id=policy_id,
        variant_id=variant_id,
        target=target,
    )
