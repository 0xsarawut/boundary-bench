from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from boundarybench.daytona.hardening_config import DaytonaHardeningConfig
from boundarybench.daytona.runtime_gate_matrix import (
    build_daytona_config,
    get_matrix_policy_spec,
)
from boundarybench.policy_catalog import CompileResult, compile_policy_variant


NO_POLICY = "none"
BASIC_ONLY_POLICY = "basic-only"
NIST_LINUX_80053_LOW_POLICY = "nist-linux-80053-low"
NIST_LINUX_80053_MEDIUM_POLICY = "nist-linux-80053-medium"
NIST_LINUX_80053_HIGH_POLICY = "nist-linux-80053-high"
NIST_LINUX_SECURITY_PACK = "nist-linux-security"
NIST_LINUX_80053_HIGH_VARIANT = "nist-linux-80053-high-daytona-v1"
NIST_LINUX_80053_MEDIUM_VARIANT = "nist-linux-80053-medium-daytona-v1"
NIST_LINUX_80053_LOW_VARIANT = "nist-linux-80053-low-daytona-v1"


@lru_cache(maxsize=1)
def nist_linux_80053_high_compile_result() -> CompileResult:
    """Compile the NIST-derived High benchmark profile from the in-repo catalog."""

    return compile_policy_variant(
        pack_id=NIST_LINUX_SECURITY_PACK,
        policy_id=NIST_LINUX_80053_HIGH_POLICY,
        variant_id=NIST_LINUX_80053_HIGH_VARIANT,
    )


def nist_linux_80053_high_hardening_config() -> DaytonaHardeningConfig:
    """NIST-derived High benchmark profile generated from the gate matrix."""

    return build_daytona_config(get_matrix_policy_spec(NIST_LINUX_80053_HIGH_POLICY))


def basic_only_hardening_config() -> DaytonaHardeningConfig:
    """Basic environment setup without a network or command/filesystem gate."""

    return build_daytona_config(get_matrix_policy_spec(BASIC_ONLY_POLICY))


@lru_cache(maxsize=1)
def nist_linux_80053_medium_compile_result() -> CompileResult:
    """Compile the NIST-derived Medium benchmark profile from the in-repo catalog."""

    return compile_policy_variant(
        pack_id=NIST_LINUX_SECURITY_PACK,
        policy_id=NIST_LINUX_80053_MEDIUM_POLICY,
        variant_id=NIST_LINUX_80053_MEDIUM_VARIANT,
    )


def nist_linux_80053_medium_hardening_config() -> DaytonaHardeningConfig:
    """NIST-derived Medium benchmark profile generated from the gate matrix."""

    return build_daytona_config(get_matrix_policy_spec(NIST_LINUX_80053_MEDIUM_POLICY))


@lru_cache(maxsize=1)
def nist_linux_80053_low_compile_result() -> CompileResult:
    """Compile the NIST-derived Low benchmark profile from the in-repo catalog."""

    return compile_policy_variant(
        pack_id=NIST_LINUX_SECURITY_PACK,
        policy_id=NIST_LINUX_80053_LOW_POLICY,
        variant_id=NIST_LINUX_80053_LOW_VARIANT,
    )


def nist_linux_80053_low_hardening_config() -> DaytonaHardeningConfig:
    """NIST-derived Low benchmark profile generated from the gate matrix."""

    return build_daytona_config(get_matrix_policy_spec(NIST_LINUX_80053_LOW_POLICY))


@dataclass(frozen=True)
class RunPolicy:
    name: str
    hardening_config: DaytonaHardeningConfig | None

    @property
    def applies_hardening(self) -> bool:
        return self.hardening_config is not None


RUN_POLICIES: dict[str, RunPolicy] = {
    NO_POLICY: RunPolicy(name=NO_POLICY, hardening_config=None),
    BASIC_ONLY_POLICY: RunPolicy(
        name=BASIC_ONLY_POLICY,
        hardening_config=basic_only_hardening_config(),
    ),
    NIST_LINUX_80053_LOW_POLICY: RunPolicy(
        name=NIST_LINUX_80053_LOW_POLICY,
        hardening_config=nist_linux_80053_low_hardening_config(),
    ),
    NIST_LINUX_80053_MEDIUM_POLICY: RunPolicy(
        name=NIST_LINUX_80053_MEDIUM_POLICY,
        hardening_config=nist_linux_80053_medium_hardening_config(),
    ),
    NIST_LINUX_80053_HIGH_POLICY: RunPolicy(
        name=NIST_LINUX_80053_HIGH_POLICY,
        hardening_config=nist_linux_80053_high_hardening_config(),
    ),
}
RUN_POLICY_ALIASES = {"control": NO_POLICY}


def resolve_run_policy(name: str | None) -> RunPolicy:
    requested = (name or NO_POLICY).strip() or NO_POLICY
    key = RUN_POLICY_ALIASES.get(requested, requested)
    if key in RUN_POLICIES:
        return RUN_POLICIES[key]
    try:
        from boundarybench.terminalbench.policies import resolve_policy

        hardening_policy = resolve_policy(key)
    except Exception as exc:
        known = ", ".join(sorted(RUN_POLICIES))
        raise ValueError(
            f"unknown run policy {key!r}; known policies: {known}"
        ) from exc
    return RunPolicy(name=key, hardening_config=hardening_policy.config)
