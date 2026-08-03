"""Composable hardening policies for Terminal-Bench Daytona runs.

The Daytona task image is the baseline. A policy is a named stack of BoundaryBench
overlays layered on top of that baseline: agent user, blocked surfaces, env
stripping, and network controls. This keeps the control run honest: ``none`` is
not a special hardened variant, it is the Daytona/task-image baseline with no
BoundaryBench policy overlays.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

from boundarybench.enforcement.config import EnforcementConfig
from boundarybench.benchmarks.common.policies import (
    NIST_LINUX_80053_HIGH_POLICY,
    NIST_LINUX_80053_LOW_POLICY,
    NIST_LINUX_80053_MEDIUM_POLICY,
    NO_POLICY,
    nist_linux_80053_high_compile_result,
    nist_linux_80053_low_compile_result,
    nist_linux_80053_medium_compile_result,
)
from boundarybench.daytona.hardening_config import (
    DEFAULT_DAYTONA_HARDENING_CONFIG,
    DaytonaHardeningConfig,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    AxisPreset,
    Privilege,
    build_daytona_config_from_axes,
)
from boundarybench.daytona.runtime_gate_matrix import (
    MATRIX_POLICY_SPECS,
    RuntimeGatePolicySpec,
    build_daytona_config,
    get_matrix_policy_spec,
    unsupported_surfaces_for_spec,
)
from boundarybench.daytona.runtime_policy_probes import RuntimeUnsupportedSurface
from boundarybench.policy_catalog import CompileResult
from boundarybench.policy_catalog.catalog.schema import (
    AGENTSH_POLICY_V1,
    MappingStatus,
)


DEBUG_POLICY_OPT_IN_ENV = "BOUNDARYBENCH_ALLOW_DEBUG_POLICY"
_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class HardeningPolicy:
    """A named stack of BoundaryBench overlays applied to the Daytona baseline."""

    name: str
    config: DaytonaHardeningConfig
    overlays: tuple[str, ...] = ()
    agent_user: str = "root"
    isolate_network: bool = False
    block_network: bool = False
    block_child_shell_network: bool = True
    full_mac_enforcement: bool = False
    unsupported_surfaces: tuple[RuntimeUnsupportedSurface, ...] = ()
    runtime_probe_scope: str = "representative"
    agentsh_policy_config: EnforcementConfig | None = None
    debug_only: bool = False
    description: str = ""
    enforcement_mode: str = "legacy"

    def __post_init__(self) -> None:
        if self.enforcement_mode not in ("legacy", "native"):
            raise ValueError(
                f"unknown enforcement_mode: {self.enforcement_mode!r} "
                "(expected 'legacy' or 'native')"
            )

    @property
    def run_agent_as_root(self) -> bool:
        return self.agent_user == "root"

    @property
    def applies_hardening(self) -> bool:
        """Whether this policy actually applies hardening (vs. plain baseline).

        Native presets carry ``overlays=()`` — enforcement is mode-selected, not
        overlay-driven — so a ``bool(overlays)`` check mislabels every hardened
        native preset as baseline. For native policies this instead reads the
        config's active native mechanisms: only the ``control`` cell (n0-f0-p0,
        no active mechanism) is baseline; every other native preset is hardened.
        Legacy policies keep the historical ``bool(overlays)`` semantics.
        """

        if self.enforcement_mode == "native":
            c = self.config
            return bool(
                c.native_egress_reject
                or c.filesystem_scope != "open"
                or c.lock_root_password
                or c.no_new_privs
                or c.drop_bounding_caps
                or c.strip_setuid
                or c.secret_paths_root_owned
                or c.strip_env_vars
            )
        return bool(self.overlays)


def _blank_config(name: str) -> DaytonaHardeningConfig:
    """Return a named hardening config with no blocked-surface overlays."""

    return replace(
        DEFAULT_DAYTONA_HARDENING_CONFIG,
        name=name,
        denied_exec_paths=(),
        denied_command_names=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )


_NONE_CONFIG = _blank_config("none")
_NONROOT_CONFIG = _blank_config("nonroot")

_NIST_TERMINALBENCH_RUNTIME_SUPPORTED_CATALOG_GAPS = (
    "seccomp_syscall_policy",
)

def _runtime_unsupported_surfaces_from_compile_result(
    result: CompileResult,
    *,
    supported_surfaces: tuple[str, ...] = (),
) -> tuple[RuntimeUnsupportedSurface, ...]:
    surfaces: dict[str, RuntimeUnsupportedSurface] = {}
    supported = set(supported_surfaces)
    for feature in result.plan.unsupported_features:
        surface = str(feature.get("surface") or "")
        if not surface:
            continue
        if surface in supported:
            continue
        if surface in surfaces:
            continue
        reason = str(feature.get("reason") or "catalog mapping is not runtime-enforced")
        missing_surface = str(feature.get("missing_surface") or "") or None
        verification_hint = str(feature.get("verification_hint") or "") or None
        surfaces[surface] = RuntimeUnsupportedSurface(
            surface=surface,
            reason=reason,
            missing_surface=missing_surface,
            verification_hint=verification_hint,
        )
    return tuple(surfaces[surface] for surface in sorted(surfaces))


def _runtime_unsupported_surfaces_from_catalog() -> tuple[
    RuntimeUnsupportedSurface, ...
]:
    return _runtime_unsupported_surfaces_from_compile_result(
        nist_linux_80053_high_compile_result()
    )


def _agentsh_operation_path_config_from_compile_result(
    result: CompileResult,
) -> EnforcementConfig | None:
    read_paths: list[str] = []
    write_paths: list[str] = []
    for item in result.plan.coverage:
        if (
            item["target"] != AGENTSH_POLICY_V1
            or item["surface"] != "operation_specific_path_mode_policy"
            or item["status"] != MappingStatus.ENFORCED
        ):
            continue
        operation_mode = item.get("metadata", {}).get("operation_mode")
        if operation_mode == "read":
            read_paths.extend(str(value) for value in item["values"])
        elif operation_mode == "write":
            write_paths.extend(str(value) for value in item["values"])
    read_paths = _dedupe(read_paths)
    write_paths = _dedupe(write_paths)
    if not read_paths and not write_paths:
        return None
    return EnforcementConfig(
        config_id=f"{result.plan.policy_id}-agentsh-policy-v1",
        backend=AGENTSH_POLICY_V1,
        severity="benchmark",
        task_id=result.plan.policy_id,
        blocked_commands=(),
        blocked_binary_paths=(),
        blocked_read_paths=tuple(read_paths),
        blocked_write_paths=tuple(write_paths),
        blocked_exec_paths=(),
        blocked_env_vars=(),
        require_non_root_user=True,
        network_policy="not_claimed_by_backend",
        capability_policy="not_claimed_by_backend",
        preflight_checks=(),
        metadata={
            "policy_id": result.plan.policy_id,
            "variant_id": result.plan.variant_id,
            "runtime_target": AGENTSH_POLICY_V1,
            "surface": "operation_specific_path_mode_policy",
            "agentsh_write_paths_are_exact": True,
            "operation_specific_path_mode_policy": {
                "read_paths": read_paths,
                "write_paths": write_paths,
            },
        },
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


_NIST_LINUX_80053_HIGH_AGENTSH_CONFIG = _agentsh_operation_path_config_from_compile_result(
    nist_linux_80053_high_compile_result()
)
_NIST_LINUX_80053_MEDIUM_AGENTSH_CONFIG = _agentsh_operation_path_config_from_compile_result(
    nist_linux_80053_medium_compile_result()
)
_NIST_LINUX_80053_LOW_AGENTSH_CONFIG = _agentsh_operation_path_config_from_compile_result(
    nist_linux_80053_low_compile_result()
)


def _nist_terminalbench_runtime_supported_catalog_gaps(
    agentsh_policy_config: EnforcementConfig | None,
) -> tuple[str, ...]:
    supported = list(_NIST_TERMINALBENCH_RUNTIME_SUPPORTED_CATALOG_GAPS)
    if agentsh_policy_config is not None:
        supported.append("operation_specific_path_mode_policy")
    return tuple(supported)


def _overlays_for_matrix_spec(spec: RuntimeGatePolicySpec) -> tuple[str, ...]:
    if spec.environment == "none":
        return ()
    overlays = ["nonroot-agent", "blocked-surfaces", "env-strip"]
    overlays.append("seccomp-syscall")
    if spec.network in {"offline_tools", "trusted"}:
        overlays.extend(("cidr-egress", "domain-egress"))
    if spec.network == "offline_tools":
        overlays.append("child-network")
    if spec.command_filesystem == "read_only":
        overlays.append("read-only-workspace-artifacts")
    return tuple(overlays)


def _hardening_policy_from_matrix_spec(
    spec: RuntimeGatePolicySpec,
    *,
    name: str | None = None,
) -> HardeningPolicy:
    return HardeningPolicy(
        name=name or spec.policy_id,
        config=build_daytona_config(spec),
        overlays=_overlays_for_matrix_spec(spec),
        agent_user="root" if spec.environment == "none" else "daytona",
        isolate_network=False,
        block_network=False,
        block_child_shell_network=spec.network == "offline_tools",
        unsupported_surfaces=unsupported_surfaces_for_spec(spec),
    )


def _nist_policy_from_matrix_spec(policy_id: str) -> HardeningPolicy:
    spec = get_matrix_policy_spec(policy_id)
    compile_result_by_policy = {
        NIST_LINUX_80053_HIGH_POLICY: nist_linux_80053_high_compile_result,
        NIST_LINUX_80053_MEDIUM_POLICY: nist_linux_80053_medium_compile_result,
        NIST_LINUX_80053_LOW_POLICY: nist_linux_80053_low_compile_result,
    }
    catalog_unsupported = _runtime_unsupported_surfaces_from_compile_result(
        compile_result_by_policy[policy_id](),
        supported_surfaces=_NIST_TERMINALBENCH_RUNTIME_SUPPORTED_CATALOG_GAPS,
    )
    matrix_unsupported = unsupported_surfaces_for_spec(spec)
    unsupported_by_surface = {
        surface.surface: surface for surface in (*catalog_unsupported, *matrix_unsupported)
    }
    return replace(
        _hardening_policy_from_matrix_spec(spec, name=policy_id),
        runtime_probe_scope="all",
        unsupported_surfaces=tuple(
            unsupported_by_surface[surface]
            for surface in sorted(unsupported_by_surface)
        ),
    )


_MATRIX_POLICIES: dict[str, HardeningPolicy] = {
    spec.policy_id: _hardening_policy_from_matrix_spec(spec)
    for spec in MATRIX_POLICY_SPECS
    if spec.policy_id != NO_POLICY
}


def _hardening_policy_from_axis_preset(preset: AxisPreset) -> HardeningPolicy:
    """Build a native ``HardeningPolicy`` from an N×F×P axis preset.

    The config is generated task_id-less at registry-build time; network levels
    opt into per-task egress through their contribution data. ``daytona_eval``
    recomputes the config WITH the task id, while N5 remains fixed. Native
    enforcement is selected via
    ``enforcement_mode="native"`` (Task 9a) — not overlays — so ``overlays`` is
    empty and the install gate fires on the native mode. ``agent_user`` follows
    the privilege axis: only the P0 (root) control cell runs as root.
    """

    return HardeningPolicy(
        name=preset.name,
        config=build_daytona_config_from_axes(preset),
        overlays=(),
        agent_user="root" if preset.privilege == Privilege.P0 else "daytona",
        isolate_network=False,
        block_network=False,
        block_child_shell_network=False,
        unsupported_surfaces=(),
        runtime_probe_scope="all",
        enforcement_mode="native",
        description=preset.nist_story,
    )


POLICIES: dict[str, HardeningPolicy] = {}
for _preset in AXIS_PRESETS.values():
    _policy = _hardening_policy_from_axis_preset(_preset)
    POLICIES[_preset.name] = _policy

DEFAULT_POLICY_NAME = "control"


def resolve_policy(name: str | None) -> HardeningPolicy:
    """Return the named policy, or raise with the list of known names."""

    key = (name or DEFAULT_POLICY_NAME).strip() or DEFAULT_POLICY_NAME
    if key not in POLICIES:
        known = ", ".join(sorted(POLICIES))
        raise ValueError(f"unknown hardening policy {key!r}; known policies: {known}")
    return POLICIES[key]


def debug_policy_opt_in_enabled() -> bool:
    value = os.environ.get(DEBUG_POLICY_OPT_IN_ENV, "").strip().lower()
    return value in _TRUE_ENV_VALUES


def resolve_policy_for_run(name: str | None) -> HardeningPolicy:
    policy = resolve_policy(name)
    if policy.debug_only and not debug_policy_opt_in_enabled():
        raise ValueError(
            f"hardening policy {policy.name!r} is internal debug-only; set "
            f"{DEBUG_POLICY_OPT_IN_ENV}=1 to use it for diagnostics"
        )
    return policy
