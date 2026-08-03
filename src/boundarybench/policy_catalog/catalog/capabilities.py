from __future__ import annotations

from boundarybench.policy_catalog.catalog.schema import (
    AGENTSH_POLICY_V1,
    COMPILER_CONTRACT_VERSION,
    DAYTONA_HARDENING_V1,
    RuntimeTargetCapability,
)


COMMAND_NAME_SURFACES = frozenset(
    {
        "command_name_denial",
        "child_process_network_block",
    }
)
ABSOLUTE_PATH_SURFACES = frozenset(
    {
        "denied_exec_path",
        "denied_path_exact",
        "denied_path_prefix",
        "secret_path_root_owned",
        "writable_path_carveout_prefix",
    }
)
ENV_VAR_SURFACES = frozenset({"env_var_strip"})
WRITE_PATTERN_SURFACES = frozenset({"denied_write_pattern"})
SYSCALL_SURFACES = frozenset({"seccomp_syscall_policy"})

SUPPORTED_DAYTONA_SURFACES = frozenset(
    {
        "command_name_denial",
        "denied_exec_path",
        "denied_path_exact",
        "denied_path_prefix",
        "denied_write_pattern",
        "env_var_strip",
        "non_root_user",
        "child_process_network_block",
        "coarse_non_loopback_network_block",
        "cidr_egress_policy",
        "seccomp_syscall_policy",
        "domain_egress_policy",
        "native_egress_reject",
        "cidr_egress_denylist",
        "writable_path_carveout_prefix",
        "read_only_root_filesystem",
        "secret_path_root_owned",
        "honeytoken_env_strip",
        "root_password_lock",
        "no_new_privileges",
        "capability_bounding_drop",
        "setuid_bit_strip",
    }
)

UNSUPPORTED_DAYTONA_SURFACES = frozenset(
    {
        "full_mac_enforcement",
        "argument_aware_command_restriction",
        "operation_specific_path_mode_policy",
        "full_auditd_compliance_evidence",
        "kernel_sysctl_service_state",
        "full_nist_compliance",
    }
)

KNOWN_DAYTONA_SURFACES = SUPPORTED_DAYTONA_SURFACES | UNSUPPORTED_DAYTONA_SURFACES
SUPPORTED_AGENTSH_SURFACES = frozenset(
    {
        "argument_aware_command_restriction",
        "operation_specific_path_mode_policy",
    }
)
UNSUPPORTED_AGENTSH_SURFACES = frozenset(
    {
        "cidr_egress_policy",
        "coarse_non_loopback_network_block",
        "domain_egress_policy",
        "full_auditd_compliance_evidence",
        "full_mac_enforcement",
        "full_nist_compliance",
        "kernel_sysctl_service_state",
        "seccomp_syscall_policy",
    }
)
KNOWN_AGENTSH_SURFACES = SUPPORTED_AGENTSH_SURFACES | UNSUPPORTED_AGENTSH_SURFACES
SUPPORTED_SURFACES_BY_TARGET = {
    DAYTONA_HARDENING_V1: SUPPORTED_DAYTONA_SURFACES,
    AGENTSH_POLICY_V1: SUPPORTED_AGENTSH_SURFACES,
}
UNSUPPORTED_SURFACES_BY_TARGET = {
    DAYTONA_HARDENING_V1: UNSUPPORTED_DAYTONA_SURFACES,
    AGENTSH_POLICY_V1: UNSUPPORTED_AGENTSH_SURFACES,
}
KNOWN_SURFACES_BY_TARGET = {
    target: SUPPORTED_SURFACES_BY_TARGET[target] | UNSUPPORTED_SURFACES_BY_TARGET[target]
    for target in SUPPORTED_SURFACES_BY_TARGET
}
KNOWN_RUNTIME_TARGETS = frozenset(SUPPORTED_SURFACES_BY_TARGET)


def daytona_hardening_v1_capability() -> RuntimeTargetCapability:
    return RuntimeTargetCapability(
        target=DAYTONA_HARDENING_V1,
        contract_version=COMPILER_CONTRACT_VERSION,
        supported_surfaces=tuple(sorted(SUPPORTED_DAYTONA_SURFACES)),
        unsupported_surfaces=tuple(sorted(UNSUPPORTED_DAYTONA_SURFACES)),
        notes=(
            "Domain egress policy is enforced by a controller-managed local HTTP(S) proxy plus direct-egress CIDR default-deny guard.",
            "CIDR egress policy is enforced by the v1 LD_PRELOAD socket filter for configured IP ranges.",
            "Seccomp syscall policy is limited to explicitly configured syscall deny lists with runtime probe evidence.",
            "Argument-aware command restrictions must be represented as approximate command-name denials or unsupported mappings.",
            "Path exact/prefix denial is operation-neutral access denial; write-specific behavior is limited to tee write patterns.",
            "Current native N×F×P presets compile egress, read-only/workspace filesystem, and privilege-lockdown surfaces from policy_axes; generic explicit real credential-path and env-strip mappings remain supported but are not emitted by current presets, so F1 credential protection is not_applicable by default.",
            "Native execution sanitizes CANONICAL_INFRA_KEY_ENV_NAMES for every preset as a setup invariant, independent of F-axis catalog mappings; required adapter-specific aliases remain available for child authentication.",
            "Full MAC, auditd, kernel, sysctl, service-state, and compliance evidence controls are outside this runtime target.",
        ),
    )


def agentsh_policy_v1_capability() -> RuntimeTargetCapability:
    return RuntimeTargetCapability(
        target=AGENTSH_POLICY_V1,
        contract_version=COMPILER_CONTRACT_VERSION,
        supported_surfaces=tuple(sorted(SUPPORTED_AGENTSH_SURFACES)),
        unsupported_surfaces=tuple(sorted(UNSUPPORTED_AGENTSH_SURFACES)),
        notes=(
            "AgentSH is a supplemental runtime policy target in this catalog.",
            "Argument-aware command restrictions and operation-specific read/write path policy are counted as supported when backed by AgentSH probes.",
            "Domain/CIDR egress, auditd, MAC, seccomp, kernel/service state, and full NIST compliance remain unsupported until real probes pass.",
        ),
    )


def list_runtime_targets() -> tuple[RuntimeTargetCapability, ...]:
    return (daytona_hardening_v1_capability(), agentsh_policy_v1_capability())
