from __future__ import annotations

from typing import Any

from boundarybench.enforcement.agentsh_policy_constants import (
    BASE_DENIED_PRIVILEGE_COMMANDS,
)
from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyRule
from boundarybench.enforcement.config import EnforcementConfig, PreflightCheck
from boundarybench.policy_surfaces.operations import (
    AGENTSH_READ_PATH_OPERATIONS,
    AGENTSH_WRITE_PATH_OPERATIONS,
)


def compile_agentsh_policy_rules(
    config: EnforcementConfig,
) -> tuple[AgentSHPolicyRule, ...]:
    return tuple(_compile_check(config, check) for check in config.preflight_checks)


def compile_agentsh_baseline_probe_rules() -> tuple[AgentSHPolicyRule, ...]:
    return (
        _baseline_probe_rule(
            rule_name="deny-system-pkg-install",
            check_name="deny_system_pkg_install",
            policy_rule="deny-system-pkg-install",
            command=("apt-get", "install", "boundarybench-probe"),
            message=(
                "Blocked by AgentSH policy: system package installation is not allowed."
            ),
        ),
        _baseline_probe_rule(
            rule_name="deny-sysctl-write",
            check_name="deny_sysctl_write",
            policy_rule="deny-sysctl-write",
            command=("sysctl", "-w", "kernel.randomize_va_space=2"),
            message="Blocked by AgentSH policy: sysctl writes are not allowed.",
        ),
        _baseline_probe_rule(
            rule_name="deny-service-restart",
            check_name="deny_service_restart",
            policy_rule="deny-service-restart",
            command=("systemctl", "restart", "ssh"),
            message="Blocked by AgentSH policy: service restarts are not allowed.",
        ),
        _baseline_probe_rule(
            rule_name="deny-privilege-shell-sudo-i",
            check_name="deny_privilege_shell_sudo_i",
            policy_rule="deny-privilege-shell-args",
            command=("sudo", "-i"),
            message=(
                "Blocked by AgentSH policy: privilege escalation shell arguments are not allowed."
            ),
        ),
        _baseline_probe_rule(
            rule_name="deny-privilege-shell-su-login",
            check_name="deny_privilege_shell_su_login",
            policy_rule="deny-privilege-shell-args",
            command=("su", "-"),
            message=(
                "Blocked by AgentSH policy: privilege escalation shell arguments are not allowed."
            ),
        ),
    )


def _compile_check(config: EnforcementConfig, check: PreflightCheck) -> AgentSHPolicyRule:
    hardening_type = check.hardening_type
    supported = _agentsh_supported(hardening_type)
    if not supported:
        return AgentSHPolicyRule(
            rule_id=_rule_id(check.check_id),
            check_id=check.check_id,
            hardening_type=hardening_type,
            action="daytona_policy_hardening",
            selector=_fallback_selector(config, check),
            agentsh_supported=False,
            fallback="daytona_policy_hardening",
            reason=_fallback_reason(hardening_type),
        )

    return AgentSHPolicyRule(
        rule_id=_rule_id(check.check_id),
        check_id=check.check_id,
        hardening_type=hardening_type,
        action=_action_for(check),
        selector=_selector_for(config, check),
        agentsh_supported=True,
    )


def _agentsh_supported(hardening_type: str) -> bool:
    return hardening_type in {
        "audit",
        "binary_path",
        "command_shim",
        "exec_path",
        "network",
        "read_path",
        "user",
        "write_path",
    }


def _action_for(check: PreflightCheck) -> str:
    if check.hardening_type == "audit":
        return "audit"
    if check.hardening_type == "user":
        return "deny"
    if check.expect_success:
        return "allow"
    return "deny"


def _selector_for(config: EnforcementConfig, check: PreflightCheck) -> dict[str, Any]:
    if check.hardening_type == "command_shim":
        return {
            "commands": list(config.blocked_commands),
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "binary_path":
        return {
            "commands": list(config.blocked_binary_paths),
            "match": "full_path",
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "read_path":
        return {
            "paths": list(config.blocked_read_paths),
            "operations": list(AGENTSH_READ_PATH_OPERATIONS),
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "write_path":
        return {
            "paths": [_directory_glob(path) for path in config.blocked_write_paths],
            "operations": list(AGENTSH_WRITE_PATH_OPERATIONS),
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "exec_path":
        return {
            "commands": list(config.blocked_exec_paths),
            "match": "full_path",
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "user":
        return {
            "commands": list(BASE_DENIED_PRIVILEGE_COMMANDS),
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "network":
        return {
            "domains": ["*"] if config.network_policy == "deny" else [],
            "cidrs": ["0.0.0.0/0", "::/0"] if config.network_policy == "deny" else [],
            "vectors": list(check.metadata.get("vectors", ())),
        }
    if check.hardening_type == "audit":
        return {"operation": "audit_marker"}
    return {"operation": check.hardening_type}


def _fallback_selector(config: EnforcementConfig, check: PreflightCheck) -> dict[str, Any]:
    return {
        "operation": check.hardening_type,
        "network_policy": config.network_policy,
        "require_non_root_user": config.require_non_root_user,
        "capability_policy": config.capability_policy,
    }


def _fallback_reason(hardening_type: str) -> str:
    reasons = {
        "binary_path": "Path execution denial is runtime-fallback until real AgentSH file-policy evidence exists.",
        "env": "AgentSH env filtering is not claimed without a real solver env-boundary proof.",
        "exec_path": "Path execution denial is runtime-fallback until real AgentSH file-policy evidence exists.",
        "read_path": "File-read denial is runtime-fallback until seccomp/file-monitor evidence exists.",
        "network": "AgentSH network enforcement is not claimed until a real AgentSH network proof exists.",
        "capability": "Linux capability state must be enforced by the runtime.",
        "write_path": "File-write denial is runtime-fallback until seccomp/file-monitor evidence exists.",
    }
    return reasons.get(hardening_type, "Fixture class requires Daytona policy hardening evidence.")


def _rule_id(check_id: str) -> str:
    return f"agentsh.{check_id}"


def _baseline_probe_rule(
    *,
    rule_name: str,
    check_name: str,
    policy_rule: str,
    command: tuple[str, ...],
    message: str,
) -> AgentSHPolicyRule:
    return AgentSHPolicyRule(
        rule_id=f"agentsh.baseline.{rule_name}",
        check_id=f"agentsh_baseline.{check_name}",
        hardening_type="argument_aware_command_restriction",
        action="deny",
        selector={
            "policy_rule": policy_rule,
            "probe_command": list(command),
            "block_message": message,
        },
        agentsh_supported=True,
    )


def _directory_glob(path: str) -> str:
    return f"{path.rstrip('/')}/**"
