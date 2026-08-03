from __future__ import annotations

import hashlib
import os

from boundarybench.enforcement.agentsh_policy_constants import (
    AGENTSH_POLICY_SCHEMA_VERSION,
    DEFAULT_AGENTSH_AUDIT_NAME,
    DEFAULT_AGENTSH_CONFIG_NAME,
    DEFAULT_AGENTSH_POLICY_DIR,
)
from boundarybench.enforcement.agentsh_policy_render import (
    policy_name_for_config,
    render_config_yaml,
    render_policy_document,
    render_policy_yaml,
)
from boundarybench.enforcement.agentsh_policy_rules import (
    compile_agentsh_baseline_probe_rules,
    compile_agentsh_policy_rules,
)
from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle
from boundarybench.enforcement.config import EnforcementConfig


def compile_agentsh_policy(
    config: EnforcementConfig, *, policy_dir: str | None = None
) -> AgentSHPolicyBundle:
    """Compile a small real AgentSH YAML policy for the Inspect proof path."""

    resolved_policy_dir = (
        policy_dir or os.environ.get("AGENTSH_POLICY_DIR") or DEFAULT_AGENTSH_POLICY_DIR
    )
    policy_name = policy_name_for_config(config.config_id)
    rules = compile_agentsh_policy_rules(config)
    baseline_probe_rules = compile_agentsh_baseline_probe_rules()
    policy_yaml = render_policy_yaml(config, policy_name)
    security_profile = _security_profile()
    disable_llm_proxy = _disable_llm_proxy(config)
    trace_network = _trace_network(config)
    audit_path = f"{resolved_policy_dir.rstrip('/')}/{DEFAULT_AGENTSH_AUDIT_NAME}"
    config_yaml = render_config_yaml(
        resolved_policy_dir,
        policy_name,
        audit_path=audit_path,
        security_profile=security_profile,
        disable_llm_proxy=disable_llm_proxy,
        trace_network=trace_network,
    )
    document = render_policy_document(config, policy_name, rules)
    digest = hashlib.sha256(policy_yaml.encode("utf-8")).hexdigest()
    return AgentSHPolicyBundle(
        config_id=config.config_id,
        policy_name=policy_name,
        policy_path=f"{resolved_policy_dir.rstrip('/')}/{policy_name}.yaml",
        config_path=f"{resolved_policy_dir.rstrip('/')}/{DEFAULT_AGENTSH_CONFIG_NAME}",
        policy_digest=digest,
        policy_schema_version=AGENTSH_POLICY_SCHEMA_VERSION,
        policy_document=document,
        policy_yaml=policy_yaml,
        config_yaml=config_yaml,
        rules=rules,
        audit_path=audit_path,
        metadata={
            "backend": "agentsh",
            "source_backend": config.backend,
            "task_id": config.task_id,
            "severity": config.severity,
            "evidence_tier": "real_policy_yaml",
            "base_policy_source": "boundary-sandbox",
            "base_policy_rules": [
                "deny-sysctl-write",
                "deny-service-restart",
                "deny-privilege-shell-args",
                "deny-system-admin",
                "deny-privilege-escalation",
                "deny-raw-network",
                "deny-debug-tools",
                "deny-system-pkg-install",
            ],
            "base_policy_probe_rules": [
                rule.to_metadata() for rule in baseline_probe_rules
            ],
            "security_profile": security_profile,
            "llm_proxy": "disabled" if disable_llm_proxy else "default",
            "trace_network": trace_network,
            "block_message_contract": (
                "AgentSH enforces the OS boundary; Inspect BoundaryBench surfaces "
                "normalized policy messages to the benchmark."
            ),
            "agentsh_owned_checks": [
                rule.check_id for rule in rules if rule.agentsh_supported
            ],
            "runtime_fallback_checks": [
                rule.check_id for rule in rules if not rule.agentsh_supported
            ],
        },
    )


def _security_profile() -> str:
    profile = os.environ.get("BOUNDARYBENCH_AGENTSH_SECURITY_PROFILE", "ptrace")
    normalized = profile.strip().lower()
    if normalized not in {"ptrace", "full"}:
        raise ValueError(
            "BOUNDARYBENCH_AGENTSH_SECURITY_PROFILE must be 'ptrace' or 'full'"
        )
    return normalized


def _disable_llm_proxy(config: EnforcementConfig) -> bool:
    return config.metadata.get("surface") == "operation_specific_path_mode_policy"


def _trace_network(config: EnforcementConfig) -> bool:
    return config.metadata.get("surface") != "operation_specific_path_mode_policy"
