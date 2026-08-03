from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentSHPolicyRule:
    rule_id: str
    check_id: str
    hardening_type: str
    action: str
    selector: dict[str, Any]
    agentsh_supported: bool
    fallback: str | None = None
    reason: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "check_id": self.check_id,
            "hardening_type": self.hardening_type,
            "action": self.action,
            "selector": dict(self.selector),
            "agentsh_supported": self.agentsh_supported,
            "fallback": self.fallback,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AgentSHPolicyBundle:
    config_id: str
    policy_name: str
    policy_path: str
    config_path: str
    policy_digest: str
    policy_schema_version: str
    policy_document: dict[str, Any]
    policy_yaml: str
    config_yaml: str
    rules: tuple[AgentSHPolicyRule, ...]
    audit_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "config_id": self.config_id,
            "policy_name": self.policy_name,
            "policy_path": self.policy_path,
            "config_path": self.config_path,
            "policy_digest": self.policy_digest,
            "policy_schema_version": self.policy_schema_version,
            "audit_path": self.audit_path,
            "rules": [rule.to_metadata() for rule in self.rules],
            "metadata": dict(self.metadata),
        }
