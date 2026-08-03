from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from boundarybench.enforcement.agentsh_events import AgentSHEvent
from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle
from boundarybench.enforcement.config import EnforcementConfig
from boundarybench.enforcement.preflight import PreflightResult


class AgentSHBackend(Protocol):
    backend_kind: str
    evidence_tier: str

    def compile_policy(self, config: EnforcementConfig) -> AgentSHPolicyBundle:
        ...

    async def start_session(
        self, config: EnforcementConfig, policy: AgentSHPolicyBundle
    ) -> "AgentSHSession":
        ...

    async def run_preflight(
        self,
        config: EnforcementConfig,
        session: "AgentSHSession",
    ) -> "AgentSHPreflightReport":
        ...


@dataclass(frozen=True)
class AgentSHSession:
    session_id: str
    policy: AgentSHPolicyBundle
    backend_kind: str
    evidence_tier: str
    agentsh_version: str | None
    metadata: dict[str, Any]

    def to_metadata(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "backend": self.backend_kind,
            "evidence_tier": self.evidence_tier,
            "agentsh_version": self.agentsh_version,
            "policy": self.policy.to_metadata(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AgentSHPreflightReport:
    status: str
    passed: bool
    backend: str
    evidence_tier: str
    session: AgentSHSession
    events: tuple[AgentSHEvent, ...]
    results: tuple[PreflightResult, ...]
    errors: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] | None = None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "passed": self.passed,
            "backend": self.backend,
            "evidence_tier": self.evidence_tier,
            "session_id": self.session.session_id,
            "policy_digest": self.session.policy.policy_digest,
            "policy_path": self.session.policy.policy_path,
            "events": [event.to_metadata() for event in self.events],
            "results": [result.to_metadata() for result in self.results],
            "errors": [dict(error) for error in self.errors],
            "metadata": dict(self.metadata or {}),
        }
