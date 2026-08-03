from __future__ import annotations

from typing import Any, Iterable

from boundarybench.enforcement.agentsh_events import (
    AgentSHEvent,
    redact_agentsh_event,
)
from boundarybench.enforcement.agentsh_policy_compiler import (
    compile_agentsh_policy,
)
from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle
from boundarybench.enforcement.agentsh_preflight import (
    build_agentsh_preflight_results,
)
from boundarybench.enforcement.agentsh_types import (
    AgentSHPreflightReport,
    AgentSHSession,
)
from boundarybench.enforcement.config import EnforcementConfig
from boundarybench.enforcement.preflight import preflight_passed


class FakeAgentSHBackend:
    """Deterministic AgentSH contract backend for local tests and smokes only."""

    backend_kind = "fake"
    evidence_tier = "contract_test"
    agentsh_version = "fake-agentsh-test-backend"
    wraps_upstream_solver = False

    def __init__(self, *, failure_mode: str | None = None) -> None:
        self.failure_mode = failure_mode

    def compile_policy(self, config: EnforcementConfig) -> AgentSHPolicyBundle:
        return compile_agentsh_policy(config)

    async def start_session(
        self, config: EnforcementConfig, policy: AgentSHPolicyBundle
    ) -> AgentSHSession:
        return AgentSHSession(
            session_id=f"fake-agentsh-{config.config_id}",
            policy=policy,
            backend_kind=self.backend_kind,
            evidence_tier=self.evidence_tier,
            agentsh_version=self.agentsh_version,
            metadata={
                "fake": True,
                "test_only": True,
                "benchmark_claim": "none",
                "silent_fallback": False,
            },
        )

    async def run_preflight(
        self, config: EnforcementConfig, session: AgentSHSession
    ) -> AgentSHPreflightReport:
        events = tuple(self._events_for(session))
        if self.failure_mode == "omit_supported_event":
            events = events[:-1]
        if self.failure_mode == "invert_supported_event":
            events = tuple(
                _replace_event_decision(event, "allowed") if index == 0 else event
                for index, event in enumerate(events)
            )
        fallback_evidence = _fake_runtime_fallback_evidence(session.policy)
        results = build_agentsh_preflight_results(
            config,
            session.policy,
            events,
            runtime_fallback_evidence=fallback_evidence,
            session_id=session.session_id,
        )
        passed = preflight_passed(results)
        return AgentSHPreflightReport(
            status="pass" if passed else "fail",
            passed=passed,
            backend=self.backend_kind,
            evidence_tier=self.evidence_tier,
            session=session,
            events=events,
            results=results,
            metadata={
                "fake": True,
                "test_only": True,
                "benchmark_claim": "none",
                "failure_mode": self.failure_mode,
            },
        )

    def _events_for(self, session: AgentSHSession) -> Iterable[AgentSHEvent]:
        for rule in session.policy.rules:
            if not rule.agentsh_supported:
                continue
            decision = "allowed" if rule.action in {"allow", "audit"} else "denied"
            yield AgentSHEvent(
                event_id=f"fake-{rule.check_id}",
                timestamp="",
                rule_id=rule.rule_id,
                check_id=rule.check_id,
                action=rule.action,
                decision=decision,
                command=None,
                path=None,
                session_id=session.session_id,
                policy_digest=session.policy.policy_digest,
                raw={
                    "fake": True,
                    "rule_id": rule.rule_id,
                    "check_id": rule.check_id,
                },
            )


def _fake_runtime_fallback_evidence(
    bundle: AgentSHPolicyBundle,
) -> dict[str, dict[str, Any]]:
    return {
        rule.check_id: {
            "status": "pass",
            "backend": "fake_runtime_fallback",
            "test_only": True,
            "reason": rule.reason,
        }
        for rule in bundle.rules
        if not rule.agentsh_supported
    }


def _replace_event_decision(event: AgentSHEvent, decision: str) -> AgentSHEvent:
    return redact_agentsh_event(
        AgentSHEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            rule_id=event.rule_id,
            check_id=event.check_id,
            action=event.action,
            decision=decision,
            command=event.command,
            path=event.path,
            session_id=event.session_id,
            policy_digest=event.policy_digest,
            raw=event.raw,
        )
    )
