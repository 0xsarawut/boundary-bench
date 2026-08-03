from __future__ import annotations

from typing import Any, Iterable

from boundarybench.enforcement.agentsh_events import (
    AgentSHEvent,
    match_agentsh_events_to_checks,
)
from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle
from boundarybench.enforcement.config import EnforcementConfig
from boundarybench.enforcement.preflight import PreflightResult


def build_agentsh_preflight_results(
    config: EnforcementConfig,
    bundle: AgentSHPolicyBundle,
    events: Iterable[AgentSHEvent],
    *,
    runtime_fallback_evidence: dict[str, dict[str, Any]] | None = None,
    session_id: str | None = None,
) -> tuple[PreflightResult, ...]:
    """Map AgentSH events and runtime fallbacks into backend-neutral preflight results."""

    matched_events = match_agentsh_events_to_checks(
        bundle, events, session_id=session_id
    )
    fallback_evidence = runtime_fallback_evidence or {}
    config_checks = {check.check_id: check for check in config.preflight_checks}
    results: list[PreflightResult] = []
    for rule in bundle.rules:
        check = config_checks[rule.check_id]
        event = matched_events.get(rule.check_id)
        if not rule.agentsh_supported:
            evidence = fallback_evidence.get(rule.check_id)
            fallback_passed = evidence is not None and str(
                evidence.get("status", "")
            ).lower() in {"pass", "passed", "success", "ok"}
            results.append(
                PreflightResult(
                    check_id=rule.check_id,
                    hardening_type=rule.hardening_type,
                    expected_policy_result="daytona_policy_hardening",
                    observed_runtime_result=(
                        "daytona_policy_hardening_passed"
                        if fallback_passed
                        else "fallback_required"
                    ),
                    backend="agentsh",
                    status="pass" if fallback_passed else "fallback_required",
                    exit_code=None,
                    stdout="",
                    stderr="" if fallback_passed else "Runtime fallback evidence required",
                    backend_evidence={
                        "agentsh_supported": False,
                        "fallback": rule.fallback,
                        "reason": rule.reason,
                        "runtime_fallback_evidence": dict(evidence or {}),
                    },
                    agentsh_policy_result=(
                        "fallback_passed" if fallback_passed else "fallback_required"
                    ),
                    agentsh_event_seen=False,
                    agentsh_event_id=None,
                )
            )
            continue

        expected = "allow" if check.expect_success else "deny"
        event_seen = event is not None
        observed = event.decision if event is not None else "missing_event"
        passed = event_seen and _decision_matches(expected, observed)
        if (
            passed
            and rule.hardening_type == "user"
            and event is not None
            and event.raw.get("os_boundary_enforced") is False
        ):
            passed = False
        results.append(
            PreflightResult(
                check_id=rule.check_id,
                hardening_type=rule.hardening_type,
                expected_policy_result=expected,
                observed_runtime_result=observed,
                backend="agentsh",
                status="pass" if passed else "fail",
                exit_code=None,
                stdout="",
                stderr=(
                    ""
                    if passed
                    else "AgentSH event evidence missing or unexpected"
                ),
                backend_evidence={
                    "agentsh_supported": True,
                    "rule_id": rule.rule_id,
                    "action": rule.action,
                    "block_message": (
                        event.raw.get("normalized_block_message")
                        if event is not None
                        else None
                    ),
                    "os_boundary_enforced": (
                        event.raw.get("os_boundary_enforced")
                        if event is not None
                        else None
                    ),
                    "os_boundary_event_type": (
                        event.raw.get("os_boundary_event_type")
                        if event is not None
                        else None
                    ),
                    "subprocess_os_boundary_enforced": (
                        event.raw.get("subprocess_os_boundary_enforced")
                        if event is not None
                        else None
                    ),
                    "ptrace_execve_deny_count": (
                        event.raw.get("ptrace_execve_deny_count")
                        if event is not None
                        else None
                    ),
                    "direct_probe_decision": (
                        event.raw.get("direct_probe_decision")
                        if event is not None
                        else None
                    ),
                    "subprocess_probe_decision": (
                        event.raw.get("subprocess_probe_decision")
                        if event is not None
                        else None
                    ),
                },
                agentsh_policy_result=observed,
                agentsh_event_seen=event_seen,
                agentsh_event_id=event.event_id if event is not None else None,
            )
        )
    return tuple(results)


def _decision_matches(expected: str, observed: str) -> bool:
    normalized = observed.lower()
    if expected == "deny":
        return normalized in {"deny", "denied", "block", "blocked"}
    if expected == "allow":
        return normalized in {"allow", "allowed", "pass", "passed"}
    return normalized == expected
