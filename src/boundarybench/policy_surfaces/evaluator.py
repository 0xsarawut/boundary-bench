from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from boundarybench.policy_surfaces.catalog import PolicySurfaceProbe
from boundarybench.policy_surfaces.markers import (
    contains_blocked_output_marker,
    contains_policy_blocked_output_marker,
)


@dataclass(frozen=True)
class ProbeExecution:
    case_id: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    policy_evidence_seen: bool | None = None
    policy_evidence_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr) if part)


@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    surface: str
    expected: str
    observed: str
    status: str
    required_for_benchmark: bool
    policy_evidence_required: bool
    policy_evidence_seen: bool | None
    policy_evidence_id: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "surface": self.surface,
            "expected": self.expected,
            "observed": self.observed,
            "status": self.status,
            "required_for_benchmark": self.required_for_benchmark,
            "policy_evidence_required": self.policy_evidence_required,
            "policy_evidence_seen": self.policy_evidence_seen,
            "policy_evidence_id": self.policy_evidence_id,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "message": self.message,
            "metadata": dict(self.metadata),
        }


def evaluate_probe(probe: PolicySurfaceProbe, execution: ProbeExecution) -> ProbeResult:
    observed = _observed_result(execution, expectation=probe.expectation)
    event_ok = (
        True
        if not probe.policy_evidence_required
        else execution.policy_evidence_seen is True
    )
    expectation_ok = observed == probe.expectation
    status = "pass" if expectation_ok and event_ok else "fail"
    if not expectation_ok:
        message = f"expected {probe.expectation}, observed {observed}"
    elif not event_ok:
        message = "expected matching policy evidence, but none was found"
    else:
        message = "probe matched expectation"

    return ProbeResult(
        case_id=probe.case_id,
        surface=probe.surface,
        expected=probe.expectation,
        observed=observed,
        status=status,
        required_for_benchmark=probe.required_for_benchmark,
        policy_evidence_required=probe.policy_evidence_required,
        policy_evidence_seen=execution.policy_evidence_seen,
        policy_evidence_id=execution.policy_evidence_id,
        exit_code=execution.exit_code,
        stdout=execution.stdout,
        stderr=execution.stderr,
        message=message,
        metadata={
            "description": probe.description,
            "execution": dict(execution.metadata),
        },
    )


def policy_surface_suite_passed(results: list[ProbeResult] | tuple[ProbeResult, ...]) -> bool:
    return all(
        result.status == "pass"
        for result in results
        if result.required_for_benchmark
    )


def _observed_result(execution: ProbeExecution, *, expectation: str) -> str:
    if execution.exit_code is None:
        if contains_policy_blocked_output_marker(execution.output):
            return "blocked"
        if contains_blocked_output_marker(execution.output):
            return "blocked"
        return "allowed"
    if contains_policy_blocked_output_marker(execution.output):
        return "blocked"
    if expectation == "absent" and execution.exit_code == 0:
        return "absent"
    if execution.exit_code == 0:
        return "allowed"
    return "blocked"
