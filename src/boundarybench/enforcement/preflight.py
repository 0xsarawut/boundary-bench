from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class PreflightResult:
    """One backend-neutral preflight check result."""

    check_id: str
    hardening_type: str
    expected_policy_result: str
    observed_runtime_result: str
    backend: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    backend_evidence: dict[str, Any] = field(default_factory=dict)
    agentsh_policy_result: str | None = None
    agentsh_event_seen: bool | None = None
    agentsh_event_id: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "hardening_type": self.hardening_type,
            "expected_policy_result": self.expected_policy_result,
            "observed_runtime_result": self.observed_runtime_result,
            "backend": self.backend,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "backend_evidence": dict(self.backend_evidence),
            "agentsh_policy_result": self.agentsh_policy_result,
            "agentsh_event_seen": self.agentsh_event_seen,
            "agentsh_event_id": self.agentsh_event_id,
        }


def preflight_passed(results: Iterable[PreflightResult]) -> bool:
    result_list = list(results)
    return bool(result_list) and all(result.status == "pass" for result in result_list)
