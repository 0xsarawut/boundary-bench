from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle


REDACTED = "[REDACTED]"
SECRET_FIELD_MARKERS = ("secret", "token", "api_key", "apikey", "password", "credential")


@dataclass(frozen=True)
class AgentSHEvent:
    event_id: str
    timestamp: str
    rule_id: str | None
    check_id: str | None
    action: str
    decision: str
    command: str | None
    path: str | None
    session_id: str | None = None
    policy_digest: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "check_id": self.check_id,
            "action": self.action,
            "decision": self.decision,
            "command": self.command,
            "path": self.path,
            "session_id": self.session_id,
            "policy_digest": self.policy_digest,
            "raw": _redact_mapping(self.raw, set()),
        }

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "AgentSHEvent":
        return cls(
            event_id=str(payload.get("event_id") or payload.get("id") or ""),
            timestamp=str(payload.get("timestamp") or ""),
            rule_id=_optional_str(payload.get("rule_id")),
            check_id=_optional_str(payload.get("check_id")),
            action=str(payload.get("action") or ""),
            decision=str(payload.get("decision") or ""),
            command=_optional_str(payload.get("command")),
            path=_optional_str(payload.get("path")),
            session_id=_optional_str(payload.get("session_id")),
            policy_digest=_optional_str(payload.get("policy_digest")),
            raw=dict(payload.get("raw") or payload),
        )


def redact_agentsh_event(
    event: AgentSHEvent, *, secret_values: Iterable[str] = ()
) -> AgentSHEvent:
    secrets = {value for value in secret_values if value}
    return AgentSHEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        rule_id=event.rule_id,
        check_id=event.check_id,
        action=event.action,
        decision=event.decision,
        command=_redact_value(event.command, secrets),
        path=_redact_value(event.path, secrets),
        session_id=event.session_id,
        policy_digest=event.policy_digest,
        raw=_redact_mapping(event.raw, secrets),
    )


def match_agentsh_events_to_checks(
    bundle: AgentSHPolicyBundle,
    events: Iterable[AgentSHEvent],
    *,
    session_id: str | None = None,
) -> dict[str, AgentSHEvent]:
    rule_to_check = {rule.rule_id: rule.check_id for rule in bundle.rules}
    matched: dict[str, AgentSHEvent] = {}
    for event in events:
        if session_id is not None and event.session_id != session_id:
            continue
        if session_id is not None and event.policy_digest != bundle.policy_digest:
            continue
        if session_id is None and event.policy_digest not in {None, bundle.policy_digest}:
            continue
        check_id = event.check_id or (rule_to_check.get(event.rule_id or ""))
        if check_id and check_id not in matched:
            matched[check_id] = event
    return matched


def _redact_mapping(payload: dict[str, Any], secrets: set[str]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_secret_field(key):
            redacted[key] = REDACTED
            continue
        redacted[key] = _redact_nested(value, secrets)
    return redacted


def _redact_nested(value: Any, secrets: set[str]) -> Any:
    if isinstance(value, dict):
        return _redact_mapping(value, secrets)
    if isinstance(value, list):
        return [_redact_nested(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_nested(item, secrets) for item in value)
    return _redact_value(value, secrets)


def _redact_value(value: Any, secrets: set[str]) -> Any:
    if not isinstance(value, str):
        return value
    redacted = value
    for secret in secrets:
        redacted = redacted.replace(secret, REDACTED)
    return redacted


def _is_secret_field(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(marker in normalized for marker in SECRET_FIELD_MARKERS)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
