from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EnforcementEvent:
    """Structured hardening event suitable for Inspect sample metadata."""

    event_type: str
    backend: str
    config_id: str
    status: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "backend": self.backend,
            "config_id": self.config_id,
            "status": self.status,
            "message": self.message,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "EnforcementEvent":
        event_type = payload.get("event_type") or payload.get("type") or "unknown"
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        return cls(
            event_type=str(event_type),
            backend=str(payload.get("backend", "")),
            config_id=str(payload.get("config_id", "")),
            status=str(payload.get("status", "")),
            message=str(payload.get("message", "")),
            metadata=dict(metadata),
        )
