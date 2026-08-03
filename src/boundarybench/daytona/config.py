from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from boundarybench.daytona.hardening_config import (
    DEFAULT_POLICY_BLOCK_MESSAGE,
)


DEFAULT_DAYTONA_SNAPSHOT = "boundary-policy-lab-v1"


@dataclass(frozen=True)
class DaytonaResourceProfile:
    """Expected resources baked into a Daytona snapshot."""

    cpu: int
    memory_gib: int
    disk_gib: int
    profile: str = "minimal"

    def to_metadata(self) -> dict[str, int | str]:
        return {
            "profile": self.profile,
            "cpu": self.cpu,
            "memory_gib": self.memory_gib,
            "disk_gib": self.disk_gib,
        }


DEFAULT_DAYTONA_RESOURCE_PROFILE = DaytonaResourceProfile(
    cpu=1,
    memory_gib=2,
    disk_gib=3,
)


def daytona_snapshot_from_env() -> str:
    """Return the configured Daytona snapshot, defaulting to the minimal base."""

    return (
        os.environ.get("BOUNDARYBENCH_DAYTONA_SNAPSHOT")
        or os.environ.get("BOUNDARY_DAYTONA_SNAPSHOT")
        or DEFAULT_DAYTONA_SNAPSHOT
    )


def daytona_resource_profile_from_env() -> DaytonaResourceProfile:
    """Return resource metadata for the selected snapshot.

    Daytona resources are attached to snapshots at push time. These values are
    recorded into artifacts and used to catch accidental drift to larger runs.
    """

    return DaytonaResourceProfile(
        cpu=_int_env("BOUNDARYBENCH_DAYTONA_CPU", DEFAULT_DAYTONA_RESOURCE_PROFILE.cpu),
        memory_gib=_int_env(
            "BOUNDARYBENCH_DAYTONA_MEMORY_GIB",
            DEFAULT_DAYTONA_RESOURCE_PROFILE.memory_gib,
        ),
        disk_gib=_int_env(
            "BOUNDARYBENCH_DAYTONA_DISK_GIB",
            DEFAULT_DAYTONA_RESOURCE_PROFILE.disk_gib,
        ),
        profile=os.environ.get("BOUNDARYBENCH_DAYTONA_RESOURCE_PROFILE", "minimal"),
    )


def daytona_policy_block_message_from_env() -> str:
    """Return the configured Daytona policy block message.

    Use the file form for multi-line experiment messages. The direct env var is
    useful for quick one-line local runs.
    """

    message_file = os.environ.get("BOUNDARYBENCH_POLICY_BLOCK_MESSAGE_FILE")
    if message_file:
        return _read_block_message_file(message_file)
    return (
        os.environ.get("BOUNDARYBENCH_POLICY_BLOCK_MESSAGE")
        or DEFAULT_POLICY_BLOCK_MESSAGE
    )


def read_daytona_policy_block_message_file(path: str) -> str:
    return _read_block_message_file(path)


def require_minimal_profile(
    snapshot: str,
    resources: DaytonaResourceProfile,
    *,
    allow_override: bool = False,
) -> None:
    """Fail when a run silently drifts away from the small Daytona baseline."""

    if allow_override:
        return
    expected = DEFAULT_DAYTONA_RESOURCE_PROFILE
    if snapshot != DEFAULT_DAYTONA_SNAPSHOT:
        raise ValueError(
            "Daytona benchmark runs default to the minimal AgentSH snapshot. "
            f"Got {snapshot!r}, expected {DEFAULT_DAYTONA_SNAPSHOT!r}. "
            "Set allow_resource_override=True only for an explicitly documented run."
        )
    if resources != expected:
        raise ValueError(
            "Daytona benchmark runs default to 1 CPU, 2 GiB RAM, 3 GiB disk. "
            f"Got {resources.to_metadata()!r}. "
            "Set allow_resource_override=True only for an explicitly documented run."
        )


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _read_block_message_file(path: str) -> str:
    message = Path(path).expanduser().read_text(encoding="utf-8")
    if message.endswith("\n"):
        message = message[:-1]
    if not message:
        raise ValueError(f"{path} must contain a non-empty policy block message")
    return message
