from __future__ import annotations

import os

from boundarybench.enforcement.agentsh_fake import FakeAgentSHBackend
from boundarybench.enforcement.agentsh_preflight import (
    build_agentsh_preflight_results,
)
from boundarybench.enforcement.agentsh_real import RealAgentSHBackend
from boundarybench.enforcement.agentsh_types import (
    AgentSHBackend,
    AgentSHPreflightReport,
    AgentSHSession,
)


def load_agentsh_backend(*, backend: str | None = None) -> AgentSHBackend:
    requested = (
        backend
        if backend is not None
        else os.environ.get("BOUNDARYBENCH_AGENTSH_BACKEND")
    )
    if requested is None or not requested.strip():
        raise ValueError(
            "BOUNDARYBENCH_AGENTSH_BACKEND must be explicitly set to "
            "'fake' or 'real', or backend must be passed."
        )
    requested = requested.strip().lower()
    if requested == "fake":
        failure_mode = os.environ.get("BOUNDARYBENCH_AGENTSH_FAKE_FAILURE")
        return FakeAgentSHBackend(failure_mode=failure_mode)
    if requested == "real":
        return RealAgentSHBackend()
    raise ValueError("BOUNDARYBENCH_AGENTSH_BACKEND must be 'fake' or 'real'")


__all__ = [
    "AgentSHBackend",
    "AgentSHPreflightReport",
    "AgentSHSession",
    "FakeAgentSHBackend",
    "RealAgentSHBackend",
    "build_agentsh_preflight_results",
    "load_agentsh_backend",
]
