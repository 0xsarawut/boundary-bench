from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput
from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import Generate, Solver, TaskState, solver


@dataclass(frozen=True)
class SmokeRun:
    """Result payload produced by the local fake backend."""

    stdout: str
    events: list[dict[str, Any]]
    metadata: dict[str, Any]


def _smoke_samples() -> list[Sample]:
    """Create the single smoke sample used to validate Inspect wiring."""

    return [
        Sample(
            id="local-fake-smoke",
            input=(
                "Run the local fake smoke path. This sample proves "
                "Inspect plugin discovery, task execution, scoring, and log "
                "writing only."
            ),
            target="local_fake_smoke_ok",
            metadata={
                "enforcement": "local_fake",
                "control_mode": False,
                "hardened_execution": False,
                "purpose": "inspect_extension_smoke",
                "benchmark_claim": "none",
            },
        )
    ]


@solver
def local_fake_runner(
    enforcement: str = "local_fake",
    local_fake_delay_seconds: float = 0.0,
) -> Solver:
    """Return a solver that records a local fake smoke result."""

    delay_seconds = _parse_delay_seconds(local_fake_delay_seconds)

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        """Execute the local fake backend for one Inspect sample."""

        if delay_seconds:
            await asyncio.sleep(delay_seconds)
        run = _run_local_fake(
            state,
            enforcement=enforcement,
            delay_seconds=delay_seconds,
        )
        state.metadata["local_fake"] = run.metadata
        state.metadata["events"] = run.events
        state.output = ModelOutput(
            model=str(state.model),
            completion=run.stdout,
            metadata=run.metadata,
        )
        state.completed = True
        return state

    return solve


def _run_local_fake(
    state: TaskState,
    *,
    enforcement: str,
    delay_seconds: float = 0.0,
) -> SmokeRun:
    """Run the local fake backend without external services or benchmark claims."""

    if enforcement != "local_fake":
        raise ValueError("local fake smoke supports only enforcement=local_fake")

    event = {
        "type": "local_fake_smoke",
        "sample_id": state.sample_id,
        "status": "ok",
    }
    metadata = {
        "backend": "local_fake",
        "delay_seconds": delay_seconds,
        "smoke_result": "local_fake_smoke_ok",
    }
    return SmokeRun(
        stdout="local_fake_smoke_ok",
        events=[event],
        metadata=metadata,
    )


def _parse_delay_seconds(value: float | int | str) -> float:
    try:
        delay_seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"local_fake_delay_seconds must be a non-negative number, got {value!r}"
        ) from exc
    if delay_seconds < 0:
        raise ValueError(
            f"local_fake_delay_seconds must be >= 0, got {delay_seconds:g}"
        )
    return delay_seconds


@scorer(metrics=[])
def smoke_scorer():
    """Return the local fake smoke-only scorer."""

    async def score(state: TaskState, target: Any) -> Score:
        """Score only the local fake smoke completion and backend metadata."""

        output = getattr(getattr(state, "output", None), "completion", "")
        target_text = target.text if hasattr(target, "text") else str(target)
        metadata = dict(getattr(state, "metadata", {}) or {})
        local_fake = dict(metadata.get("local_fake", {}) or {})
        passed = (
            output.strip() == target_text and local_fake.get("backend") == "local_fake"
        )
        return Score(
            value=1.0 if passed else 0.0,
            answer="success" if passed else "failure",
            explanation="Local fake smoke scorer",
            metadata={
                "scorer": "smoke_only",
                "smoke_result": local_fake.get("smoke_result"),
            },
        )

    return score
