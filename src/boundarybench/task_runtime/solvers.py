from __future__ import annotations

from typing import Any

from inspect_ai.model import ModelOutput
from inspect_ai.solver import Generate, Solver, TaskState, solver

from boundarybench.task_runtime.loading import (
    _collect_events,
    _load_agentsh_runtime,
    _maybe_await,
    _preflight_passed,
    _to_metadata,
)


@solver
def agentsh_solver(
    upstream_solver: Solver,
    hardening_config: str,
    task_id: str | None = None,
    preflight_only: bool = False,
) -> Solver:
    """Compile AgentSH policy, start a session, and gate Harbor execution."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata = dict(state.metadata or {})
        runtime = _load_agentsh_runtime()
        resolved_task_id = task_id or str(state.sample_id)
        config = await _maybe_await(
            runtime.load_config(hardening_config, resolved_task_id)
        )
        config_metadata = _to_metadata(config)

        state.metadata.update(
            {
                "enforcement": "agentsh",
                "severity": "sev1",
                "control_mode": False,
                "hardened_execution": True,
                "hardening_config": hardening_config,
                "preflight_only": preflight_only,
                "benchmark_claim": "none",
                "harbor_verifier_ran": False,
                "terminal_bench_score_eligible": False,
            }
        )
        state.metadata["hardening"] = {
            "enforcement": "agentsh",
            "config": config_metadata,
            "preflight_only": preflight_only,
            "agent_started": False,
            "agentsh_backend": getattr(runtime.backend, "backend_kind", None),
            "evidence_tier": getattr(runtime.backend, "evidence_tier", None),
            "benchmark_claim": "none",
            "agentsh_can_wrap_upstream": bool(
                getattr(runtime.backend, "wraps_upstream_solver", False)
            ),
            "harbor_verifier_ran": False,
            "terminal_bench_score_eligible": False,
        }

        try:
            policy = await _maybe_await(runtime.backend.compile_policy(config))
            policy_metadata = _to_metadata(policy)
            state.metadata["agentsh_policy"] = policy_metadata
            state.metadata["hardening"]["policy"] = policy_metadata

            session = await _maybe_await(runtime.backend.start_session(config, policy))
            session_metadata = _to_metadata(session)
            state.metadata["agentsh_session"] = session_metadata
            state.metadata["hardening"]["session"] = session_metadata

            preflight_report = await _maybe_await(
                runtime.backend.run_preflight(config, session)
            )
        except Exception as exc:
            return _agentsh_fail_closed_state(
                state,
                failure_type="agentsh_setup_or_session_failure",
                error=exc,
            )

        preflight_metadata = _to_metadata(preflight_report)
        state.metadata["hardening_preflight"] = preflight_metadata
        state.metadata["agentsh_preflight"] = preflight_metadata
        state.metadata["hardening"]["preflight"] = preflight_metadata
        state.metadata["hardening"]["events"] = _collect_events(preflight_metadata)
        state.metadata["hardening"]["agentsh_backend"] = preflight_metadata.get(
            "backend"
        )
        state.metadata["hardening"]["evidence_tier"] = preflight_metadata.get(
            "evidence_tier"
        )
        backend_wraps_upstream = bool(
            getattr(runtime.backend, "wraps_upstream_solver", False)
        )
        state.metadata["hardening"]["agentsh_can_wrap_upstream"] = (
            backend_wraps_upstream
        )
        state.metadata["hardening"]["benchmark_claim"] = _agentsh_benchmark_claim(
            preflight_metadata=preflight_metadata,
            backend_wraps_upstream=backend_wraps_upstream,
        )
        state.metadata["benchmark_claim"] = state.metadata["hardening"][
            "benchmark_claim"
        ]

        if not _preflight_passed(preflight_metadata):
            state.metadata["hardening"]["agent_started"] = False
            state.output = ModelOutput(
                model=str(state.model),
                completion="agentsh_preflight_failed",
                metadata={"hardening_preflight": preflight_metadata},
            )
            state.completed = True
            return state

        if preflight_only:
            state.metadata["hardening"]["agent_started"] = False
            state.output = ModelOutput(
                model=str(state.model),
                completion="agentsh_preflight_passed",
                metadata={"hardening_preflight": preflight_metadata},
            )
            state.completed = True
            return state

        if not backend_wraps_upstream:
            return _agentsh_fail_closed_state(
                state,
                failure_type="agentsh_agent_wrapping_not_implemented",
                error=RuntimeError(
                    "AgentSH backend cannot yet wrap upstream Harbor agent "
                    "execution; refusing to call upstream solver for non-preflight "
                    "runs."
                ),
            )

        state.metadata["hardening"]["agent_started"] = True
        state.metadata["hardening"]["terminal_bench_score_eligible"] = (
            state.metadata["hardening"].get("benchmark_claim") != "none"
        )
        state.metadata["terminal_bench_score_eligible"] = state.metadata["hardening"][
            "terminal_bench_score_eligible"
        ]
        return await upstream_solver(state, generate)

    return solve


def _agentsh_benchmark_claim(
    *,
    preflight_metadata: dict[str, Any],
    backend_wraps_upstream: bool,
) -> str:
    if (
        preflight_metadata.get("evidence_tier") == "real_agentsh"
        and backend_wraps_upstream
    ):
        return "official_terminal_bench_candidate"
    return "none"


def _agentsh_fail_closed_state(
    state: TaskState, *, failure_type: str, error: Exception
) -> TaskState:
    error_metadata = {
        "status": "fail",
        "passed": False,
        "backend": "agentsh",
        "agentsh_backend": state.metadata.get("hardening", {}).get("agentsh_backend"),
        "evidence_tier": state.metadata.get("hardening", {}).get("evidence_tier"),
        "benchmark_claim": state.metadata.get("hardening", {}).get("benchmark_claim"),
        "failure_type": failure_type,
        "error_type": type(error).__name__,
        "error": str(error),
        "silent_fallback": False,
        "harbor_verifier_ran": False,
        "harbor_reward": None,
        "terminal_bench_score_eligible": False,
    }
    state.metadata.setdefault("hardening", {})
    state.metadata["hardening"]["preflight"] = error_metadata
    state.metadata["hardening"]["agent_started"] = False
    state.metadata["hardening"]["harbor_verifier_ran"] = False
    state.metadata["hardening"]["terminal_bench_score_eligible"] = False
    state.metadata["harbor_verifier_ran"] = False
    state.metadata["terminal_bench_score_eligible"] = False
    state.metadata["hardening_preflight"] = error_metadata
    state.metadata["agentsh_preflight"] = error_metadata
    state.output = ModelOutput(
        model=str(state.model),
        completion="agentsh_preflight_failed",
        metadata={"hardening_preflight": error_metadata},
    )
    state.completed = True
    return state
