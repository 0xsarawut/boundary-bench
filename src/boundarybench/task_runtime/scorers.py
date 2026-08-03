from __future__ import annotations

import re
from typing import Any

from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import TaskState

from boundarybench.task_runtime.loading import _maybe_await, _preflight_passed
from boundarybench.task_runtime.sandbox import (
    _hardening_agent_started,
    _lift_hardening_for_verifier,
)


@scorer(metrics=[])
def hardening_preflight_scorer():
    """Score preflight-only runs without invoking local fake scoring."""

    async def score(state: TaskState, target: Any) -> Score:
        metadata = dict(getattr(state, "metadata", {}) or {})
        hardening = dict(metadata.get("hardening", {}) or {})
        preflight = dict(hardening.get("preflight", {}) or {})
        passed = _preflight_passed(preflight)
        return Score(
            value=1.0 if passed else 0.0,
            answer="success" if passed else "failure",
            explanation="Hardening preflight scorer",
            metadata={
                "scorer": "hardening_preflight_only",
                "score_source": "hardening_preflight_sentinel",
                "enforcement": hardening.get("enforcement"),
                "severity": "sev1",
                "control_mode": False,
                "hardened_execution": True,
                "hardening_config": (hardening.get("config") or {}).get("config_id"),
                "preflight_only": hardening.get("preflight_only"),
                "preflight_status": preflight.get("status"),
                "agentsh_backend": hardening.get("agentsh_backend"),
                "evidence_tier": hardening.get("evidence_tier"),
                "benchmark_claim": hardening.get("benchmark_claim"),
                "dataset_version": metadata.get("dataset_version"),
                "terminal_bench_task_id": metadata.get("terminal_bench_task_id"),
                "harbor_package_name": metadata.get("harbor_package_name"),
                "harbor_package_ref": metadata.get("harbor_package_ref"),
                "official_verifier_source": metadata.get("official_verifier_source"),
                "custom_verifier": False,
                "harbor_verifier_ran": hardening.get("harbor_verifier_ran", False),
                "harbor_reward": None,
                "terminal_bench_score_eligible": hardening.get(
                    "terminal_bench_score_eligible", False
                ),
                "harbor_result": metadata.get("harbor_result"),
            },
        )

    return score


def hardening_aware_harbor_scorer(harbor_scorer: Any) -> Any:
    """Wrap Harbor scorers so preflight failures cannot become Harbor scores."""

    if harbor_scorer is None:
        return _wrap_harbor_scorer(None)
    if isinstance(harbor_scorer, (list, tuple)):
        return [_wrap_harbor_scorer(score) for score in harbor_scorer]
    return _wrap_harbor_scorer(harbor_scorer)


def _wrap_harbor_scorer(harbor_score: Any) -> Any:
    async def score(state: TaskState, target: Any) -> Score:
        failure_metadata = _hardening_preflight_failure_metadata(state)
        if failure_metadata is not None:
            return Score(
                value=0.0,
                answer="failure",
                explanation="Hardening preflight failed before Harbor verifier ran",
                metadata=failure_metadata,
            )

        if harbor_score is None:
            return Score(
                value=0.0,
                answer="failure",
                explanation="No Harbor scorer was available",
                metadata={
                    "failure_type": "missing_harbor_scorer",
                    "enforcement": (
                        (getattr(state, "metadata", {}) or {})
                        .get("hardening", {})
                        .get("enforcement")
                    ),
                    "severity": "sev1",
                    "control_mode": False,
                    "hardened_execution": True,
                },
            )

        lift_metadata = await _lift_hardening_for_verifier(state)
        if lift_metadata:
            state.metadata.setdefault("hardening", {})[
                "verifier_hardening_lift"
            ] = lift_metadata

        try:
            harbor_result = await _maybe_await(harbor_score(state, target))
        except Exception as exc:
            if not _is_harbor_copy_tests_error(exc) or not _hardening_agent_started(
                state
            ):
                raise
            return _hardening_verifier_failure_score(
                state,
                failure_type="harbor_verifier_copy_blocked",
                explanation=(
                    "Hardening prevented Harbor from installing or copying its "
                    "official verifier tests. No alternate verifier was run."
                ),
                upstream_error=exc,
            )
        if _is_harbor_bootstrap_failure(harbor_result, state):
            return _hardening_verifier_failure_score(
                state,
                failure_type="harbor_verifier_bootstrap_blocked",
                explanation=(
                    "Hardening prevented Harbor's official verifier bootstrap "
                    "from completing. No alternate verifier was run."
                ),
                upstream_score=harbor_result,
            )
        return _hardened_harbor_success_score(state, harbor_result)

    if harbor_score is not None:
        score.__name__ = getattr(harbor_score, "__name__", score.__name__)
        score.__qualname__ = getattr(harbor_score, "__qualname__", score.__qualname__)
        for attr in ("__registry_info__", "__registry_params__"):
            if hasattr(harbor_score, attr):
                setattr(score, attr, getattr(harbor_score, attr))

    return score


def _hardened_harbor_success_score(state: TaskState, harbor_result: Score) -> Score:
    state_metadata = getattr(state, "metadata", {}) or {}
    if isinstance(state_metadata, dict):
        state_metadata.setdefault("hardening", {})
        state_metadata["hardening"]["harbor_verifier_ran"] = True
        state_metadata["hardening"]["harbor_reward"] = harbor_result.value
    hardening = dict((getattr(state, "metadata", {}) or {}).get("hardening", {}) or {})
    metadata = {
        **dict(harbor_result.metadata or {}),
        "enforcement": hardening.get("enforcement"),
        "severity": "sev1",
        "control_mode": False,
        "hardened_execution": True,
        "hardening_config": (hardening.get("config") or {}).get("config_id"),
        "preflight_only": hardening.get("preflight_only"),
        "preflight_status": (hardening.get("preflight") or {}).get("status"),
        "agent_started": hardening.get("agent_started"),
        "score_source": "harbor_official_verifier",
        "harbor_verifier_ran": True,
        "harbor_reward": harbor_result.value,
        "benchmark_claim": hardening.get("benchmark_claim"),
        "terminal_bench_score_eligible": hardening.get(
            "terminal_bench_score_eligible", True
        ),
        "verifier_hardening_lift": hardening.get("verifier_hardening_lift"),
        "custom_verifier": False,
    }
    return Score(
        value=harbor_result.value,
        answer=harbor_result.answer,
        explanation=harbor_result.explanation,
        metadata=metadata,
    )


def _hardening_verifier_failure_score(
    state: TaskState,
    *,
    failure_type: str,
    explanation: str,
    upstream_error: Exception | None = None,
    upstream_score: Score | None = None,
) -> Score:
    hardening = dict((getattr(state, "metadata", {}) or {}).get("hardening", {}) or {})
    metadata: dict[str, Any] = {
        "scorer": "hardening_aware_harbor",
        "failure_type": failure_type,
        "enforcement": hardening.get("enforcement"),
        "severity": "sev1",
        "control_mode": False,
        "hardened_execution": True,
        "hardening_config": (hardening.get("config") or {}).get("config_id"),
        "preflight_only": hardening.get("preflight_only"),
        "agent_started": hardening.get("agent_started"),
        "score_source": "hardening_preflight_sentinel",
        "harbor_verifier_ran": False,
        "harbor_reward": None,
        "terminal_bench_score_eligible": False,
        "official_verifier_source": "inspect-harbor harbor_scorer",
        "dataset_version": (getattr(state, "metadata", {}) or {}).get(
            "dataset_version"
        ),
        "terminal_bench_task_id": (getattr(state, "metadata", {}) or {}).get(
            "terminal_bench_task_id"
        ),
        "harbor_package_name": (getattr(state, "metadata", {}) or {}).get(
            "harbor_package_name"
        ),
        "harbor_package_ref": (getattr(state, "metadata", {}) or {}).get(
            "harbor_package_ref"
        ),
        "official_verifier_result": None,
        "verifier_hardening_lift": hardening.get("verifier_hardening_lift"),
        "custom_verifier": False,
        "alternate_reward_computed": False,
        "harbor_result": (getattr(state, "metadata", {}) or {}).get("harbor_result"),
    }
    if upstream_error is not None:
        metadata["upstream_error_type"] = type(upstream_error).__name__
        metadata["upstream_error"] = str(upstream_error)
    if upstream_score is not None:
        metadata["upstream_harbor_score"] = {
            "value": upstream_score.value,
            "answer": upstream_score.answer,
            "explanation": upstream_score.explanation,
            "metadata": dict(upstream_score.metadata or {}),
        }
    return Score(
        value=0.0,
        answer="failure",
        explanation=explanation,
        metadata=metadata,
    )


def _is_harbor_copy_tests_error(exc: Exception) -> bool:
    return type(exc).__name__ == "CopyTestsDirError"


def _is_harbor_bootstrap_failure(score: Any, state: TaskState) -> bool:
    if not _hardening_agent_started(state):
        return False
    try:
        failed = float(getattr(score, "value", 0.0)) == 0.0
    except (TypeError, ValueError):
        failed = False
    if not failed:
        return False
    explanation = str(getattr(score, "explanation", ""))
    bootstrap_marker_patterns = (
        re.compile(r"^uvx: command not found\b", re.MULTILINE),
        re.compile(r"^Unable to locate package curl\b", re.MULTILINE),
        re.compile(r"^setgroups(?:\b|:)", re.MULTILINE),
        re.compile(r"^(?:E:\s*)?Method http has died unexpectedly\b", re.MULTILINE),
    )
    return any(pattern.search(explanation) for pattern in bootstrap_marker_patterns)


def _hardening_preflight_failure_metadata(state: TaskState) -> dict[str, Any] | None:
    metadata = dict(getattr(state, "metadata", {}) or {})
    hardening = dict(metadata.get("hardening", {}) or {})
    preflight = dict(hardening.get("preflight", {}) or {})

    if not hardening or not preflight:
        return None

    agent_started = hardening.get("agent_started")
    preflight_failed = not _preflight_passed(preflight)
    if not preflight_failed or agent_started is True:
        return None

    results = _preflight_results(preflight)
    return {
        "scorer": "hardening_aware_harbor",
        "failure_type": "hardening_preflight",
        "enforcement": hardening.get("enforcement"),
        "severity": "sev1",
        "control_mode": False,
        "hardened_execution": True,
        "hardening_config": (hardening.get("config") or {}).get("config_id"),
        "preflight_only": hardening.get("preflight_only"),
        "preflight_status": preflight.get("status"),
        "preflight_passed": preflight.get("passed"),
        "agent_started": agent_started,
        "agentsh_backend": hardening.get("agentsh_backend"),
        "evidence_tier": hardening.get("evidence_tier"),
        "benchmark_claim": hardening.get("benchmark_claim"),
        "score_source": "hardening_preflight_sentinel",
        "harbor_verifier_ran": False,
        "harbor_reward": None,
        "terminal_bench_score_eligible": False,
        "dataset_version": metadata.get("dataset_version"),
        "terminal_bench_task_id": metadata.get("terminal_bench_task_id"),
        "harbor_package_name": metadata.get("harbor_package_name"),
        "harbor_package_ref": metadata.get("harbor_package_ref"),
        "official_verifier_source": metadata.get("official_verifier_source"),
        "custom_verifier": False,
        "check_ids": [
            result.get("check_id")
            for result in results
            if isinstance(result, dict) and result.get("check_id") is not None
        ],
        "preflight_results": results,
        "hardening_preflight": preflight,
        "harbor_result": metadata.get("harbor_result"),
    }


def _preflight_results(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    results = preflight.get("results")
    if not isinstance(results, list):
        return []
    return [dict(result) for result in results if isinstance(result, dict)]
