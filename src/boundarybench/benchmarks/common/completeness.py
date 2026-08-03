"""Run-completeness metadata for benchmark eval artifacts.

Interrupted, cancelled, or partial benchmark executions can produce Inspect
``.eval`` logs that are structurally readable but do not represent complete
benchmark runs.  This module computes a ``RunCompleteness`` record from an
``EvalLog`` so downstream aggregation, export, and chart pipelines can filter
out partial artifacts without manual auditing.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any

from inspect_ai.log import EvalLog


class CompletionStatus(str, enum.Enum):
    """Classification of an eval log's completeness."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    ERROR = "error"
    EMPTY = "empty"

    def __str__(self) -> str:  # pragma: no cover — cosmetic
        return self.value


@dataclass(frozen=True)
class RunCompleteness:
    """Snapshot of how complete a single eval log is relative to expectations."""

    status: CompletionStatus
    expected_samples: int
    completed_samples: int
    scored_samples: int
    error_samples: int
    eval_status: str
    completeness_pct: float
    is_usable: bool
    reason: str
    task_name: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_mapping(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = str(self.status)
        return data


def compute_completeness(
    log: EvalLog,
    *,
    expected_samples: int | None = None,
) -> RunCompleteness:
    """Derive ``RunCompleteness`` from an Inspect ``EvalLog``.

    Parameters
    ----------
    log:
        A finished (or interrupted) Inspect eval log.
    expected_samples:
        The number of samples the run was *supposed* to produce.  When
        ``None``, the value is inferred from ``log.eval.dataset`` or from
        ``log.results.total_samples`` — whichever is available.
    """

    eval_status = str(getattr(log, "status", "unknown") or "unknown")
    task_name = str(getattr(getattr(log, "eval", None), "task", "") or "unknown")
    samples = list(log.samples or [])
    completed = len(samples)

    if expected_samples is None:
        expected_samples = _infer_expected_samples(log, completed)

    scored = _count_scored(samples)
    errors = _count_errors(samples)
    warnings: list[str] = []

    pct = (completed / expected_samples * 100.0) if expected_samples > 0 else 0.0

    if completed == 0:
        status = CompletionStatus.EMPTY
        is_usable = False
        reason = "eval produced no samples"
    elif eval_status not in {"success", "completed"}:
        status = CompletionStatus.ERROR
        is_usable = False
        reason = f"eval status is '{eval_status}'"
    elif expected_samples > 0 and completed < expected_samples:
        status = CompletionStatus.PARTIAL
        is_usable = False
        reason = (
            f"only {completed}/{expected_samples} samples completed "
            f"({pct:.0f}%)"
        )
    else:
        status = CompletionStatus.COMPLETE
        is_usable = True
        reason = "all expected samples completed"

    if errors > 0:
        warnings.append(f"{errors}/{completed} samples ended as errors")
    if errors == completed and completed > 0:
        warnings.append("every sample is an error — include in error review")

    return RunCompleteness(
        status=status,
        expected_samples=expected_samples,
        completed_samples=completed,
        scored_samples=scored,
        error_samples=errors,
        eval_status=eval_status,
        completeness_pct=round(pct, 1),
        is_usable=is_usable,
        reason=reason,
        task_name=task_name,
        warnings=warnings,
    )


def summarize_batch_completeness(
    logs: list[EvalLog],
    *,
    expected_per_log: dict[str, int] | None = None,
) -> list[RunCompleteness]:
    """Compute completeness for each log in a batch.

    Parameters
    ----------
    expected_per_log:
        Optional mapping from task name to expected sample count.
    """

    results: list[RunCompleteness] = []
    for log in logs:
        task_name = str(
            getattr(getattr(log, "eval", None), "task", "") or "unknown"
        )
        expected = (expected_per_log or {}).get(task_name)
        results.append(compute_completeness(log, expected_samples=expected))
    return results


def _infer_expected_samples(log: EvalLog, fallback_completed: int) -> int:
    """Best-effort extraction of the intended sample count from log metadata."""

    eval_obj = getattr(log, "eval", None)
    if eval_obj is not None:
        dataset = getattr(eval_obj, "dataset", None)
        if dataset is not None:
            ds_samples = getattr(dataset, "samples", None)
            if isinstance(ds_samples, int) and ds_samples > 0:
                return ds_samples

    results = getattr(log, "results", None)
    if results is not None:
        total = getattr(results, "total_samples", None)
        if isinstance(total, int) and total > 0:
            return total

    if eval_obj is not None:
        task_meta = getattr(eval_obj, "metadata", None) or {}
        if isinstance(task_meta, dict):
            counts = task_meta.get("dataset_counts")
            if isinstance(counts, dict):
                total = sum(
                    v for v in counts.values() if isinstance(v, (int, float))
                )
                if total > 0:
                    return int(total)

    return fallback_completed


def _count_scored(samples: list[Any]) -> int:
    count = 0
    for sample in samples:
        scores = getattr(sample, "scores", None)
        if scores and isinstance(scores, dict):
            if any(
                getattr(score, "value", None) is not None
                for score in scores.values()
            ):
                count += 1
    return count


def _count_errors(samples: list[Any]) -> int:
    count = 0
    for sample in samples:
        output = getattr(sample, "output", None)
        if output is not None:
            meta = getattr(output, "metadata", None) or {}
            if isinstance(meta, dict) and meta.get("answer") == "ERROR":
                count += 1
                continue
        sample_meta = getattr(sample, "metadata", None) or {}
        for key in ("terminalbench_daytona", "boundary_bench_v1_daytona"):
            nested = sample_meta.get(key)
            if isinstance(nested, dict) and nested.get("answer") == "ERROR":
                count += 1
                break
    return count
