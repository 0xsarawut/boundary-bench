"""Filtering and deduplication of benchmark eval log collections.

When multiple ``.eval`` artifacts are present for the same benchmark condition
(model + policy + task set), this module identifies duplicates, selects the
canonical run, and filters out partial or contaminated artifacts so aggregate
tables, charts, and exports operate only on clean data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from inspect_ai.log import EvalLog

from boundarybench.benchmarks.common.completeness import (
    CompletionStatus,
    RunCompleteness,
    compute_completeness,
)


@dataclass(frozen=True)
class RunFingerprint:
    """Identifies a unique benchmark condition across eval logs.

    Two logs with the same fingerprint represent the same experiment condition
    and should not both appear in aggregate results.
    """

    task_name: str
    model: str
    policy: str
    sample_ids: tuple[str, ...]

    @staticmethod
    def from_log(log: EvalLog) -> RunFingerprint:
        eval_obj = getattr(log, "eval", None)
        task_name = str(getattr(eval_obj, "task", "") or "unknown")
        model = str(getattr(eval_obj, "model", "") or "unknown")

        policy = _extract_policy(log)

        sample_ids = tuple(
            sorted(
                str(getattr(s, "id", "") or getattr(s, "sample_id", "") or "")
                for s in (log.samples or [])
            )
        )
        return RunFingerprint(
            task_name=task_name,
            model=model,
            policy=policy,
            sample_ids=sample_ids,
        )


@dataclass
class FilteredLogSet:
    """Result of filtering a collection of eval logs."""

    usable: list[EvalLog] = field(default_factory=list)
    partial: list[EvalLog] = field(default_factory=list)
    duplicate: list[EvalLog] = field(default_factory=list)
    empty: list[EvalLog] = field(default_factory=list)
    error: list[EvalLog] = field(default_factory=list)

    @property
    def excluded_count(self) -> int:
        return len(self.partial) + len(self.duplicate) + len(self.empty) + len(self.error)

    def summary(self) -> dict[str, Any]:
        return {
            "usable": len(self.usable),
            "partial": len(self.partial),
            "duplicate": len(self.duplicate),
            "empty": len(self.empty),
            "error": len(self.error),
            "excluded_total": self.excluded_count,
        }


def filter_logs(
    logs: list[EvalLog],
    *,
    expected_per_task: dict[str, int] | None = None,
    dedupe: bool = True,
) -> FilteredLogSet:
    """Classify and partition a collection of eval logs.

    The returned ``FilteredLogSet.usable`` contains complete logs safe for
    aggregate analysis. When ``dedupe`` is true, only the latest usable log is
    kept for each fingerprint and older matching logs move to ``duplicate``.

    Parameters
    ----------
    expected_per_task:
        Optional mapping from task name to expected sample count.
    dedupe:
        Whether to exclude older usable logs that share a run fingerprint.
    """

    result = FilteredLogSet()
    completeness_map: dict[int, RunCompleteness] = {}

    for log in logs:
        task_name = str(
            getattr(getattr(log, "eval", None), "task", "") or "unknown"
        )
        expected = (expected_per_task or {}).get(task_name)
        comp = compute_completeness(log, expected_samples=expected)
        completeness_map[id(log)] = comp

        if comp.status == CompletionStatus.EMPTY:
            result.empty.append(log)
        elif not comp.is_usable:
            if comp.status == CompletionStatus.ERROR:
                result.error.append(log)
            else:
                result.partial.append(log)
        else:
            result.usable.append(log)

    if dedupe and len(result.usable) > 1:
        result.usable, dupes = _deduplicate(result.usable)
        result.duplicate.extend(dupes)

    return result


def deduplicate_logs(logs: list[EvalLog]) -> tuple[list[EvalLog], list[EvalLog]]:
    """Remove duplicate runs from a list of usable logs.

    Returns ``(canonical, duplicates)`` where canonical keeps one log per
    unique ``RunFingerprint`` (the most recent).
    """

    return _deduplicate(logs)


def _extract_policy(log: EvalLog) -> str:
    eval_obj = getattr(log, "eval", None)
    task_meta = getattr(eval_obj, "metadata", None) or {}
    if isinstance(task_meta, dict):
        for key in ("run_policy", "policy"):
            val = task_meta.get(key)
            if val:
                return str(val)

    for sample in (log.samples or [])[:1]:
        sample_meta = getattr(sample, "metadata", None) or {}
        if isinstance(sample_meta, dict):
            for key in ("policy", "run_policy"):
                val = sample_meta.get(key)
                if val:
                    return str(val)
    return "unknown"


def _log_created(log: EvalLog) -> str:
    eval_obj = getattr(log, "eval", None)
    return str(getattr(eval_obj, "created", "") or "")


def _deduplicate(
    logs: list[EvalLog],
) -> tuple[list[EvalLog], list[EvalLog]]:
    by_fingerprint: dict[RunFingerprint, list[EvalLog]] = {}
    for log in logs:
        fp = RunFingerprint.from_log(log)
        by_fingerprint.setdefault(fp, []).append(log)

    canonical: list[EvalLog] = []
    duplicates: list[EvalLog] = []
    for _fp, group in by_fingerprint.items():
        if len(group) == 1:
            canonical.append(group[0])
        else:
            sorted_group = sorted(group, key=_log_created, reverse=True)
            canonical.append(sorted_group[0])
            duplicates.extend(sorted_group[1:])
    return canonical, duplicates
