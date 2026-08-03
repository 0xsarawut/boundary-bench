"""Tests for run-completeness metadata and eval log filtering."""

from __future__ import annotations

from types import SimpleNamespace

from boundarybench.benchmarks.common.completeness import (
    CompletionStatus,
    compute_completeness,
    summarize_batch_completeness,
)
from boundarybench.benchmarks.common.log_filter import (
    RunFingerprint,
    deduplicate_logs,
    filter_logs,
)


def _fake_sample(
    sample_id: str = "task-a",
    score_value: float | None = 1.0,
    answer: str = "PASS",
) -> SimpleNamespace:
    scores = {}
    if score_value is not None:
        scores["primary"] = SimpleNamespace(value=score_value)
    metadata_inner = {"reward": score_value or 0, "answer": answer}
    return SimpleNamespace(
        id=sample_id,
        sample_id=sample_id,
        scores=scores,
        metadata={"terminalbench_daytona": metadata_inner, "reward": score_value},
        output=SimpleNamespace(metadata=metadata_inner),
    )


def _fake_error_sample(sample_id: str = "task-err") -> SimpleNamespace:
    metadata_inner = {"reward": 0.0, "answer": "ERROR", "error": "some error"}
    return SimpleNamespace(
        id=sample_id,
        sample_id=sample_id,
        scores={"primary": SimpleNamespace(value=0.0)},
        metadata={"terminalbench_daytona": metadata_inner, "reward": 0.0},
        output=SimpleNamespace(metadata=metadata_inner),
    )


def _fake_log(
    *,
    status: str = "success",
    samples: list | None = None,
    task: str = "hardened_terminalbench_daytona",
    model: str = "openrouter/minimax/minimax-m3",
    dataset_samples: int | None = None,
    total_samples: int | None = None,
    created: str = "2026-06-23T10:00:00Z",
    metadata: dict | None = None,
) -> SimpleNamespace:
    if samples is None:
        samples = [_fake_sample()]
    dataset = SimpleNamespace(samples=dataset_samples) if dataset_samples else None
    results = SimpleNamespace(total_samples=total_samples) if total_samples else None
    eval_obj = SimpleNamespace(
        task=task,
        model=model,
        dataset=dataset,
        created=created,
        metadata=metadata or {},
    )
    return SimpleNamespace(
        status=status,
        eval=eval_obj,
        samples=samples,
        results=results,
    )


class TestComputeCompleteness:
    def test_complete_run(self):
        log = _fake_log(
            samples=[_fake_sample("t1"), _fake_sample("t2")],
            dataset_samples=2,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.COMPLETE
        assert c.is_usable is True
        assert c.expected_samples == 2
        assert c.completed_samples == 2
        assert c.completeness_pct == 100.0
        assert c.error_samples == 0

    def test_partial_run(self):
        log = _fake_log(
            samples=[_fake_sample("t1")],
            dataset_samples=5,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.PARTIAL
        assert c.is_usable is False
        assert c.expected_samples == 5
        assert c.completed_samples == 1
        assert c.completeness_pct == 20.0

    def test_empty_run(self):
        log = _fake_log(samples=[], dataset_samples=5)
        c = compute_completeness(log)
        assert c.status == CompletionStatus.EMPTY
        assert c.is_usable is False

    def test_error_status(self):
        log = _fake_log(
            status="error",
            samples=[_fake_sample()],
            dataset_samples=1,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.ERROR
        assert c.is_usable is False
        assert "error" in c.reason

    def test_cancelled_status_is_error(self):
        log = _fake_log(
            status="cancelled",
            samples=[_fake_sample()],
            dataset_samples=3,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.ERROR
        assert c.is_usable is False

    def test_all_error_samples_remain_usable_for_error_review(self):
        log = _fake_log(
            samples=[_fake_error_sample("e1"), _fake_error_sample("e2")],
            dataset_samples=2,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.COMPLETE
        assert c.is_usable is True
        assert any("every sample is an error" in w for w in c.warnings)

    def test_some_error_samples_warn(self):
        log = _fake_log(
            samples=[_fake_sample("t1"), _fake_error_sample("e1")],
            dataset_samples=2,
        )
        c = compute_completeness(log)
        assert c.status == CompletionStatus.COMPLETE
        assert c.is_usable is True
        assert c.error_samples == 1
        assert any("1/2 samples ended as errors" in w for w in c.warnings)

    def test_explicit_expected_overrides_inferred(self):
        log = _fake_log(
            samples=[_fake_sample("t1"), _fake_sample("t2")],
            dataset_samples=2,
        )
        c = compute_completeness(log, expected_samples=10)
        assert c.status == CompletionStatus.PARTIAL
        assert c.expected_samples == 10
        assert c.completed_samples == 2

    def test_infers_from_results_total_samples(self):
        log = _fake_log(
            samples=[_fake_sample("t1")],
            total_samples=3,
        )
        c = compute_completeness(log)
        assert c.expected_samples == 3
        assert c.status == CompletionStatus.PARTIAL

    def test_infers_from_dataset_counts_metadata(self):
        log = _fake_log(
            samples=[_fake_sample("t1")],
            metadata={"dataset_counts": {"sev0": 2, "sev1": 3}},
        )
        c = compute_completeness(log)
        assert c.expected_samples == 5
        assert c.status == CompletionStatus.PARTIAL

    def test_fallback_to_completed_count(self):
        log = _fake_log(
            samples=[_fake_sample("t1"), _fake_sample("t2")],
        )
        c = compute_completeness(log)
        assert c.expected_samples == 2
        assert c.status == CompletionStatus.COMPLETE

    def test_to_mapping_serializable(self):
        log = _fake_log(samples=[_fake_sample()])
        c = compute_completeness(log)
        m = c.to_mapping()
        assert isinstance(m, dict)
        assert m["status"] == "complete"
        assert isinstance(m["warnings"], list)


class TestSummarizeBatch:
    def test_batch_summary(self):
        logs = [
            _fake_log(
                samples=[_fake_sample()],
                dataset_samples=1,
                task="task_a",
            ),
            _fake_log(
                samples=[_fake_sample()],
                dataset_samples=5,
                task="task_b",
            ),
        ]
        results = summarize_batch_completeness(logs)
        assert len(results) == 2
        assert results[0].is_usable is True
        assert results[1].is_usable is False

    def test_batch_with_expected_override(self):
        logs = [
            _fake_log(
                samples=[_fake_sample(), _fake_sample()],
                task="task_a",
            ),
        ]
        results = summarize_batch_completeness(
            logs, expected_per_log={"task_a": 10}
        )
        assert results[0].expected_samples == 10
        assert results[0].status == CompletionStatus.PARTIAL


class TestRunFingerprint:
    def test_same_condition_same_fingerprint(self):
        log1 = _fake_log(
            samples=[_fake_sample("a"), _fake_sample("b")],
            task="tb",
            model="openrouter/minimax/minimax-m3",
            metadata={"policy": "nist-linux-80053-low"},
        )
        log2 = _fake_log(
            samples=[_fake_sample("b"), _fake_sample("a")],
            task="tb",
            model="openrouter/minimax/minimax-m3",
            metadata={"policy": "nist-linux-80053-low"},
        )
        assert RunFingerprint.from_log(log1) == RunFingerprint.from_log(log2)

    def test_different_model_different_fingerprint(self):
        log1 = _fake_log(model="openrouter/minimax/minimax-m3")
        log2 = _fake_log(model="openrouter/anthropic/claude-sonnet-4-20250514")
        assert RunFingerprint.from_log(log1) != RunFingerprint.from_log(log2)

    def test_different_policy_different_fingerprint(self):
        log1 = _fake_log(metadata={"policy": "none"})
        log2 = _fake_log(metadata={"policy": "nist-linux-80053-low"})
        assert RunFingerprint.from_log(log1) != RunFingerprint.from_log(log2)

    def test_different_samples_different_fingerprint(self):
        log1 = _fake_log(samples=[_fake_sample("a")])
        log2 = _fake_log(samples=[_fake_sample("a"), _fake_sample("b")])
        assert RunFingerprint.from_log(log1) != RunFingerprint.from_log(log2)


class TestFilterLogs:
    def test_complete_logs_are_usable(self):
        log = _fake_log(samples=[_fake_sample()], dataset_samples=1)
        result = filter_logs([log])
        assert len(result.usable) == 1
        assert result.excluded_count == 0

    def test_partial_logs_excluded(self):
        log = _fake_log(samples=[_fake_sample()], dataset_samples=10)
        result = filter_logs([log])
        assert len(result.usable) == 0
        assert len(result.partial) == 1

    def test_empty_logs_excluded(self):
        log = _fake_log(samples=[], dataset_samples=5)
        result = filter_logs([log])
        assert len(result.empty) == 1

    def test_error_logs_excluded(self):
        log = _fake_log(status="error", samples=[_fake_sample()], dataset_samples=1)
        result = filter_logs([log])
        assert len(result.error) == 1

    def test_complete_all_error_logs_are_usable_for_error_review(self):
        log = _fake_log(
            samples=[_fake_error_sample("e1"), _fake_error_sample("e2")],
            dataset_samples=2,
        )
        result = filter_logs([log])
        assert len(result.usable) == 1
        assert result.usable[0] is log
        assert result.excluded_count == 0

    def test_mixed_collection(self):
        good = _fake_log(
            samples=[_fake_sample("a")],
            dataset_samples=1,
            created="2026-06-23T10:00:00Z",
        )
        partial = _fake_log(
            samples=[_fake_sample("a")],
            dataset_samples=5,
            created="2026-06-23T09:00:00Z",
        )
        empty = _fake_log(samples=[], dataset_samples=3)
        result = filter_logs([good, partial, empty])
        assert len(result.usable) == 1
        assert len(result.partial) == 1
        assert len(result.empty) == 1
        s = result.summary()
        assert s["usable"] == 1
        assert s["excluded_total"] == 2

    def test_duplicates_detected(self):
        log1 = _fake_log(
            samples=[_fake_sample("a")],
            dataset_samples=1,
            created="2026-06-23T10:00:00Z",
        )
        log2 = _fake_log(
            samples=[_fake_sample("a")],
            dataset_samples=1,
            created="2026-06-23T11:00:00Z",
        )
        result = filter_logs([log1, log2])
        assert len(result.usable) == 1
        assert len(result.duplicate) == 1

    def test_expected_per_task_override(self):
        log = _fake_log(
            samples=[_fake_sample("a"), _fake_sample("b")],
            task="my_task",
        )
        result = filter_logs([log], expected_per_task={"my_task": 89})
        assert len(result.partial) == 1
        assert len(result.usable) == 0


class TestDeduplicateLogs:
    def test_keeps_latest(self):
        old = _fake_log(
            samples=[_fake_sample("a")],
            created="2026-06-22T10:00:00Z",
        )
        new = _fake_log(
            samples=[_fake_sample("a")],
            created="2026-06-23T10:00:00Z",
        )
        canonical, dupes = deduplicate_logs([old, new])
        assert len(canonical) == 1
        assert canonical[0] is new
        assert len(dupes) == 1
        assert dupes[0] is old

    def test_no_duplicates_when_different_conditions(self):
        log1 = _fake_log(
            samples=[_fake_sample("a")],
            model="openrouter/minimax/minimax-m3",
        )
        log2 = _fake_log(
            samples=[_fake_sample("a")],
            model="openrouter/anthropic/claude-sonnet-4-20250514",
        )
        canonical, dupes = deduplicate_logs([log1, log2])
        assert len(canonical) == 2
        assert len(dupes) == 0

    def test_single_log_no_duplicate(self):
        log = _fake_log(samples=[_fake_sample("a")])
        canonical, dupes = deduplicate_logs([log])
        assert len(canonical) == 1
        assert len(dupes) == 0

    def test_empty_input(self):
        canonical, dupes = deduplicate_logs([])
        assert canonical == []
        assert dupes == []
