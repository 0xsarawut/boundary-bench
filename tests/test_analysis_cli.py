from __future__ import annotations

from types import SimpleNamespace

from boundarybench import cli
from boundarybench.analysis.cli import analyze_logs, analyze_sample


def _sample(policy: str | None, events: list[dict] | None, task_id: str = "t1"):
    metadata = {}
    if policy is not None:
        metadata["terminalbench_daytona"] = {
            "policy": policy,
            "task_id": task_id,
            "policy_events": events or [],
        }
    return SimpleNamespace(id=task_id, metadata=metadata, scores={})


def _privilege_block_event() -> dict:
    return {
        "event_type": "policy_block",
        "axis": "privilege",
        "operation": "sudo",
        "target": "sudo apt-get install",
        "observer": "sudo_log",
    }


def test_analyze_command_routes_to_analysis_cli(monkeypatch):
    called = {}

    def fake_main(args: list[str] | None = None) -> int:
        called["args"] = args
        return 29

    monkeypatch.setattr("boundarybench.analysis.cli.main", fake_main)

    assert cli.main(["analyze", "--input", "logs"]) == 29
    assert called["args"] == ["--input", "logs"]


def test_analyze_sample_returns_none_without_policy_data():
    assert analyze_sample(_sample(policy=None, events=None)) is None


def test_analyze_sample_returns_none_for_non_axis_policy():
    assert analyze_sample(_sample(policy="none", events=[])) is None


def test_analyze_sample_counts_privilege_hit():
    row = analyze_sample(
        _sample(policy="non-root", events=[_privilege_block_event()])
    )

    assert row is not None
    assert row["policy"] == "non-root"
    assert row["task_id"] == "t1"
    assert row["hit_count"] == 1
    assert row["blocked_trial_count"] == 1
    assert row["axis_counts"]["privilege"]["hit_occurrence_count"] == 1
    assert row["axis_counts"]["privilege"]["blocked_trial_count"] == 1


def test_analyze_logs_aggregates_and_skips():
    log = SimpleNamespace(
        eval=SimpleNamespace(run_id="run-1"),
        samples=[
            _sample(policy="non-root", events=[_privilege_block_event()]),
            _sample(policy="control", events=[], task_id="t2"),
            _sample(policy=None, events=None, task_id="t3"),
        ],
    )

    report = analyze_logs([log])

    assert report["totals"]["samples_analyzed"] == 2
    assert report["totals"]["samples_skipped_no_axis_policy"] == 1
    assert report["totals"]["policy_hit_occurrences"] == 1
    assert report["totals"]["blocked_trials"] == 1
    assert {row["task_id"] for row in report["samples"]} == {"t1", "t2"}
