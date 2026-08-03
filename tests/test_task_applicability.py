from __future__ import annotations

import csv
from pathlib import Path

from boundarybench.terminalbench import task_applicability as ta


def test_full_universe_roster_is_frozen_and_consistent():
    ids = ta.all_task_ids()
    assert len(ids) == 89
    assert len(set(ids)) == 89
    assert ids == tuple(sorted(ids))
    assert set(ta.POLICY_INAPPLICABLE_TASKS) <= set(ids)
    assert set(ta.adapted_verifier_task_ids()) <= set(ids)


def test_full_universe_roster_matches_the_solvability_evidence_csv():
    csv_path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "task-evidence"
        / "high-nist-89-task-evidence.csv"
    )
    with csv_path.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(sorted(row["task"] for row in rows)) == ta.all_task_ids()


def test_adapted_verifier_roster_is_exactly_the_committed_assets():
    assert ta.adapted_verifier_task_ids() == (
        "adaptive-rejection-sampler",
        "configure-git-webserver",
        "make-doom-for-mips",
        "mcmc-sampling-stan",
        "sqlite-with-gcov",
    )


def test_policy_inapplicable_roster_has_the_seven_conflict_tasks():
    assert set(ta.POLICY_INAPPLICABLE_TASKS) == {
        "build-pmars",
        "build-pov-ray",
        "build-cython-ext",
        "kv-store-grpc",
        "nginx-request-logging",
        "mailman",
        "count-dataset-tokens",
    }
    assert all(reason for reason in ta.POLICY_INAPPLICABLE_TASKS.values())


def test_conflict_tasks_are_applicable_under_control_equivalents_only():
    for task_id in ta.POLICY_INAPPLICABLE_TASKS:
        for policy in ("control", "n0-f0-p0", "none", ""):
            assert ta.policy_applicability(task_id, policy) == ta.APPLICABLE
        for policy in ("non-root", "n0-f0-p1", "high-nist", "n2-f2-p2",
                       "low-nist", "moderate-nist", "netlock", "fslock"):
            assert ta.policy_applicability(task_id, policy) == ta.NOT_APPLICABLE
            assert ta.policy_applicability_reason(task_id, policy)


def test_ordinary_tasks_are_applicable_everywhere():
    assert ta.policy_applicability("log-summary-date-ranges", "high-nist") == (
        ta.APPLICABLE
    )
    assert ta.policy_applicability_reason("log-summary-date-ranges", "high-nist") == ""


def test_verifier_source_flags_only_adapted_tasks():
    assert ta.verifier_source("sqlite-with-gcov") == ta.VERIFIER_SOURCE_ADAPTED
    assert ta.verifier_source("log-summary-date-ranges") == (
        ta.VERIFIER_SOURCE_OFFICIAL
    )


def test_applicability_metadata_shape():
    stamped = ta.applicability_metadata("mailman", "high-nist")
    assert stamped["verifier_source"] == "official"
    assert stamped["policy_applicability"] == "not_applicable"
    assert stamped["policy_applicability_reason"]
    assert "inspect-harbor" in stamped["official_verifier_source"]

    adapted = ta.applicability_metadata("mcmc-sampling-stan", "control")
    assert adapted["verifier_source"] == "adapted"
    assert adapted["policy_applicability"] == "applicable"
    assert "adapted_verifiers/mcmc-sampling-stan" in (
        adapted["official_verifier_source"]
    )


def test_hardened_task_samples_carry_applicability_metadata():
    from boundarybench.terminalbench.daytona_eval import hardened_terminalbench_daytona

    task = hardened_terminalbench_daytona(
        task_ids="mailman,log-summary-date-ranges",
        policy="high-nist",
        include_not_applicable=True,
    )
    by_id = {
        sample.metadata["terminal_bench_task_id"]: sample.metadata
        for sample in task.dataset
    }
    assert by_id["mailman"]["policy_applicability"] == "not_applicable"
    assert by_id["mailman"]["verifier_source"] == "official"
    assert by_id["log-summary-date-ranges"]["policy_applicability"] == "applicable"


def test_hardened_task_refuses_not_applicable_selection_up_front():
    import pytest

    from boundarybench.terminalbench.daytona_eval import hardened_terminalbench_daytona

    with pytest.raises(ValueError, match="not applicable under policy"):
        hardened_terminalbench_daytona(
            task_ids="mailman,log-summary-date-ranges",
            policy="high-nist",
        )
    task = hardened_terminalbench_daytona(
        task_ids="mailman,log-summary-date-ranges",
        policy="control",
    )
    assert len(list(task.dataset)) == 2


def test_summarize_excludes_not_applicable_from_success_denominator():
    from boundarybench.terminalbench.results_dataframe import summarize

    def _row(task_id: str, success: bool, applicability: str) -> dict:
        return {
            "model": "m",
            "policy": "high-nist",
            "mitigation_type": "none",
            "mitigation_configured": False,
            "task_id": task_id,
            "outcome_raw": "PASS" if success else "FAIL",
            "success": success,
            "valid_for_analysis": True,
            "policy_applicability": applicability,
            "verifier_source": "official",
            "policy_block_hit": False,
            "cost_usd": "",
            "cost_present": False,
            "runtime_total_ms": "",
            "assistant_turns": "",
            "assistant_turns_present": False,
            "stream_truncated_or_malformed": False,
            "final_result_event_present": True,
            "model_usage_present": True,
            "model_usage_recovered": False,
        }

    summary = summarize(
        [
            _row("t-pass", True, "applicable"),
            _row("t-fail", False, "applicable"),
            _row("mailman", False, "not_applicable"),
        ]
    )

    assert len(summary) == 1
    row = summary[0]
    assert row["n_rows"] == 3
    assert row["not_applicable_count"] == 1
    assert row["applicable_count"] == 2
    assert row["success_rate"] == 0.5
