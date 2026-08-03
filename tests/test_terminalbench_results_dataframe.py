from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

import pytest

from boundarybench.terminalbench import results_dataframe as rdf


def test_normalize_outcome_keeps_pass_fail_error_only():
    assert rdf.normalize_outcome("PASS") == "PASS"
    assert rdf.normalize_outcome("fail") == "FAIL"
    assert rdf.normalize_outcome("ERROR") == "ERROR"
    assert rdf.normalize_outcome("weird") == "ERROR"
    assert rdf.normalize_outcome(None) == "ERROR"


def test_policy_block_hit_is_an_independent_summary_dimension():
    rows = [
        {
            "model": "openrouter/anthropic/claude-haiku-4.5",
            "policy": "default",
            "mitigation_type": "block_message",
            "mitigation_configured": True,
            "task_id": "pass-with-block",
            "outcome_raw": "PASS",
            "task_outcome": "PASS",
            "failure_class": "none",
            "valid_for_analysis": True,
            "success": True,
            "policy_block_hit": True,
            "cost_usd": 1.0,
            "runtime_total_ms": 1000,
            "assistant_turns": 2,
            "cost_present": True,
            "assistant_turns_present": True,
        },
        {
            "model": "openrouter/anthropic/claude-haiku-4.5",
            "policy": "default",
            "mitigation_type": "block_message",
            "mitigation_configured": True,
            "task_id": "fail-no-block",
            "outcome_raw": "FAIL",
            "task_outcome": "FAIL",
            "failure_class": "task_model",
            "valid_for_analysis": True,
            "success": False,
            "policy_block_hit": False,
            "cost_usd": 2.0,
            "runtime_total_ms": 2000,
            "assistant_turns": 4,
            "cost_present": True,
            "assistant_turns_present": True,
        },
        {
            "model": "openrouter/anthropic/claude-haiku-4.5",
            "policy": "default",
            "mitigation_type": "block_message",
            "mitigation_configured": True,
            "task_id": "error-no-block",
            "outcome_raw": "ERROR",
            "task_outcome": "ERROR",
            "failure_class": "infra_daytona",
            "valid_for_analysis": False,
            "success": False,
            "policy_block_hit": False,
            "cost_usd": "",
            "runtime_total_ms": "",
            "assistant_turns": "",
            "cost_present": False,
            "assistant_turns_present": False,
        },
    ]

    summary = rdf.summarize(rows)[0]

    assert summary["pass_count"] == 1
    assert summary["fail_count"] == 1
    assert summary["error_count"] == 1
    assert summary["success_rate"] == 1 / 3
    assert summary["valid_for_analysis_count"] == 2
    assert summary["invalid_for_analysis_count"] == 1
    assert summary["analysis_success_rate"] == 0.5
    assert summary["policy_block_rate"] == 1 / 3
    assert summary["avg_cost_usd_present_only"] == 1.5
    assert summary["avg_cost_usd_zero_missing"] == 1.0
    assert summary["cost_present_count"] == 2


def test_classify_operational_failures_as_errors_not_blocks():
    assert rdf.classify_error(
        outcome_raw="ERROR",
        error_message="RuntimeError('tar: test_outputs.py: Cannot open: No space left on device')",
        metadata={},
    ) == ("disk", "sandbox", False)

    assert rdf.classify_error(
        outcome_raw="ERROR",
        error_message="Daytona session failed while creating sandbox",
        metadata={},
    ) == ("daytona", "sandbox", False)

    assert rdf.classify_error(
        outcome_raw="FAIL",
        error_message="",
        metadata={"policy_block_count": 3},
    ) == ("", "", False)


def test_infer_mitigation_type_from_block_message_only_when_no_explicit_value():
    assert rdf.infer_mitigation_type({}, explicit_block_message=True) == "block_message"
    assert rdf.infer_mitigation_type({}, explicit_block_message=False) == "none"
    assert (
        rdf.infer_mitigation_type(
            {"mitigation_type": "skill"}, explicit_block_message=True
        )
        == "skill"
    )


def test_empty_input_is_a_cli_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc_info:
        rdf.main(
            [
                "--input",
                str(tmp_path / "missing"),
                "--output",
                str(tmp_path / "rows.csv"),
            ]
        )

    assert exc_info.value.code == 2
    assert "no .eval files matched --input" in capsys.readouterr().err
    assert not (tmp_path / "rows.csv").exists()


def test_gcs_inputs_stage_to_distinct_local_paths(tmp_path, monkeypatch):
    copied: list[tuple[str, str]] = []

    def fake_gsutil_ls(uri: str) -> list[str]:
        if "run-a" in uri:
            return ["gs://bucket/run-a/results.eval"]
        return ["gs://bucket/run-b/results.eval"]

    def fake_run(cmd: list[str]):
        copied.append((cmd[2], cmd[3]))

    monkeypatch.setattr(rdf, "_gsutil_ls", fake_gsutil_ls)
    monkeypatch.setattr(rdf, "_run", fake_run)

    resolved = rdf.resolve_eval_inputs(
        ["gs://bucket/run-a", "gs://bucket/run-b"],
        temp_dir=tmp_path,
    )

    assert [source for _local, source in resolved] == [
        "gs://bucket/run-a/results.eval",
        "gs://bucket/run-b/results.eval",
    ]
    local_paths = [local for local, _source in resolved]
    assert len(set(local_paths)) == 2
    assert copied == [
        ("gs://bucket/run-a/results.eval", str(local_paths[0])),
        ("gs://bucket/run-b/results.eval", str(local_paths[1])),
    ]


def test_main_filters_partial_logs_but_preserves_replicate_runs_by_default(
    tmp_path, monkeypatch, capsys
):
    old_log = _fake_log(
        sample_id="task-a",
        created="2026-06-23T10:00:00Z",
        run_id="old-run",
    )
    new_log = _fake_log(
        sample_id="task-a",
        created="2026-06-23T11:00:00Z",
        run_id="new-run",
    )
    partial_log = _fake_log(
        sample_id="task-b",
        created="2026-06-23T12:00:00Z",
        run_id="partial-run",
        dataset_samples=2,
    )
    logs_by_path = {
        "old.eval": old_log,
        "new.eval": new_log,
        "partial.eval": partial_log,
    }
    monkeypatch.setattr(
        rdf,
        "resolve_eval_inputs",
        lambda _inputs, *, temp_dir: [
            (Path("old.eval"), "gs://bucket/old.eval"),
            (Path("new.eval"), "gs://bucket/new.eval"),
            (Path("partial.eval"), "gs://bucket/partial.eval"),
        ],
    )
    monkeypatch.setattr(
        rdf,
        "read_eval_log",
        lambda path: logs_by_path[Path(path).name],
    )

    output = tmp_path / "rows.csv"
    rc = rdf.main(
        [
            "--input",
            "gs://bucket/runs",
            "--output",
            str(output),
            "--experiment-id",
            "exp-1",
        ]
    )

    assert rc == 0
    rows = list(csv.DictReader(output.open()))
    assert [row["run_id"] for row in rows] == ["old-run", "new-run"]
    assert [row["eval_file_uri"] for row in rows] == [
        "gs://bucket/old.eval",
        "gs://bucket/new.eval",
    ]
    assert "partial=1 duplicate=0 empty=0 error=0" in capsys.readouterr().out


def test_main_can_include_partial_logs_with_artifact_metadata(
    tmp_path, monkeypatch, capsys
):
    complete_log = _fake_log(
        sample_id="task-a",
        created="2026-06-23T10:00:00Z",
        run_id="complete-run",
    )
    partial_log = _fake_log(
        sample_id="task-b",
        created="2026-06-23T12:00:00Z",
        run_id="partial-run",
        dataset_samples=2,
    )
    logs_by_path = {
        "complete.eval": complete_log,
        "partial.eval": partial_log,
    }
    monkeypatch.setattr(
        rdf,
        "resolve_eval_inputs",
        lambda _inputs, *, temp_dir: [
            (Path("complete.eval"), "gs://bucket/complete.eval"),
            (Path("partial.eval"), "gs://bucket/partial.eval"),
        ],
    )
    monkeypatch.setattr(
        rdf,
        "read_eval_log",
        lambda path: logs_by_path[Path(path).name],
    )

    output = tmp_path / "rows.csv"
    rc = rdf.main(
        [
            "--input",
            "gs://bucket/runs",
            "--output",
            str(output),
            "--experiment-id",
            "exp-1",
            "--include-partial",
        ]
    )

    assert rc == 0
    rows = list(csv.DictReader(output.open()))
    assert [row["run_id"] for row in rows] == ["complete-run", "partial-run"]
    complete_row = rows[0]
    partial_row = rows[1]
    assert complete_row["artifact_status"] == "complete"
    assert complete_row["artifact_expected_samples"] == "1"
    assert complete_row["artifact_completed_samples"] == "1"
    assert complete_row["artifact_completeness_pct"] == "100.0"
    assert partial_row["artifact_status"] == "partial"
    assert partial_row["artifact_expected_samples"] == "2"
    assert partial_row["artifact_completed_samples"] == "1"
    assert partial_row["artifact_completeness_pct"] == "50.0"
    assert "partial=1 duplicate=0 empty=0 error=0" in capsys.readouterr().out


def test_main_can_dedupe_replicate_runs_when_explicitly_requested(
    tmp_path, monkeypatch, capsys
):
    old_log = _fake_log(
        sample_id="task-a",
        created="2026-06-23T10:00:00Z",
        run_id="old-run",
    )
    new_log = _fake_log(
        sample_id="task-a",
        created="2026-06-23T11:00:00Z",
        run_id="new-run",
    )
    logs_by_path = {
        "old.eval": old_log,
        "new.eval": new_log,
    }
    monkeypatch.setattr(
        rdf,
        "resolve_eval_inputs",
        lambda _inputs, *, temp_dir: [
            (Path("old.eval"), "gs://bucket/old.eval"),
            (Path("new.eval"), "gs://bucket/new.eval"),
        ],
    )
    monkeypatch.setattr(
        rdf,
        "read_eval_log",
        lambda path: logs_by_path[Path(path).name],
    )

    output = tmp_path / "rows.csv"
    rc = rdf.main(
        [
            "--input",
            "gs://bucket/runs",
            "--output",
            str(output),
            "--experiment-id",
            "exp-1",
            "--dedupe",
            "latest",
        ]
    )

    assert rc == 0
    rows = list(csv.DictReader(output.open()))
    assert len(rows) == 1
    assert rows[0]["run_id"] == "new-run"
    assert rows[0]["eval_file_uri"] == "gs://bucket/new.eval"
    assert "partial=0 duplicate=1 empty=0 error=0" in capsys.readouterr().out


def test_main_exports_complete_all_error_runs_to_error_review(
    tmp_path, monkeypatch, capsys
):
    error_log = _fake_log(
        sample_id="task-error",
        created="2026-06-23T10:00:00Z",
        run_id="error-run",
        answer="ERROR",
        reward=0.0,
    )
    monkeypatch.setattr(
        rdf,
        "resolve_eval_inputs",
        lambda _inputs, *, temp_dir: [
            (Path("error.eval"), "gs://bucket/error.eval"),
        ],
    )
    monkeypatch.setattr(rdf, "read_eval_log", lambda _path: error_log)

    output = tmp_path / "rows.csv"
    error_output = tmp_path / "errors.csv"
    rc = rdf.main(
        [
            "--input",
            "gs://bucket/runs",
            "--output",
            str(output),
            "--error-review-output",
            str(error_output),
            "--experiment-id",
            "exp-1",
        ]
    )

    assert rc == 0
    rows = list(csv.DictReader(output.open()))
    error_rows = list(csv.DictReader(error_output.open()))
    assert len(rows) == 1
    assert rows[0]["run_id"] == "error-run"
    assert rows[0]["outcome_raw"] == "ERROR"
    assert len(error_rows) == 1
    assert error_rows[0]["run_id"] == "error-run"
    assert "excluded eval logs" not in capsys.readouterr().out


def test_row_from_sample_keeps_cost_blank_when_usage_has_no_cost():
    sample = SimpleNamespace(
        id="task-no-cost",
        uuid="task-no-cost-uuid",
        started_at="2026-06-23T10:00:01Z",
        completed_at="2026-06-23T10:00:02Z",
        metadata={
            "terminal_bench_task_id": "task-no-cost",
            "dataset": "terminal-bench-2.1",
            "terminalbench_daytona": {
                "answer": "PASS",
                "reward": 1.0,
                "policy_events": [
                    {"event_type": "policy_enforce", "surface": "full_mac_enforcement"},
                    {
                        "event_type": "policy_block",
                        "surface": "command",
                        "command": "bash",
                    },
                ],
            },
        },
        scores={"primary": SimpleNamespace(answer="PASS", value=1.0, metadata={})},
        output=SimpleNamespace(model="openrouter/test/model"),
        model_usage={
            "openrouter/test/model": SimpleNamespace(
                input_tokens=10,
                output_tokens=20,
                input_tokens_cache_read=3,
                input_tokens_cache_write=4,
                total_tokens=37,
                total_cost=None,
            )
        },
    )

    row = rdf.row_from_sample(
        sample,
        source_uri="gs://bucket/run.eval",
        experiment_id="exp-1",
        run_id="run-1",
        eval_id="eval-1",
        run_started_at="2026-06-23T10:00:00Z",
        benchmark="hardened_terminalbench_daytona",
        default_model="openrouter/test/model",
        task_args={},
    )

    assert row["cost_usd"] == ""
    assert row["cost_present"] is False
    assert row["input_tokens"] == 10
    assert row["output_tokens"] == 20
    assert row["cache_read_tokens"] == 3
    assert row["cache_write_tokens"] == 4
    assert row["total_tokens"] == 37
    assert row["policy_event_count"] == 2
    assert row["policy_block_count"] == 1
    assert row["policy_block_hit"] is True


def _model_row(*, metadata_model, output_model, task_args_model, default_model):
    metadata = {"terminal_bench_task_id": "task-model", "dataset": "terminal-bench-2.1"}
    if metadata_model is not None:
        metadata["model"] = metadata_model
    sample = SimpleNamespace(
        id="task-model",
        uuid="task-model-uuid",
        started_at="2026-06-23T10:00:01Z",
        completed_at="2026-06-23T10:00:02Z",
        metadata=metadata,
        scores={"primary": SimpleNamespace(answer="PASS", value=1.0, metadata={})},
        output=SimpleNamespace(model=output_model),
    )
    return rdf.row_from_sample(
        sample,
        source_uri="gs://bucket/run.eval",
        experiment_id="exp-1",
        run_id="run-1",
        eval_id="eval-1",
        run_started_at="2026-06-23T10:00:00Z",
        benchmark="hardened_terminalbench_daytona",
        default_model=default_model,
        task_args={} if task_args_model is None else {"model": task_args_model},
    )


def test_row_model_prefers_the_harness_model_over_the_inspect_placeholder():
    # The agent runs in the sandbox, so the Inspect-level model is a mock and
    # must not be what the row reports.
    row = _model_row(
        metadata_model="openai/gpt-5.6-luna",
        output_model="mockllm/model",
        task_args_model="openai/gpt-5.6-luna",
        default_model="mockllm/model",
    )

    assert row["model"] == "openai/gpt-5.6-luna"


def test_row_model_falls_back_to_task_args_when_sample_metadata_lacks_it():
    row = _model_row(
        metadata_model=None,
        output_model="mockllm/model",
        task_args_model="openai/gpt-5.6-luna",
        default_model="mockllm/model",
    )

    assert row["model"] == "openai/gpt-5.6-luna"


def test_row_model_still_uses_output_model_when_it_is_the_only_truth():
    # Logs that predate the harness metadata must not regress.
    row = _model_row(
        metadata_model=None,
        output_model="openrouter/test/model",
        task_args_model=None,
        default_model="",
    )

    assert row["model"] == "openrouter/test/model"


def test_row_model_falls_back_to_the_eval_model_last():
    row = _model_row(
        metadata_model=None,
        output_model=None,
        task_args_model=None,
        default_model="openrouter/test/model",
    )

    assert row["model"] == "openrouter/test/model"


def test_row_from_sample_exports_benchmark_status_fields():
    sample = SimpleNamespace(
        id="daytona-error",
        uuid="daytona-error-uuid",
        started_at="2026-06-23T10:00:01Z",
        completed_at="2026-06-23T10:00:02Z",
        metadata={
            "terminal_bench_task_id": "daytona-error",
            "dataset": "terminal-bench-2.1",
            "terminalbench_daytona": {
                "answer": "ERROR",
                "reward": 0.0,
                "error": (
                    "DaytonaNotFoundError: Failed to get session command: "
                    "sandbox container not found"
                ),
                "benchmark_status": {
                    "task_outcome": "ERROR",
                    "failure_class": "infra_daytona",
                    "valid_for_analysis": False,
                },
            },
        },
        scores={
            "hardened_daytona_scorer": SimpleNamespace(
                answer="ERROR",
                value=float("nan"),
                metadata={
                    "benchmark_status": {
                        "task_outcome": "ERROR",
                        "failure_class": "infra_daytona",
                        "valid_for_analysis": False,
                    }
                },
            )
        },
        output=SimpleNamespace(model="openrouter/test/model"),
    )

    row = rdf.row_from_sample(
        sample,
        source_uri="gs://bucket/run.eval",
        experiment_id="exp-1",
        run_id="run-1",
        eval_id="eval-1",
        run_started_at="2026-06-23T10:00:00Z",
        benchmark="hardened_terminalbench_daytona",
        default_model="openrouter/test/model",
        task_args={},
    )

    assert row["task_outcome"] == "ERROR"
    assert row["failure_class"] == "infra_daytona"
    assert row["valid_for_analysis"] is False
    assert row["error_type"] == "daytona"
    assert row["error_needs_review"] is False


def test_row_from_sample_replays_daytona_status_with_shared_taxonomy():
    sample = SimpleNamespace(
        id="historical-daytona-error",
        uuid="historical-daytona-error-uuid",
        started_at="2026-06-23T10:00:01Z",
        completed_at="2026-06-23T10:00:02Z",
        metadata={
            "terminal_bench_task_id": "historical-daytona-error",
            "dataset": "terminal-bench-2.1",
            "terminalbench_daytona": {
                "answer": "ERROR",
                "reward": 0.0,
                "error": (
                    "DaytonaAuthenticationError: Failed to execute command: "
                    "bearer token is invalid"
                ),
            },
        },
        scores={
            "hardened_daytona_scorer": SimpleNamespace(
                answer="ERROR",
                value=float("nan"),
                metadata={},
            )
        },
        output=SimpleNamespace(model="openrouter/test/model"),
    )

    row = rdf.row_from_sample(
        sample,
        source_uri="gs://bucket/run.eval",
        experiment_id="exp-1",
        run_id="run-1",
        eval_id="eval-1",
        run_started_at="2026-06-23T10:00:00Z",
        benchmark="hardened_terminalbench_daytona",
        default_model="openrouter/test/model",
        task_args={},
    )

    assert row["task_outcome"] == "ERROR"
    assert row["failure_class"] == "infra_daytona"
    assert row["valid_for_analysis"] is False


def _fake_log(
    *,
    sample_id: str,
    created: str,
    run_id: str,
    dataset_samples: int = 1,
    answer: str = "PASS",
    reward: float = 1.0,
) -> SimpleNamespace:
    sample = SimpleNamespace(
        id=sample_id,
        uuid=f"{sample_id}-uuid",
        started_at="2026-06-23T10:00:01Z",
        completed_at="2026-06-23T10:00:02Z",
        metadata={
            "terminal_bench_task_id": sample_id,
            "dataset": "terminal-bench-2.1",
            "dataset_version": "terminal-bench-2.1",
            "policy": "default",
            "terminalbench_daytona": {
                "answer": answer,
                "reward": reward,
                "policy": "default",
            },
        },
        scores={"primary": SimpleNamespace(answer=answer, value=reward, metadata={})},
        output=SimpleNamespace(model="openrouter/test/model"),
    )
    return SimpleNamespace(
        status="success",
        eval=SimpleNamespace(
            run_id=run_id,
            eval_id=f"{run_id}-eval",
            created=created,
            task="hardened_terminalbench_daytona",
            model="openrouter/test/model",
            task_args={"policy": "default"},
            dataset=SimpleNamespace(samples=dataset_samples),
            metadata={"policy": "default"},
        ),
        samples=[sample],
    )


def _telemetry_sample(diagnostics: dict) -> SimpleNamespace:
    return SimpleNamespace(
        id="telemetry-task",
        uuid="telemetry-task-uuid",
        started_at="2026-07-07T10:00:01Z",
        completed_at="2026-07-07T10:00:02Z",
        metadata={
            "terminal_bench_task_id": "telemetry-task",
            "dataset": "terminal-bench-2.1",
            "terminalbench_daytona": {
                "answer": "FAIL",
                "reward": 0.0,
                "policy": "default",
                **diagnostics,
            },
        },
        scores={"primary": SimpleNamespace(answer="FAIL", value=0.0, metadata={})},
        output=SimpleNamespace(model="openrouter/test/model"),
    )


def test_row_exports_no_final_result_event_telemetry():
    sample = _telemetry_sample(
        {
            "agent_stdout_truncated_or_malformed": False,
            "agent_stdout_result_event_present": False,
            "agent_stdout_final_result_event_present": False,
            "agent_stdout_result_event_missing": True,
            "agent_model_usage_present": True,
            "agent_model_usage_source": "partial_events",
            "agent_model_usage_recovered": True,
            "agent_model_cost_available": False,
        }
    )

    row = rdf.row_from_sample(
        sample,
        source_uri="gs://bucket/run.eval",
        experiment_id="exp-1",
        run_id="run-1",
        eval_id="eval-1",
        run_started_at="2026-07-07T10:00:00Z",
        benchmark="hardened_terminalbench_daytona",
        default_model="openrouter/test/model",
        task_args={},
    )

    assert row["stream_truncated_or_malformed"] is False
    assert row["result_event_missing"] is True
    assert row["final_result_event_present"] is False
    assert row["model_usage_present"] is True
    assert row["model_usage_source"] == "partial_events"
    assert row["model_usage_recovered"] is True
    assert row["cost_available"] is False


def test_summary_counts_telemetry_gaps_distinctly():
    rows = [
        {
            "model": "m",
            "policy": "p",
            "mitigation_type": "none",
            "mitigation_configured": False,
            "task_id": "t1",
            "outcome_raw": "FAIL",
            "success": False,
            "valid_for_analysis": True,
            "policy_block_hit": False,
            "cost_usd": "",
            "cost_present": False,
            "runtime_total_ms": 100,
            "assistant_turns": 3,
            "assistant_turns_present": True,
            "stream_truncated_or_malformed": True,
            "final_result_event_present": False,
            "model_usage_present": False,
            "model_usage_recovered": False,
        },
        {
            "model": "m",
            "policy": "p",
            "mitigation_type": "none",
            "mitigation_configured": False,
            "task_id": "t2",
            "outcome_raw": "PASS",
            "success": True,
            "valid_for_analysis": True,
            "policy_block_hit": False,
            "cost_usd": 0.01,
            "cost_present": True,
            "runtime_total_ms": 200,
            "assistant_turns": 5,
            "assistant_turns_present": True,
            "stream_truncated_or_malformed": False,
            "final_result_event_present": False,
            "model_usage_present": True,
            "model_usage_recovered": True,
        },
    ]

    summary = rdf.summarize(rows)

    assert len(summary) == 1
    group = summary[0]
    assert group["malformed_stream_count"] == 1
    assert group["missing_final_result_event_count"] == 2
    assert group["missing_usage_count"] == 1
    assert group["usage_recovered_count"] == 1
