from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from inspect_ai.log import read_eval_log

from boundarybench.terminalbench import task_applicability

from boundarybench.benchmarks.common.completeness import (
    RunCompleteness,
    compute_completeness,
)
from boundarybench.benchmarks.common.log_filter import filter_logs
from boundarybench.benchmarks.common.status_taxonomy import sample_benchmark_status


FIELDNAMES = [
    "experiment_id",
    "run_id",
    "eval_id",
    "eval_file_uri",
    "artifact_status",
    "artifact_eval_status",
    "artifact_expected_samples",
    "artifact_completed_samples",
    "artifact_scored_samples",
    "artifact_error_samples",
    "artifact_completeness_pct",
    "artifact_completeness_reason",
    "run_started_at",
    "sample_started_at",
    "sample_completed_at",
    "sample_uuid",
    "model",
    "model_provider",
    "model_family",
    "benchmark",
    "benchmark_version",
    "task_id",
    "task_name",
    "task_split",
    "policy",
    "policy_overlays",
    "verifier_source",
    "policy_applicability",
    "policy_applicability_reason",
    "mitigation_type",
    "mitigation_configured",
    "block_message",
    "outcome_raw",
    "task_outcome",
    "failure_class",
    "valid_for_analysis",
    "success",
    "reward",
    "score_name",
    "policy_block_hit",
    "policy_event_count",
    "policy_block_count",
    "policy_block_commands",
    "policy_block_messages",
    "cost_usd",
    "cost_present",
    "cost_available",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "total_tokens",
    "stream_truncated_or_malformed",
    "result_event_present",
    "final_result_event_present",
    "result_event_missing",
    "model_usage_present",
    "model_usage_source",
    "model_usage_recovered",
    "runtime_total_ms",
    "runtime_working_ms",
    "agent_wall_ms",
    "agent_wall_present",
    "assistant_turns",
    "assistant_turns_present",
    "tool_calls",
    "internal_thinking_updates",
    "attempt",
    "max_attempts",
    "agent_user",
    "agent_timed_out",
    "transient_error",
    "error_type",
    "error_source",
    "error_message",
    "error_needs_review",
    "trace_uri",
    "transcript_present",
    "harbor_package_ref",
    "hardened_execution",
    "enforcement",
]

SUMMARY_FIELDNAMES = [
    "model",
    "policy",
    "mitigation_type",
    "mitigation_configured",
    "n_rows",
    "n_tasks",
    "not_applicable_count",
    "applicable_count",
    "adapted_verifier_count",
    "pass_count",
    "fail_count",
    "error_count",
    "success_rate",
    "valid_for_analysis_count",
    "invalid_for_analysis_count",
    "analysis_success_rate",
    "policy_block_rate",
    "avg_cost_usd_present_only",
    "avg_cost_usd_zero_missing",
    "cost_present_count",
    "avg_runtime_total_ms",
    "avg_assistant_turns",
    "missing_cost_count",
    "missing_runtime_count",
    "missing_steps_count",
    "malformed_stream_count",
    "missing_final_result_event_count",
    "missing_usage_count",
    "usage_recovered_count",
]

ERROR_REVIEW_FIELDNAMES = [
    "experiment_id",
    "run_id",
    "eval_file_uri",
    "artifact_status",
    "artifact_eval_status",
    "artifact_expected_samples",
    "artifact_completed_samples",
    "model",
    "policy",
    "mitigation_type",
    "task_id",
    "outcome_raw",
    "task_outcome",
    "failure_class",
    "valid_for_analysis",
    "error_type",
    "error_source",
    "error_message",
    "error_needs_review",
    "policy_block_hit",
    "policy_event_count",
    "policy_block_count",
    "trace_uri",
]

USAGE_RE = re.compile(
    r"\*\*Usage:\*\*\s+in=(?P<input>\d+)\s+out=(?P<output>\d+)\s+"
    r"cache_read=(?P<cache_read>\d+)\s+cache_write=(?P<cache_write>\d+)\s+"
    r"cost=(?P<cost>\$[0-9.]+|unpriced)"
)
WALL_RE = re.compile(r"\*\*Wall:\*\*\s+(?P<wall>\d+)\s+ms")
ACTIVITY_RE = re.compile(
    r"\*\*Activity:\*\*\s+(?P<turns>\d+)\s+assistant turns,\s+"
    r"(?P<tools>\d+)\s+tool calls"
    r"(?:,\s+(?P<thinking>\d+)\s+internal-thinking updates)?"
)
TURN_HEADING_RE = re.compile(r"^### Turn\s+\d+", re.M)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Export Terminal-Bench Inspect .eval logs to a row-level CSV for "
            "pandas/EDA, with optional summary and error-review CSVs."
        )
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help=(
            "Input .eval file, directory, glob, or gs:// path. Repeat for multiple "
            "runs. Directories are searched recursively for .eval files."
        ),
    )
    parser.add_argument("--output", required=True, help="Row-level CSV output path.")
    parser.add_argument(
        "--summary-output",
        help="Optional aggregate summary CSV grouped by model/policy/mitigation.",
    )
    parser.add_argument(
        "--error-review-output",
        help="Optional CSV containing ERROR rows for audit/review.",
    )
    parser.add_argument(
        "--experiment-id",
        default="",
        help="Experiment id to stamp on every row. Defaults to blank.",
    )
    parser.add_argument(
        "--dedupe",
        choices=["none", "latest"],
        default="none",
        help=(
            "Duplicate handling for repeated completed runs. Default 'none' "
            "preserves replicate runs; 'latest' keeps only the newest matching "
            "task/model/policy/sample set."
        ),
    )
    parser.add_argument(
        "--include-partial",
        action="store_true",
        help=(
            "Opt in to exporting recorded sample rows from partial eval artifacts. "
            "Rows are stamped with artifact completeness metadata so downstream "
            "analysis can filter them explicitly."
        ),
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="boundarybench-evals-") as tmp:
        evals = resolve_eval_inputs(args.input, temp_dir=Path(tmp))
        if not evals:
            parser.error("no .eval files matched --input")
        logs: list[tuple[Any, str]] = []
        source_by_log_id: dict[int, str] = {}
        for local_path, source_uri in evals:
            log = read_eval_log(str(local_path))
            logs.append((log, source_uri))
            source_by_log_id[id(log)] = source_uri
        filtered = filter_logs(
            [log for log, _source_uri in logs],
            dedupe=args.dedupe == "latest",
        )
        if filtered.excluded_count:
            print(
                "[terminalbench-results] filtered eval logs: "
                f"partial={len(filtered.partial)} "
                f"duplicate={len(filtered.duplicate)} "
                f"empty={len(filtered.empty)} "
                f"error={len(filtered.error)}"
            )
        export_logs = list(filtered.usable)
        if args.include_partial:
            export_logs.extend(filtered.partial)
        if not export_logs:
            parser.error("no exportable .eval logs matched --input")
        rows: list[dict[str, Any]] = []
        for log in export_logs:
            rows.extend(
                rows_from_log(
                    log,
                    source_uri=source_by_log_id[id(log)],
                    experiment_id=args.experiment_id,
                    artifact_completeness=compute_completeness(log),
                )
            )

        write_csv(Path(args.output), rows, FIELDNAMES)
        if args.summary_output:
            write_csv(Path(args.summary_output), summarize(rows), SUMMARY_FIELDNAMES)
        if args.error_review_output:
            errors = [
                {name: row.get(name, "") for name in ERROR_REVIEW_FIELDNAMES}
                for row in rows
                if row.get("outcome_raw") == "ERROR"
            ]
            write_csv(Path(args.error_review_output), errors, ERROR_REVIEW_FIELDNAMES)

    print(f"wrote {len(rows)} rows to {args.output}")
    return 0


def resolve_eval_inputs(inputs: list[str], *, temp_dir: Path) -> list[tuple[Path, str]]:
    evals: list[tuple[Path, str]] = []
    for raw_input in inputs:
        if raw_input.startswith("gs://"):
            evals.extend(_resolve_gcs_input(raw_input, temp_dir=temp_dir))
            continue

        matches = [Path(p) for p in glob.glob(raw_input, recursive=True)]
        path = Path(raw_input)
        if not matches and path.exists():
            matches = [path]
        for match in matches:
            if match.is_dir():
                evals.extend((p, str(p)) for p in sorted(match.rglob("*.eval")))
            elif match.suffix == ".eval":
                evals.append((match, str(match)))
    unique: dict[str, tuple[Path, str]] = {}
    for local_path, source_uri in evals:
        unique[source_uri] = (local_path, source_uri)
    return list(unique.values())


def _resolve_gcs_input(uri: str, *, temp_dir: Path) -> list[tuple[Path, str]]:
    candidates = [uri] if uri.endswith(".eval") else _gsutil_ls(uri)
    out: list[tuple[Path, str]] = []
    for source_uri in (c for c in candidates if c.endswith(".eval")):
        local = temp_dir / _safe_gcs_filename(source_uri)
        _run(["gsutil", "cp", source_uri, str(local)])
        out.append((local, source_uri))
    return out


def _safe_gcs_filename(uri: str) -> str:
    digest = hashlib.sha256(uri.encode("utf-8")).hexdigest()[:16]
    name = Path(uri.removesuffix("/")).name or "eval"
    if not name.endswith(".eval"):
        name = f"{name}.eval"
    return f"gcs-{digest}-{name}"


def _gsutil_ls(uri: str) -> list[str]:
    listing_uri = uri if uri.endswith("/") else f"{uri}/"
    proc = _run(["gsutil", "ls", "-r", listing_uri])
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def rows_from_log(
    log: Any,
    *,
    source_uri: str,
    experiment_id: str,
    artifact_completeness: RunCompleteness | None = None,
) -> list[dict[str, Any]]:
    eval_meta = getattr(log, "eval", None)
    run_id = getattr(eval_meta, "run_id", "") or ""
    eval_id = getattr(eval_meta, "eval_id", "") or ""
    created = getattr(eval_meta, "created", "") or ""
    benchmark = getattr(eval_meta, "task", "") or ""
    task_args = getattr(eval_meta, "task_args", {}) or {}
    default_model = getattr(eval_meta, "model", "") or ""
    rows = []
    for sample in log.samples or []:
        rows.append(
            row_from_sample(
                sample,
                source_uri=source_uri,
                experiment_id=experiment_id,
                run_id=run_id,
                eval_id=eval_id,
                run_started_at=created,
                benchmark=benchmark,
                default_model=default_model,
                task_args=task_args,
                artifact_completeness=artifact_completeness,
            )
        )
    return rows


def row_from_sample(
    sample: Any,
    *,
    source_uri: str,
    experiment_id: str,
    run_id: str,
    eval_id: str,
    run_started_at: str,
    benchmark: str,
    default_model: str,
    task_args: dict[str, Any],
    artifact_completeness: RunCompleteness | None = None,
) -> dict[str, Any]:
    sample_metadata = getattr(sample, "metadata", None) or {}
    score_name, score = _primary_score(getattr(sample, "scores", None) or {})
    score_metadata = getattr(score, "metadata", None) or {}
    metadata = dict(sample_metadata)
    metadata.update(score_metadata)
    terminalbench = sample_metadata.get("terminalbench_daytona") or score_metadata
    transcript = str(sample_metadata.get("transcript_markdown") or "")

    outcome_raw = normalize_outcome(
        getattr(score, "answer", None)
        or terminalbench.get("answer")
        or metadata.get("answer")
    )
    benchmark_status = benchmark_status_fields(
        terminalbench,
        score_metadata=score_metadata,
        outcome_raw=outcome_raw,
    )
    reward = _float_or_blank(terminalbench.get("reward", getattr(score, "value", "")))
    policy = str(terminalbench.get("policy") or sample_metadata.get("policy") or task_args.get("policy") or "")
    block_message = str(
        terminalbench.get("block_message")
        or sample_metadata.get("block_message")
        or task_args.get("block_message")
        or ""
    )
    mitigation_type = infer_mitigation_type(
        metadata,
        explicit_block_message=bool(task_args.get("block_message")),
    )
    policy_events = terminalbench.get("policy_events") or []
    policy_event_count = _policy_event_count(terminalbench, policy_events)
    policy_block_count = _policy_block_count(terminalbench, policy_events)
    task_id = str(
        sample_metadata.get("terminal_bench_task_id") or getattr(sample, "id", "")
    )
    row_verifier_source = str(
        terminalbench.get("verifier_source")
        or task_applicability.verifier_source(task_id)
    )
    row_policy_applicability = str(
        terminalbench.get("policy_applicability")
        or task_applicability.policy_applicability(task_id, policy)
    )
    row_policy_applicability_reason = str(
        terminalbench.get("policy_applicability_reason")
        or task_applicability.policy_applicability_reason(task_id, policy)
    )
    # The Inspect-level model is nominal here: the solver never calls
    # generate(), so ``output.model`` holds the placeholder while the harness
    # records the model actually under test. Prefer what the harness recorded
    # and keep the Inspect fields as fallbacks for logs without that metadata.
    model = str(
        sample_metadata.get("model")
        or task_args.get("model")
        or getattr(getattr(sample, "output", None), "model", None)
        or default_model
    )
    usage = extract_usage(sample, transcript)
    telemetry = extract_stream_telemetry(terminalbench)
    activity = extract_activity(terminalbench, transcript)
    runtime = extract_runtime(sample, transcript)
    error_message = str(terminalbench.get("error") or "")
    error_type, error_source, error_needs_review = classify_error(
        outcome_raw=outcome_raw,
        error_message=error_message,
        metadata=terminalbench,
    )

    row = {
        "experiment_id": experiment_id,
        "run_id": run_id,
        "eval_id": eval_id,
        "eval_file_uri": source_uri,
        **artifact_metadata(artifact_completeness),
        "run_started_at": run_started_at,
        "sample_started_at": getattr(sample, "started_at", "") or "",
        "sample_completed_at": getattr(sample, "completed_at", "") or "",
        "sample_uuid": getattr(sample, "uuid", "") or "",
        "model": model,
        "model_provider": model_provider(model),
        "model_family": model_family(model),
        "benchmark": benchmark,
        "benchmark_version": sample_metadata.get("dataset_version")
        or sample_metadata.get("dataset")
        or "",
        "task_id": task_id,
        "task_name": str(terminalbench.get("task_name") or getattr(sample, "id", "")),
        "task_split": str(sample_metadata.get("task_split") or ""),
        "policy": policy,
        "policy_overlays": json.dumps(terminalbench.get("policy_overlays") or sample_metadata.get("policy_overlays") or []),
        "verifier_source": row_verifier_source,
        "policy_applicability": row_policy_applicability,
        "policy_applicability_reason": row_policy_applicability_reason,
        "mitigation_type": mitigation_type,
        "mitigation_configured": mitigation_type != "none",
        "block_message": block_message,
        "outcome_raw": outcome_raw,
        "task_outcome": benchmark_status["task_outcome"],
        "failure_class": benchmark_status["failure_class"],
        "valid_for_analysis": benchmark_status["valid_for_analysis"],
        "success": outcome_raw == "PASS",
        "reward": reward,
        "score_name": score_name,
        "policy_block_hit": policy_block_count > 0,
        "policy_event_count": policy_event_count,
        "policy_block_count": policy_block_count,
        "policy_block_commands": json.dumps(policy_block_commands(terminalbench)),
        "policy_block_messages": json.dumps(policy_block_messages(terminalbench)),
        "cost_usd": usage["cost_usd"],
        "cost_present": usage["cost_usd"] != "",
        "cost_available": telemetry["cost_available"],
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "cache_read_tokens": usage["cache_read_tokens"],
        "cache_write_tokens": usage["cache_write_tokens"],
        "total_tokens": usage["total_tokens"],
        "stream_truncated_or_malformed": telemetry["stream_truncated_or_malformed"],
        "result_event_present": telemetry["result_event_present"],
        "final_result_event_present": telemetry["final_result_event_present"],
        "result_event_missing": telemetry["result_event_missing"],
        "model_usage_present": telemetry["model_usage_present"],
        "model_usage_source": telemetry["model_usage_source"],
        "model_usage_recovered": telemetry["model_usage_recovered"],
        "runtime_total_ms": runtime["runtime_total_ms"],
        "runtime_working_ms": runtime["runtime_working_ms"],
        "agent_wall_ms": runtime["agent_wall_ms"],
        "agent_wall_present": runtime["agent_wall_ms"] != "",
        "assistant_turns": activity["assistant_turns"],
        "assistant_turns_present": activity["assistant_turns"] != "",
        "tool_calls": activity["tool_calls"],
        "internal_thinking_updates": activity["internal_thinking_updates"],
        "attempt": terminalbench.get("attempt", ""),
        "max_attempts": terminalbench.get("max_attempts", ""),
        "agent_user": terminalbench.get("agent_user", ""),
        "agent_timed_out": bool(terminalbench.get("agent_timed_out", False)),
        "transient_error": bool(terminalbench.get("transient_error", False)),
        "error_type": error_type,
        "error_source": error_source,
        "error_message": error_message,
        "error_needs_review": error_needs_review,
        "trace_uri": f"{source_uri}#sample={getattr(sample, 'id', '')}",
        "transcript_present": bool(transcript),
        "harbor_package_ref": sample_metadata.get("harbor_package_ref") or task_args.get("ref") or "",
        "hardened_execution": sample_metadata.get("hardened_execution", ""),
        "enforcement": sample_metadata.get("enforcement", ""),
    }
    return {name: row.get(name, "") for name in FIELDNAMES}


def artifact_metadata(completeness: RunCompleteness | None) -> dict[str, Any]:
    if completeness is None:
        return {
            "artifact_status": "",
            "artifact_eval_status": "",
            "artifact_expected_samples": "",
            "artifact_completed_samples": "",
            "artifact_scored_samples": "",
            "artifact_error_samples": "",
            "artifact_completeness_pct": "",
            "artifact_completeness_reason": "",
        }
    return {
        "artifact_status": str(completeness.status),
        "artifact_eval_status": completeness.eval_status,
        "artifact_expected_samples": completeness.expected_samples,
        "artifact_completed_samples": completeness.completed_samples,
        "artifact_scored_samples": completeness.scored_samples,
        "artifact_error_samples": completeness.error_samples,
        "artifact_completeness_pct": completeness.completeness_pct,
        "artifact_completeness_reason": completeness.reason,
    }


def _primary_score(scores: dict[str, Any]) -> tuple[str, Any | None]:
    if "hardened_daytona_scorer" in scores:
        return "hardened_daytona_scorer", scores["hardened_daytona_scorer"]
    if scores:
        name = next(iter(scores))
        return name, scores[name]
    return "", None


def normalize_outcome(value: Any) -> str:
    outcome = str(value or "").strip().upper()
    if outcome in {"PASS", "FAIL", "ERROR"}:
        return outcome
    return "ERROR"


def benchmark_status_fields(
    metadata: dict[str, Any],
    *,
    score_metadata: dict[str, Any],
    outcome_raw: str,
) -> dict[str, Any]:
    status = metadata.get("benchmark_status")
    if not isinstance(status, dict):
        status = score_metadata.get("benchmark_status")
    if not isinstance(status, dict):
        status = sample_benchmark_status(metadata)

    task_outcome = str(status.get("task_outcome") or outcome_raw or "ERROR").upper()
    failure_class = str(
        status.get("failure_class") or _default_failure_class(task_outcome)
    )
    valid_for_analysis = status.get("valid_for_analysis")
    if valid_for_analysis is None:
        valid_for_analysis = task_outcome in {"PASS", "FAIL"} and failure_class in {
            "none",
            "task_model",
        }

    return {
        "task_outcome": task_outcome,
        "failure_class": failure_class,
        "valid_for_analysis": _truthy(valid_for_analysis),
    }


def _default_failure_class(task_outcome: str) -> str:
    if task_outcome == "PASS":
        return "none"
    if task_outcome == "FAIL":
        return "task_model"
    return "unknown"


def infer_mitigation_type(
    metadata: dict[str, Any], *, explicit_block_message: bool = False
) -> str:
    explicit = metadata.get("mitigation_type") or metadata.get("mitigation")
    if explicit:
        value = str(explicit).strip().lower().replace("-", "_")
        if value in {"none", "skill", "block_message"}:
            return value
    if explicit_block_message:
        return "block_message"
    return "none"


def extract_usage(sample: Any, transcript: str) -> dict[str, Any]:
    usage = {
        "cost_usd": "",
        "input_tokens": "",
        "output_tokens": "",
        "cache_read_tokens": "",
        "cache_write_tokens": "",
        "total_tokens": "",
    }
    model_usage = getattr(sample, "model_usage", None) or {}
    if model_usage:
        totals = defaultdict(float)
        has_cost = False
        for item in model_usage.values():
            totals["input_tokens"] += getattr(item, "input_tokens", 0) or 0
            totals["output_tokens"] += getattr(item, "output_tokens", 0) or 0
            totals["cache_read_tokens"] += getattr(item, "input_tokens_cache_read", 0) or 0
            totals["cache_write_tokens"] += getattr(item, "input_tokens_cache_write", 0) or 0
            totals["total_tokens"] += getattr(item, "total_tokens", 0) or 0
            cost = getattr(item, "total_cost", None)
            if cost is not None:
                totals["cost_usd"] += float(cost)
                has_cost = True
        usage.update({key: _clean_number(value) for key, value in totals.items()})
        if not has_cost:
            usage["cost_usd"] = ""
        return usage

    match = USAGE_RE.search(transcript)
    if match:
        usage.update(
            {
                "input_tokens": int(match.group("input")),
                "output_tokens": int(match.group("output")),
                "cache_read_tokens": int(match.group("cache_read")),
                "cache_write_tokens": int(match.group("cache_write")),
                "total_tokens": "",
                "cost_usd": (
                    ""
                    if match.group("cost") == "unpriced"
                    else float(match.group("cost").lstrip("$"))
                ),
            }
        )
    return usage


def extract_stream_telemetry(metadata: dict[str, Any]) -> dict[str, Any]:
    result_event_present = _optional_bool(
        metadata, "agent_stdout_result_event_present"
    )
    final_result_event_present = _optional_bool(
        metadata, "agent_stdout_final_result_event_present"
    )
    result_event_missing = _optional_bool(
        metadata, "agent_stdout_result_event_missing"
    )
    if result_event_missing == "" and result_event_present != "":
        result_event_missing = not bool(result_event_present)

    model_usage_present = _optional_bool(metadata, "agent_model_usage_present")
    if model_usage_present == "":
        model_usage_present = _optional_bool(metadata, "agent_model_usage_available")

    usage_source = str(metadata.get("agent_model_usage_source") or "")
    if not usage_source and model_usage_present is True:
        if _truthy(metadata.get("agent_stdout_result_event_usage_present")):
            usage_source = "result_event"
        else:
            usage_source = "unknown"

    cost_available = _optional_bool(metadata, "agent_model_cost_available")
    if cost_available == "" and "agent_model_cost_available" not in metadata:
        cost_available = ""

    return {
        "stream_truncated_or_malformed": _optional_bool(
            metadata, "agent_stdout_truncated_or_malformed"
        ),
        "result_event_present": result_event_present,
        "final_result_event_present": final_result_event_present,
        "result_event_missing": result_event_missing,
        "model_usage_present": model_usage_present,
        "model_usage_source": usage_source,
        "model_usage_recovered": _optional_bool(metadata, "agent_model_usage_recovered"),
        "cost_available": cost_available,
    }


def extract_activity(metadata: dict[str, Any], transcript: str) -> dict[str, Any]:
    activity = metadata.get("activity") or {}
    turns = activity.get("assistant_turns", "")
    tools = activity.get("tool_calls", "")
    thinking = activity.get("thinking_token_updates", "")
    if turns != "":
        return {
            "assistant_turns": turns,
            "tool_calls": tools,
            "internal_thinking_updates": thinking,
        }
    match = ACTIVITY_RE.search(transcript)
    if match:
        return {
            "assistant_turns": int(match.group("turns")),
            "tool_calls": int(match.group("tools")),
            "internal_thinking_updates": int(match.group("thinking") or 0),
        }
    headings = TURN_HEADING_RE.findall(transcript)
    if headings:
        return {
            "assistant_turns": len(headings),
            "tool_calls": "",
            "internal_thinking_updates": "",
        }
    return {"assistant_turns": "", "tool_calls": "", "internal_thinking_updates": ""}


def extract_runtime(sample: Any, transcript: str) -> dict[str, Any]:
    total_time = getattr(sample, "total_time", None)
    working_time = getattr(sample, "working_time", None)
    match = WALL_RE.search(transcript)
    return {
        "runtime_total_ms": _seconds_to_ms(total_time),
        "runtime_working_ms": _seconds_to_ms(working_time),
        "agent_wall_ms": int(match.group("wall")) if match else "",
    }


def classify_error(
    *,
    outcome_raw: str,
    error_message: str,
    metadata: dict[str, Any],
) -> tuple[str, str, bool]:
    if outcome_raw != "ERROR":
        return "", "", False
    text = f"{error_message} {metadata.get('error', '')}".lower()
    if metadata.get("agent_timed_out") or "timed out" in text or "timeout" in text:
        return "timeout", "agent", False
    if "no space left on device" in text or "disk quota" in text:
        return "disk", "sandbox", False
    if "out of memory" in text or "oom" in text or "memoryerror" in text:
        return "oom", "sandbox", False
    if "daytona" in text or "sandbox" in text or "session" in text or "container" in text:
        return "daytona", "sandbox", False
    if "verifier" in text or "harbor" in text or "test_outputs.py" in text:
        return "verifier", "verifier", False
    if "scorer" in text or not metadata:
        return "scorer_missing", "inspect", True
    return "unknown", "unknown", True


def policy_block_commands(metadata: dict[str, Any]) -> list[str]:
    commands = []
    for event in metadata.get("policy_events") or []:
        command = event.get("command")
        if command:
            commands.append(str(command))
    for blocked in metadata.get("blocked_surfaces") or []:
        command = blocked.get("command")
        if command:
            commands.append(str(command))
    return sorted(set(commands))


def policy_block_messages(metadata: dict[str, Any]) -> list[str]:
    messages = []
    for blocked in metadata.get("blocked_surfaces") or []:
        snippet = blocked.get("snippet")
        if snippet:
            messages.append(str(snippet))
        marker = blocked.get("marker")
        if marker:
            messages.append(str(marker))
    return sorted(set(messages))


def _policy_event_count(
    metadata: dict[str, Any], policy_events: list[dict[str, Any]]
) -> int:
    value = _int_or_none(metadata.get("policy_event_count"))
    if value is not None:
        return value
    return len(policy_events)


def _policy_block_count(
    metadata: dict[str, Any], policy_events: list[dict[str, Any]]
) -> int:
    if policy_events:
        return sum(
            1 for event in policy_events if event.get("event_type") == "policy_block"
        )
    value = _int_or_none(metadata.get("policy_block_count"))
    if value is not None:
        return value
    value = _int_or_none(metadata.get("blocked_surface_count"))
    if value is not None:
        return value
    return len(metadata.get("blocked_surfaces") or [])


def model_provider(model: str) -> str:
    parts = model.split("/")
    if parts and parts[0] == "openrouter" and len(parts) > 1:
        return parts[1]
    return parts[0] if parts else ""


def model_family(model: str) -> str:
    lowered = model.lower()
    if "haiku" in lowered:
        return "claude-haiku"
    if "sonnet" in lowered:
        return "claude-sonnet"
    if "opus" in lowered:
        return "claude-opus"
    return model.split("/")[-1] if model else ""


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[
            (
                row["model"],
                row["policy"],
                row["mitigation_type"],
                row["mitigation_configured"],
            )
        ].append(row)
    out = []
    for (model, policy, mitigation_type, mitigation_configured), group in sorted(groups.items()):
        outcomes = [row["outcome_raw"] for row in group]
        applicable_group = [
            row
            for row in group
            if row.get("policy_applicability") != "not_applicable"
        ]
        analysis_rows = [
            row
            for row in applicable_group
            if _truthy(row.get("valid_for_analysis"))
        ]
        out.append(
            {
                "model": model,
                "policy": policy,
                "mitigation_type": mitigation_type,
                "mitigation_configured": mitigation_configured,
                "n_rows": len(group),
                "n_tasks": len({row["task_id"] for row in group}),
                "not_applicable_count": len(group) - len(applicable_group),
                "applicable_count": len(applicable_group),
                "adapted_verifier_count": sum(
                    row.get("verifier_source") == "adapted" for row in group
                ),
                "pass_count": outcomes.count("PASS"),
                "fail_count": outcomes.count("FAIL"),
                "error_count": outcomes.count("ERROR"),
                "success_rate": _mean_bool(
                    row["success"] for row in applicable_group
                )
                if applicable_group
                else "",
                "valid_for_analysis_count": len(analysis_rows),
                "invalid_for_analysis_count": len(applicable_group)
                - len(analysis_rows),
                "analysis_success_rate": _mean_bool(
                    row["success"] for row in analysis_rows
                )
                if analysis_rows
                else "",
                "policy_block_rate": _mean_bool(row["policy_block_hit"] for row in group),
                "avg_cost_usd_present_only": _mean_numeric(row["cost_usd"] for row in group),
                "avg_cost_usd_zero_missing": _mean_numeric_zero_missing(
                    row["cost_usd"] for row in group
                ),
                "cost_present_count": sum(bool(row["cost_present"]) for row in group),
                "avg_runtime_total_ms": _mean_numeric(row["runtime_total_ms"] for row in group),
                "avg_assistant_turns": _mean_numeric(row["assistant_turns"] for row in group),
                "missing_cost_count": sum(not bool(row["cost_present"]) for row in group),
                "missing_runtime_count": sum(row["runtime_total_ms"] == "" for row in group),
                "missing_steps_count": sum(not bool(row["assistant_turns_present"]) for row in group),
                "malformed_stream_count": sum(
                    _truthy(row.get("stream_truncated_or_malformed")) for row in group
                ),
                "missing_final_result_event_count": sum(
                    _explicit_false(row.get("final_result_event_present")) for row in group
                ),
                "missing_usage_count": sum(
                    _explicit_false(row.get("model_usage_present")) for row in group
                ),
                "usage_recovered_count": sum(
                    _truthy(row.get("model_usage_recovered")) for row in group
                ),
            }
        )
    return out


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _mean_bool(values: Any) -> float:
    items = [bool(value) for value in values]
    return sum(items) / len(items) if items else 0.0


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _optional_bool(metadata: dict[str, Any], key: str) -> bool | str:
    value = metadata.get(key)
    if key not in metadata or value is None or value == "":
        return ""
    return _truthy(value)


def _explicit_false(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, str):
        return value.strip().lower() in {"0", "false", "no", "off"}
    return value is False


def _mean_numeric(values: Any) -> float | str:
    nums = [float(value) for value in values if value != ""]
    return sum(nums) / len(nums) if nums else ""


def _mean_numeric_zero_missing(values: Any) -> float | str:
    items = list(values)
    if not items:
        return ""
    return sum(float(value) if value != "" else 0.0 for value in items) / len(items)


def _int_or_none(value: Any) -> int | None:
    if value in {"", None}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _seconds_to_ms(value: Any) -> int | str:
    if value in {"", None}:
        return ""
    return round(float(value) * 1000)


def _float_or_blank(value: Any) -> float | str:
    if value in {"", None}:
        return ""
    return float(value)


def _clean_number(value: Any) -> int | float | str:
    if value in {"", None}:
        return ""
    number = float(value)
    return int(number) if number.is_integer() else number


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
