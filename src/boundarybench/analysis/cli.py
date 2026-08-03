"""`boundarybench analyze`: post-run policy-blockage analysis over .eval logs.

Reads Inspect `.eval` logs produced by `boundarybench run`, extracts each
sample's recorded policy-event stream, and runs the policy-blockage analyzer
(`boundarybench.analysis.policy_blockages`) to report how often — and on which
N/F/P axis — the policy actually blocked the agent. Task outcome is never
consulted; this is evidence-only analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from boundarybench.analysis.policy_blockages import analyze_policy_blockages
from boundarybench.daytona.policy_axes import AXIS_PRESETS
from boundarybench.terminalbench import task_applicability


def _terminalbench_metadata(sample: Any) -> dict[str, Any]:
    metadata = getattr(sample, "metadata", None) or {}
    terminalbench = metadata.get("terminalbench_daytona")
    if isinstance(terminalbench, dict):
        return terminalbench
    scores = getattr(sample, "scores", None) or {}
    for score in scores.values():
        score_metadata = getattr(score, "metadata", None) or {}
        if score_metadata.get("policy_events") is not None:
            return score_metadata
    return {}


def analyze_sample(sample: Any, *, run_id: str = "") -> dict[str, Any] | None:
    """Analyze one eval sample; returns None without an N x F x P policy."""

    terminalbench = _terminalbench_metadata(sample)
    metadata = getattr(sample, "metadata", None) or {}
    policy = str(terminalbench.get("policy") or metadata.get("policy") or "")
    if policy not in AXIS_PRESETS:
        return None

    task_id = str(
        terminalbench.get("task_id")
        or metadata.get("task_id")
        or getattr(sample, "id", "")
    )
    full_trace = terminalbench.get("full_trace") or metadata.get("full_trace")
    analysis = analyze_policy_blockages(
        policy=policy,
        policy_events=terminalbench.get("policy_events") or [],
        full_trace=full_trace if isinstance(full_trace, dict) else None,
        run_id=run_id,
        task_id=task_id,
    )
    return {
        "task_id": task_id,
        "policy": policy,
        "verifier_source": str(
            terminalbench.get("verifier_source")
            or task_applicability.verifier_source(task_id)
        ),
        "policy_applicability": str(
            terminalbench.get("policy_applicability")
            or task_applicability.policy_applicability(task_id, policy)
        ),
        "hit_count": analysis.hit_count,
        "blocked_trial_count": analysis.blocked_trial_count,
        "axis_counts": analysis.axis_counts(),
        "summary": analysis.to_metadata_mapping(),
    }


def analyze_logs(logs: list[Any]) -> dict[str, Any]:
    """Analyze samples across eval logs; skips samples without policy data."""

    rows: list[dict[str, Any]] = []
    skipped = 0
    for log in logs:
        run_id = str(getattr(getattr(log, "eval", None), "run_id", "") or "")
        for sample in getattr(log, "samples", None) or []:
            row = analyze_sample(sample, run_id=run_id)
            if row is None:
                skipped += 1
                continue
            rows.append(row)

    totals = {
        "samples_analyzed": len(rows),
        "samples_skipped_no_axis_policy": skipped,
        "samples_not_applicable": sum(
            row["policy_applicability"] == "not_applicable" for row in rows
        ),
        "samples_adapted_verifier": sum(
            row["verifier_source"] == "adapted" for row in rows
        ),
        "policy_hit_occurrences": sum(row["hit_count"] for row in rows),
        "blocked_trials": sum(row["blocked_trial_count"] for row in rows),
    }
    return {"totals": totals, "samples": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="boundarybench analyze",
        description=(
            "Analyze policy blockages recorded in .eval logs. Reports per-sample "
            "and aggregate policy-hit counts by N/F/P axis, independent of task "
            "outcome."
        ),
    )
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help=".eval file, directory, or glob (repeatable)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the JSON report to this path instead of stdout",
    )
    args = parser.parse_args(argv)

    from inspect_ai.log import read_eval_log

    from boundarybench.terminalbench.results_dataframe import resolve_eval_inputs

    with tempfile.TemporaryDirectory(prefix="boundarybench-analyze-") as tmp:
        evals = resolve_eval_inputs(args.input, temp_dir=Path(tmp))
        if not evals:
            parser.error("no .eval files matched --input")
        logs = [read_eval_log(str(local_path)) for local_path, _source in evals]
        report = analyze_logs(logs)

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"[boundarybench-analyze] wrote {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return 0
