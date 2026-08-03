"""Canonical-trace normalization for Harbor's Terminus-2 ATIF output.

First-party translation layer (ours, not upstream's): it maps Harbor's ATIF
``trajectory.json`` and the ``bridge.py`` runner-result sentinel onto the shared
canonical trace schema. The schema and cross-harness helpers stay in
``boundarybench.harness.canonical_trace``; only Terminus-specific parsing
lives here.
"""

from __future__ import annotations

import json
from typing import Any

from boundarybench.harness.canonical_trace import (
    EVENT_ASSISTANT_MESSAGE,
    EVENT_ERROR,
    EVENT_FINAL_RESULT,
    EVENT_REASONING,
    EVENT_TOOL_CALL,
    EVENT_TOOL_RESULT,
    CanonicalTrace,
    TraceEvent,
    TraceObservability,
    _bounded,
    _int,
    _link_policy_events,
    _normalize_policy_events,
    _policy_events_changed,
    _policy_events_truncated,
    _SeqCounter,
    _trace_has_redaction,
    _trace_has_truncation,
    _usage_mapping,
)

SOURCE_TERMINUS_2_ATIF = "terminus_2_atif_trajectory"
SOURCE_TERMINUS_2_RESULT = "terminus_2_runner_result"


def trace_from_terminus_2(
    *,
    agent_stdout: str,
    model: str,
    session_artifacts: dict[str, Any] | None,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    """Normalize Harbor's ATIF trajectory emitted by Terminus-2."""

    trajectory_content: str | None = None
    artifact_truncated = False
    if isinstance(session_artifacts, dict):
        for entry in session_artifacts.get("files") or []:
            if not isinstance(entry, dict):
                continue
            path = str(entry.get("path") or "")
            content = entry.get("content")
            if path.endswith("/trajectory.json") and isinstance(content, str):
                trajectory_content = content
                artifact_truncated = bool(entry.get("truncated"))
                break

    if trajectory_content is None:
        return _terminus_2_trace_from_result(
            agent_stdout=agent_stdout,
            model=model,
            policy_events=policy_events,
        )

    try:
        trajectory = json.loads(trajectory_content)
    except json.JSONDecodeError:
        fallback = _terminus_2_trace_from_result(
            agent_stdout=agent_stdout,
            model=model,
            policy_events=policy_events,
        )
        fallback.observability.source = SOURCE_TERMINUS_2_ATIF
        fallback.observability.complete = False
        fallback.observability.parse_error_count += 1
        fallback.observability.notes.append("Terminus-2 trajectory.json was malformed")
        return fallback

    if not isinstance(trajectory, dict):
        fallback = _terminus_2_trace_from_result(
            agent_stdout=agent_stdout,
            model=model,
            policy_events=policy_events,
        )
        fallback.observability.source = SOURCE_TERMINUS_2_ATIF
        fallback.observability.complete = False
        fallback.observability.parse_error_count += 1
        fallback.observability.notes.append(
            "Terminus-2 trajectory.json top level was not an object"
        )
        return fallback
    steps = trajectory.get("steps")
    if "steps" not in trajectory or not isinstance(steps, list):
        fallback = _terminus_2_trace_from_result(
            agent_stdout=agent_stdout,
            model=model,
            policy_events=policy_events,
        )
        fallback.observability.source = SOURCE_TERMINUS_2_ATIF
        fallback.observability.complete = False
        fallback.observability.parse_error_count += 1
        fallback.observability.notes.append(
            "Terminus-2 trajectory.json steps was missing or not an array"
        )
        return fallback
    seq = _SeqCounter()
    events: list[TraceEvent] = []
    final_text: str | None = None
    completion_pending = False
    confirmed_completion = False
    parse_errors = 0
    evidence_notes: list[str] = []
    last_agent_timestamp: str | None = None
    for step_index, step in enumerate(steps):
        if not isinstance(step, dict):
            parse_errors += 1
            continue
        if step.get("source") != "agent":
            continue
        timestamp = step.get("timestamp")
        timestamp = timestamp if isinstance(timestamp, str) and timestamp.strip() else None
        last_agent_timestamp = timestamp or last_agent_timestamp
        reasoning = step.get("reasoning_content")
        if isinstance(reasoning, str) and reasoning.strip():
            events.append(
                TraceEvent(seq.next(), EVENT_REASONING, timestamp, text=reasoning)
            )
        message = step.get("message")
        if isinstance(message, str) and message.strip():
            final_text = message.strip()
            events.append(
                TraceEvent(
                    seq.next(), EVENT_ASSISTANT_MESSAGE, timestamp, text=final_text
                )
            )

        calls = step.get("tool_calls")
        if calls is not None and not isinstance(calls, list):
            parse_errors += 1
        emitted_call_ids: list[str] = []
        requested_completion = False
        for call_index, call in enumerate(calls if isinstance(calls, list) else []):
            if not isinstance(call, dict):
                parse_errors += 1
                continue
            name = str(call.get("function_name") or "") or None
            call_id = str(call.get("tool_call_id") or "")
            if not call_id:
                parse_errors += 1
                call_id = f"terminus-step-{step_index}-call-{call_index}"
            if name == "mark_task_complete":
                requested_completion = True
            emitted_call_ids.append(call_id)
            events.append(
                TraceEvent(
                    seq.next(),
                    EVENT_TOOL_CALL,
                    timestamp,
                    tool_call_id=call_id,
                    tool_name=name,
                    arguments=call.get("arguments") or {},
                )
            )
        confirmed_completion = confirmed_completion or (
            completion_pending and requested_completion
        )
        if requested_completion:
            completion_pending = True
        elif not _terminus_2_parse_feedback_step(step):
            completion_pending = False

        observation = step.get("observation")
        results = observation.get("results") if isinstance(observation, dict) else None
        results_valid = isinstance(results, list)
        if emitted_call_ids and not results_valid:
            parse_errors += 1
            evidence_notes.append(
                f"Terminus-2 step {step_index} tool observation.results was "
                "missing or not an array"
            )
        scoped_outputs: dict[str, str] = {}
        shared_outputs: list[str] = []
        for result in results if results_valid else []:
            if not isinstance(result, dict):
                parse_errors += 1
                continue
            output = result.get("content")
            source_id = result.get("source_call_id")
            if output is None:
                continue
            if source_id is None:
                shared_outputs.append(str(output))
                continue
            normalized_source_id = str(source_id)
            if normalized_source_id not in emitted_call_ids:
                parse_errors += 1
                continue
            scoped_outputs[normalized_source_id] = str(output)

        shared_output = "\n\n".join(shared_outputs)
        for call_id in emitted_call_ids:
            if call_id in scoped_outputs:
                output = scoped_outputs[call_id]
            elif shared_outputs:
                output = shared_output
            else:
                if results_valid:
                    parse_errors += 1
                    evidence_notes.append(
                        f"Terminus-2 step {step_index} has no observation content "
                        f"for tool call {call_id}"
                    )
                continue
            events.append(
                TraceEvent(
                    seq.next(),
                    EVENT_TOOL_RESULT,
                    timestamp,
                    tool_call_id=call_id,
                    output=output,
                )
            )

    from boundarybench.harness.terminus_2 import _result_object

    runner_result = _result_object(agent_stdout) or {}
    runner_terminal = runner_result.get("status") in {"ok", "error"}
    confirmed_completion = (
        confirmed_completion
        and runner_result.get("status") == "ok"
        and runner_result.get("task_complete") is True
    )
    if runner_result.get("status") == "error":
        events.append(
            TraceEvent(
                seq.next(),
                EVENT_ERROR,
                timestamp=None,
                message=_terminus_2_error_message(runner_result),
            )
        )
    elif confirmed_completion:
        events.append(
            TraceEvent(
                seq.next(),
                EVENT_FINAL_RESULT,
                timestamp=last_agent_timestamp,
                text=final_text or "task complete",
            )
        )

    metrics = trajectory.get("final_metrics")
    usage = None
    if isinstance(metrics, dict):
        usage = _usage_mapping(
            {
                "input": _int(metrics, "total_prompt_tokens"),
                "output": _int(metrics, "total_completion_tokens"),
                "cache_read": _int(metrics, "total_cached_tokens"),
                "cache_write": 0,
            },
            model=model,
            input_includes_cache=True,
        )
        native_cost = metrics.get("total_cost_usd")
        if usage is not None and isinstance(native_cost, (int, float)):
            usage["total_cost"] = float(native_cost)
            usage["cost_source"] = "terminus_2_atif"

    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    truncated = (
        artifact_truncated
        or _trace_has_truncation(events)
        or _policy_events_truncated(normalized_policy_events)
    )
    unobservable: list[str] = []
    if any(event.timestamp is None for event in events):
        unobservable.append("per_event_timestamps")
    if any(event.type == EVENT_TOOL_RESULT for event in events) and all(
        event.exit_code is None
        for event in events
        if event.type == EVENT_TOOL_RESULT
    ):
        unobservable.append("tool_exit_code")
    if usage is None:
        unobservable.append("usage")
    observability = TraceObservability(
        source=SOURCE_TERMINUS_2_ATIF,
        complete=not artifact_truncated and parse_errors == 0 and runner_terminal,
        truncated=truncated,
        parse_error_count=parse_errors,
        redaction_applied=(
            _policy_events_changed(policy_events) or _trace_has_redaction(events)
        ),
        unobservable_fields=unobservable,
    )
    if not runner_terminal:
        observability.notes.append("Terminus-2 runner result missing; run may be cut")
    if not confirmed_completion:
        observability.notes.append(
            "no confirmed mark_task_complete event; trajectory may represent a cut run"
        )
    observability.notes.extend(evidence_notes)
    return CanonicalTrace(
        harness="terminus_2",
        model=model,
        events=events,
        observability=observability,
        usage=usage,
        final_result=_bounded(final_text)[0] if confirmed_completion else None,
        policy_events=normalized_policy_events,
    )


def _terminus_2_parse_feedback_step(step: dict[str, Any]) -> bool:
    """Whether Harbor preserved pending completion across a parser retry."""

    observation = step.get("observation")
    results = observation.get("results") if isinstance(observation, dict) else None
    if not isinstance(results, list):
        return False
    return any(
        isinstance(result, dict)
        and isinstance(result.get("content"), str)
        and result["content"].startswith("Previous response had parsing errors:")
        for result in results
    )


def _terminus_2_error_message(result: dict[str, Any]) -> str:
    """Preserve the structured runner error type even when detail is empty."""

    error_type = str(result.get("error_type") or "").strip()
    error_detail = str(result.get("error") or "").strip()
    if error_type and error_detail and not error_detail.startswith(error_type):
        return f"{error_type}: {error_detail}"
    return error_detail or error_type or "Terminus-2 runner failed"


def _terminus_2_trace_from_result(
    *,
    agent_stdout: str,
    model: str,
    policy_events: list[dict[str, Any]] | None,
) -> CanonicalTrace:
    from boundarybench.harness.terminus_2 import _result_object

    result = _result_object(agent_stdout) or {}
    status = str(result.get("status") or "")
    final_text = str(result.get("final_message") or "").strip() or None
    task_complete = result.get("task_complete") is True
    events: list[TraceEvent] = []
    if final_text:
        events.append(TraceEvent(0, EVENT_ASSISTANT_MESSAGE, text=final_text))
    if status == "error":
        events.append(
            TraceEvent(
                len(events),
                EVENT_ERROR,
                message=_terminus_2_error_message(result),
            )
        )
        final_text = None
    elif task_complete:
        events.append(
            TraceEvent(len(events), EVENT_FINAL_RESULT, text=final_text or "task complete")
        )
    raw_usage = result.get("usage")
    usage = None
    if isinstance(raw_usage, dict):
        usage = _usage_mapping(
            {
                "input": _int(raw_usage, "input_tokens"),
                "output": _int(raw_usage, "output_tokens"),
                "cache_read": _int(raw_usage, "cached_input_tokens"),
                "cache_write": 0,
            },
            model=model,
            input_includes_cache=True,
        )
        native_cost = raw_usage.get("cost_usd")
        if usage is not None and isinstance(native_cost, (int, float)):
            usage["total_cost"] = float(native_cost)
            usage["cost_source"] = "terminus_2_runner_result"
    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    return CanonicalTrace(
        harness="terminus_2",
        model=model,
        events=events,
        observability=TraceObservability(
            source=SOURCE_TERMINUS_2_RESULT,
            complete=False,
            truncated=_policy_events_truncated(normalized_policy_events),
            redaction_applied=(
                _policy_events_changed(policy_events) or _trace_has_redaction(events)
            ),
            unobservable_fields=[
                "reasoning",
                "tool_calls",
                "tool_results",
                "tool_exit_code",
                "per_event_timestamps",
                *([] if usage is not None else ["usage"]),
            ],
            notes=[
                "Terminus-2 ATIF session artifact unavailable; runner result is a fallback"
            ],
        ),
        usage=usage,
        final_result=final_text if task_complete else None,
        policy_events=normalized_policy_events,
    )
