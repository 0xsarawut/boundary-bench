"""Shared contract tests for the canonical harness-neutral full trace.

These prove that Claude Code, Codex, and Grok all produce the *same* trace
schema and semantics: identical top-level keys, the same closed set
of event types, stable ``seq`` ordering, tool-call/result correlation by
``tool_call_id``, and explicit completeness/observability metadata. The Grok
cases additionally prove the full event stream (reasoning, tool calls +
results, usage) is recovered from the exported session ``updates.jsonl`` and
that unavailable data is recorded as explicitly unobservable rather than
dropped.
"""

from __future__ import annotations

import json

import pytest

from boundarybench.harness.canonical_trace import (
    CANONICAL_TRACE_SCHEMA_VERSION,
    EVENT_ASSISTANT_MESSAGE,
    EVENT_ERROR,
    EVENT_FINAL_RESULT,
    EVENT_REASONING,
    EVENT_TOOL_CALL,
    EVENT_TOOL_RESULT,
    SOURCE_GROK_FINAL_OBJECT,
    SOURCE_GROK_SESSION_UPDATES,
    TraceEvent,
    trace_from_claude_stream,
    trace_from_codex_events,
    trace_from_grok,
)
from boundarybench.harness.runtime.harbor_terminus_2.trace import (
    trace_from_terminus_2,
)
from boundarybench.harness.registry import get_harness_adapter


CLAUDE_STREAM = (
    '{"type":"assistant","message":{"content":['
    '{"type":"thinking","thinking":"I should list files."},'
    '{"type":"text","text":"Let me look."},'
    '{"type":"tool_use","id":"tu_1","name":"Bash","input":{"command":"ls"}}'
    '],"usage":{"input_tokens":100,"output_tokens":10}}}\n'
    '{"type":"user","message":{"content":['
    '{"type":"tool_result","tool_use_id":"tu_1","content":[{"type":"text","text":"file1"}]}'
    ']}}\n'
    '{"type":"result","subtype":"success","result":"Listed files.",'
    '"usage":{"input_tokens":120,"output_tokens":15}}\n'
)

CODEX_STREAM = (
    '{"type":"item.started","item":{"id":"i1","type":"command_execution",'
    '"command":"ls","status":"in_progress"}}\n'
    '{"type":"item.completed","item":{"id":"i1","type":"command_execution",'
    '"command":"ls","status":"completed","aggregated_output":"file1","exit_code":0}}\n'
    '{"type":"item.completed","item":{"id":"i2","type":"agent_message",'
    '"text":"Listed files."}}\n'
    '{"type":"token_count","usage":{"input_tokens":130,"output_tokens":8}}\n'
)


def _grok_update(session_update: dict, *, ts_ms: int, method: str = "session/update") -> dict:
    return {
        "timestamp": ts_ms // 1000,
        "method": method,
        "params": {
            "sessionId": "s1",
            "update": session_update,
            "_meta": {"agentTimestampMs": ts_ms},
        },
    }


GROK_UPDATES = "\n".join(
    json.dumps(line)
    for line in [
        _grok_update(
            {"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": "list files"}},
            ts_ms=1_783_860_949_000,
        ),
        _grok_update(
            {"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "I should "}},
            ts_ms=1_783_860_950_000,
        ),
        _grok_update(
            {"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "run ls."}},
            ts_ms=1_783_860_950_500,
        ),
        _grok_update(
            {
                "sessionUpdate": "tool_call",
                "toolCallId": "tc_1",
                "title": "run_terminal_cmd",
                "kind": "execute",
                "status": "pending",
                "rawInput": {"command": "ls"},
            },
            ts_ms=1_783_860_951_000,
        ),
        _grok_update(
            {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "tc_1",
                "status": "completed",
                "content": [{"type": "content", "content": {"type": "text", "text": "file1"}}],
                "rawOutput": {"exit_code": 0},
            },
            ts_ms=1_783_860_952_000,
        ),
        _grok_update(
            {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Listed files."}},
            ts_ms=1_783_860_953_000,
        ),
        _grok_update(
            {
                "sessionUpdate": "turn_completed",
                "prompt_id": "p1",
                "stop_reason": "end_turn",
                "agent_result": "Listed files.",
                "usage": {"input_tokens": 120, "output_tokens": 15},
            },
            ts_ms=1_783_860_954_000,
            method="_x.ai/session/update",
        ),
    ]
)


def _grok_session_artifacts(updates: str, *, truncated: bool = False) -> dict:
    return {
        "truncated": truncated,
        "files": [
            {
                "path": "/home/daytona/.grok/sessions/enc/s1/updates.jsonl",
                "content": updates,
                "truncated": truncated,
            }
        ],
    }


TERMINUS_TRAJECTORY = json.dumps(
    {
        "steps": [
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:00Z",
                "message": "Analysis: inspect files\nPlan: run ls",
                "reasoning_content": "I should inspect the workspace.",
                "tool_calls": [
                    {
                        "tool_call_id": "call_0_1",
                        "function_name": "bash_command",
                        "arguments": {"keystrokes": "ls\n", "duration": 0.1},
                    },
                    {
                        "tool_call_id": "call_0_2",
                        "function_name": "bash_command",
                        "arguments": {"keystrokes": "pwd\n", "duration": 0.1},
                    },
                    {
                        "tool_call_id": "call_0_task_complete",
                        "function_name": "mark_task_complete",
                        "arguments": {},
                    },
                ],
                "observation": {
                    "results": [{"source_call_id": None, "content": "file1\n/app"}]
                },
            },
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:01Z",
                "message": "Analysis: verified\nPlan: finish",
                "tool_calls": [
                    {
                        "tool_call_id": "call_1_task_complete",
                        "function_name": "mark_task_complete",
                        "arguments": {},
                    }
                ],
                "observation": {"results": [{"content": "confirmed"}]},
            },
        ],
        "final_metrics": {
            "total_prompt_tokens": 120,
            "total_completion_tokens": 15,
            "total_cached_tokens": 20,
            "total_cost_usd": 0.001,
        },
    }
)


def _terminus_session_artifacts(*, truncated: bool = False) -> dict:
    return {
        "truncated": truncated,
        "files": [
            {
                "path": "/home/daytona/.terminus-2/sessions/current/trajectory.json",
                "content": TERMINUS_TRAJECTORY,
                "truncated": truncated,
            }
        ],
    }


TERMINUS_STDOUT = (
    'TERMINUS2_RESULT {"status":"ok","assistant_turns":1,'
    '"tool_calls":4,"task_tool_calls":2,"final_message":"done","task_complete":true,'
    '"usage":{"input_tokens":120,"output_tokens":15,"cached_input_tokens":20}}'
)


REQUIRED_TRACE_KEYS = {
    "schema_version",
    "harness",
    "model",
    "event_count",
    "assistant_message_count",
    "tool_call_count",
    "final_result",
    "usage",
    "observability",
    "policy_events",
    "events",
}
REQUIRED_OBSERVABILITY_KEYS = {
    "source",
    "complete",
    "truncated",
    "parse_error_count",
    "redaction_applied",
    "unobservable_fields",
    "notes",
}
ALLOWED_EVENT_TYPES = {
    EVENT_ASSISTANT_MESSAGE,
    EVENT_REASONING,
    EVENT_TOOL_CALL,
    EVENT_TOOL_RESULT,
    EVENT_ERROR,
    EVENT_FINAL_RESULT,
}


def _all_traces() -> dict[str, dict]:
    return {
        "claude_code": trace_from_claude_stream(
            agent_stdout=CLAUDE_STREAM, model="anthropic/claude"
        ).to_mapping(),
        "codex": trace_from_codex_events(
            agent_stdout=CODEX_STREAM, model="openai/codex"
        ).to_mapping(),
        "grok": trace_from_grok(
            agent_stdout='{"text":"Listed files.","stopReason":"EndTurn"}',
            model="x-ai/grok-4",
            session_artifacts=_grok_session_artifacts(GROK_UPDATES),
        ).to_mapping(),
        "terminus_2": trace_from_terminus_2(
            agent_stdout=TERMINUS_STDOUT,
            model="deepseek/deepseek-v4-flash",
            session_artifacts=_terminus_session_artifacts(),
        ).to_mapping(),
    }


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_trace_has_identical_top_level_schema(harness):
    trace = _all_traces()[harness]
    assert set(trace) == REQUIRED_TRACE_KEYS, harness
    assert trace["schema_version"] == CANONICAL_TRACE_SCHEMA_VERSION
    assert trace["harness"] == harness
    assert set(trace["observability"]) == REQUIRED_OBSERVABILITY_KEYS, harness


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_events_have_stable_ordering_and_timestamp_key(harness):
    events = _all_traces()[harness]["events"]
    assert events, harness
    for index, event in enumerate(events):
        assert event["seq"] == index, harness
        assert event["type"] in ALLOWED_EVENT_TYPES, harness
        assert "timestamp" in event, harness


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_tool_results_correlate_to_a_prior_tool_call(harness):
    events = _all_traces()[harness]["events"]
    seen_call_ids: set[str] = set()
    tool_calls = 0
    tool_results = 0
    for event in events:
        if event["type"] == EVENT_TOOL_CALL:
            tool_calls += 1
            if event.get("tool_call_id"):
                seen_call_ids.add(event["tool_call_id"])
        elif event["type"] == EVENT_TOOL_RESULT:
            tool_results += 1
            assert event.get("tool_call_id") in seen_call_ids, harness
    assert tool_calls >= 1, harness
    assert tool_results >= 1, harness


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_tool_call_count_matches_activity_summary(harness):
    trace = _all_traces()[harness]
    stdout = {
        "claude_code": CLAUDE_STREAM,
        "codex": CODEX_STREAM,
        "terminus_2": TERMINUS_STDOUT,
    }.get(harness, "")
    if harness == "grok":
        assert trace["tool_call_count"] == 1
        return
    summary = get_harness_adapter(harness).activity_summary(stdout)
    assert trace["tool_call_count"] == summary["tool_calls"], harness


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_usage_metadata_present_and_shaped(harness):
    usage = _all_traces()[harness]["usage"]
    assert usage is not None, harness
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        assert key in usage, harness
    assert usage["total_tokens"] == usage["input_tokens"] + usage["output_tokens"], harness


def test_terminus_batch_observation_correlates_once_to_each_command():
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=_terminus_session_artifacts(),
    )
    calls = [event for event in trace.events if event.type == EVENT_TOOL_CALL]
    results = [event for event in trace.events if event.type == EVENT_TOOL_RESULT]
    assert [event.tool_call_id for event in calls] == [
        "call_0_1",
        "call_0_2",
        "call_0_task_complete",
        "call_1_task_complete",
    ]
    assert [event.tool_call_id for event in results] == [
        "call_0_1",
        "call_0_2",
        "call_0_task_complete",
        "call_1_task_complete",
    ]
    assert [event.output for event in results] == [
        "file1\n/app",
        "file1\n/app",
        "file1\n/app",
        "confirmed",
    ]
    assert "tool_exit_code" in trace.observability.unobservable_fields


@pytest.mark.parametrize(
    "observation",
    [None, {}, {"results": "not-an-array"}, {"results": []}],
)
def test_terminus_missing_tool_observation_is_explicitly_incomplete(observation):
    trajectory = json.loads(TERMINUS_TRAJECTORY)
    trajectory["steps"][0]["observation"] = observation
    artifacts = _terminus_session_artifacts()
    artifacts["files"][0]["content"] = json.dumps(trajectory)

    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )

    first_step_call_ids = {"call_0_1", "call_0_2", "call_0_task_complete"}
    result_ids = {
        event.tool_call_id
        for event in trace.events
        if event.type == EVENT_TOOL_RESULT
    }
    assert result_ids.isdisjoint(first_step_call_ids)
    assert trace.observability.complete is False
    assert trace.observability.parse_error_count >= 1
    assert any("observation" in note for note in trace.observability.notes)


def test_terminus_final_result_keeps_last_agent_timestamp():
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=_terminus_session_artifacts(),
    )
    final = [event for event in trace.events if event.type == EVENT_FINAL_RESULT]
    assert len(final) == 1
    assert final[0].timestamp == "2026-07-15T10:00:01Z"
    assert "per_event_timestamps" not in trace.observability.unobservable_fields


def test_terminus_runner_error_keeps_type_and_marks_timestamp_unobservable():
    trace = trace_from_terminus_2(
        agent_stdout=(
            'TERMINUS2_RESULT {"status":"error","error_type":"CancelledError",'
            '"error":"","type":"terminus_2.result"}'
        ),
        model="deepseek/deepseek-v4-flash",
        session_artifacts=_terminus_session_artifacts(),
    )
    errors = [event for event in trace.events if event.type == EVENT_ERROR]
    assert len(errors) == 1
    assert errors[0].message == "CancelledError"
    assert errors[0].timestamp is None
    assert "per_event_timestamps" in trace.observability.unobservable_fields
    assert trace.observability.complete is True


def test_terminus_runner_error_fallback_keeps_type_when_detail_is_empty():
    trace = trace_from_terminus_2(
        agent_stdout=(
            'TERMINUS2_RESULT {"status":"error","error_type":"CancelledError",'
            '"error":"","type":"terminus_2.result"}'
        ),
        model="deepseek/deepseek-v4-flash",
        session_artifacts=None,
    )
    errors = [event for event in trace.events if event.type == EVENT_ERROR]
    assert len(errors) == 1
    assert errors[0].message == "CancelledError"
    assert trace.observability.complete is False


@pytest.mark.parametrize(
    ("trajectory", "note"),
    [
        ([], "top level was not an object"),
        ({}, "steps was missing or not an array"),
        ({"steps": 1}, "steps was missing or not an array"),
    ],
)
def test_terminus_schema_invalid_trajectory_degrades_explicitly(trajectory, note):
    artifacts = _terminus_session_artifacts()
    artifacts["files"][0]["content"] = json.dumps(trajectory)
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )
    assert trace.observability.source == "terminus_2_atif_trajectory"
    assert trace.observability.complete is False
    assert trace.observability.parse_error_count == 1
    assert any(note in value for value in trace.observability.notes)


def test_terminus_single_completion_request_is_not_final():
    trajectory = json.loads(TERMINUS_TRAJECTORY)
    trajectory["steps"] = trajectory["steps"][:1]
    artifacts = _terminus_session_artifacts()
    artifacts["files"][0]["content"] = json.dumps(trajectory)
    trace = trace_from_terminus_2(
        agent_stdout="",
        model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )
    assert trace.final_result is None
    assert trace.observability.complete is False
    assert any("runner result missing" in note for note in trace.observability.notes)


def test_terminus_completion_pending_survives_parser_feedback_step():
    trajectory = json.loads(TERMINUS_TRAJECTORY)
    first, second = trajectory["steps"]
    parser_retry = {
        "source": "agent",
        "timestamp": "2026-07-15T10:00:00.5Z",
        "message": "not valid parser output",
        "tool_calls": None,
        "observation": {
            "results": [
                {
                    "content": (
                        "Previous response had parsing errors:\nERROR: invalid JSON"
                    )
                }
            ]
        },
    }
    trajectory["steps"] = [first, parser_retry, second]
    artifacts = _terminus_session_artifacts()
    artifacts["files"][0]["content"] = json.dumps(trajectory)
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )
    assert trace.final_result == "Analysis: verified\nPlan: finish"
    assert trace.observability.complete is True


def test_terminus_result_fallback_preserves_usage_but_is_explicitly_incomplete():
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=None,
    )
    assert trace.usage is not None
    assert trace.usage["input_tokens"] == 120
    assert trace.usage["output_tokens"] == 15
    assert trace.final_result == "done"
    assert trace.observability.complete is False
    assert "tool_exit_code" in trace.observability.unobservable_fields


def test_terminus_trajectory_ignores_unrelated_session_bundle_truncation():
    artifacts = _terminus_session_artifacts()
    artifacts["truncated"] = True
    artifacts["files"].append(
        {
            "path": "/home/daytona/.terminus-2/sessions/current/terminus_2.pane",
            "content": "pane output",
            "truncated": True,
        }
    )
    trace = trace_from_terminus_2(
        agent_stdout=TERMINUS_STDOUT,
        model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )
    assert trace.observability.complete is True
    assert trace.observability.truncated is False


def test_grok_recovers_full_stream_from_session_log():
    trace = trace_from_grok(
        agent_stdout='{"text":"Listed files.","stopReason":"EndTurn"}',
        model="x-ai/grok-4",
        session_artifacts=_grok_session_artifacts(GROK_UPDATES),
    )
    types = [e.type for e in trace.events]
    assert types == [
        EVENT_REASONING,
        EVENT_TOOL_CALL,
        EVENT_TOOL_RESULT,
        EVENT_ASSISTANT_MESSAGE,
        EVENT_FINAL_RESULT,
    ]
    reasoning = next(e for e in trace.events if e.type == EVENT_REASONING)
    assert reasoning.text == "I should run ls."
    call = next(e for e in trace.events if e.type == EVENT_TOOL_CALL)
    result = next(e for e in trace.events if e.type == EVENT_TOOL_RESULT)
    assert call.tool_call_id == result.tool_call_id == "tc_1"
    assert call.arguments == {"command": "ls"}
    assert result.exit_code == 0
    assert result.output == "file1"
    assert trace.observability.source == SOURCE_GROK_SESSION_UPDATES
    assert trace.observability.complete is True
    assert "tool_exit_code" not in trace.observability.unobservable_fields
    assert trace.usage["input_tokens"] == 120


def test_grok_falls_back_to_final_object_when_session_missing():
    trace = trace_from_grok(
        agent_stdout='{"text":"the answer","stopReason":"EndTurn"}',
        model="x-ai/grok-4",
        session_artifacts=None,
    )
    assert trace.observability.source == SOURCE_GROK_FINAL_OBJECT
    assert trace.observability.complete is False
    assert trace.final_result == "the answer"
    for field_name in ("tool_calls", "tool_results", "reasoning", "usage"):
        assert field_name in trace.observability.unobservable_fields
    assert trace.observability.notes


def test_grok_error_object_fallback_records_error_event():
    trace = trace_from_grok(
        agent_stdout='{"type":"error","message":"Unauthorized (401)"}',
        model="x-ai/grok-4",
        session_artifacts=None,
    )
    assert [e.type for e in trace.events] == [EVENT_ERROR]
    assert "401" in (trace.events[0].message or "")


def test_grok_truncated_session_export_flagged_incomplete():
    trace = trace_from_grok(
        agent_stdout="{}",
        model="x-ai/grok-4",
        session_artifacts=_grok_session_artifacts(GROK_UPDATES, truncated=True),
    )
    assert trace.observability.truncated is True
    assert trace.observability.complete is False
    assert any("truncat" in note.lower() for note in trace.observability.notes)


def test_grok_parse_error_counted_not_fatal():
    updates = GROK_UPDATES + "\n{ this is not json"
    trace = trace_from_grok(
        agent_stdout="{}",
        model="x-ai/grok-4",
        session_artifacts=_grok_session_artifacts(updates),
    )
    assert trace.observability.parse_error_count == 1
    assert trace.observability.complete is False
    assert any(e.type == EVENT_TOOL_CALL for e in trace.events)


def test_grok_incomplete_run_marks_missing_turn_completed():
    cut_off = "\n".join(GROK_UPDATES.split("\n")[:-1])
    trace = trace_from_grok(
        agent_stdout="{}",
        model="x-ai/grok-4",
        session_artifacts=_grok_session_artifacts(cut_off),
    )
    assert trace.observability.complete is False
    assert any("turn_completed" in note for note in trace.observability.notes)


def test_grok_retry_state_failure_becomes_error_event():
    updates = json.dumps(
        _grok_update(
            {
                "sessionUpdate": "retry_state",
                "type": "failed",
                "error_type": "auth",
                "message": "Unauthorized (401)",
            },
            ts_ms=1_783_860_949_000,
        )
    )
    trace = trace_from_grok(
        agent_stdout="{}",
        model="x-ai/grok-4",
        session_artifacts=_grok_session_artifacts(updates),
    )
    error = next(e for e in trace.events if e.type == EVENT_ERROR)
    assert error.status == "auth"
    assert "401" in (error.message or "")


def test_claude_stream_orders_reasoning_call_result_final():
    trace = trace_from_claude_stream(agent_stdout=CLAUDE_STREAM, model="anthropic/claude")
    types = [e.type for e in trace.events]
    assert types == [
        EVENT_REASONING,
        EVENT_ASSISTANT_MESSAGE,
        EVENT_TOOL_CALL,
        EVENT_TOOL_RESULT,
        EVENT_FINAL_RESULT,
    ]
    call = next(e for e in trace.events if e.type == EVENT_TOOL_CALL)
    result = next(e for e in trace.events if e.type == EVENT_TOOL_RESULT)
    assert call.tool_call_id == result.tool_call_id == "tu_1"


def test_codex_started_completed_pair_yields_single_call():
    trace = trace_from_codex_events(agent_stdout=CODEX_STREAM, model="openai/codex")
    calls = [e for e in trace.events if e.type == EVENT_TOOL_CALL]
    results = [e for e in trace.events if e.type == EVENT_TOOL_RESULT]
    assert len(calls) == 1
    assert len(results) == 1
    assert calls[0].tool_call_id == results[0].tool_call_id == "i1"
    assert results[0].exit_code == 0
    assert trace.final_result == "Listed files."


def test_claude_error_result_is_not_misreported_as_final_success():
    stream = (
        '{"type":"result","subtype":"error_during_execution",'
        '"is_error":true,"result":"agent failed"}\n'
    )
    trace = trace_from_claude_stream(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    )
    assert trace.final_result is None
    assert [event.type for event in trace.events] == [EVENT_ERROR]


def test_codex_partial_message_is_marked_incomplete_without_terminal_event():
    stream = '{"type":"item.completed","item":{"type":"agent_message","text":"partial"}}'
    trace = trace_from_codex_events(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    )
    assert trace.final_result == "partial"
    assert trace.observability.complete is False
    assert any("terminal" in note for note in trace.observability.notes)


def test_field_truncation_is_flagged():
    big = "x" * 40000
    stream = (
        '{"type":"assistant","message":{"content":['
        '{"type":"tool_use","id":"t","name":"Bash","input":{}}]}}\n'
        '{"type":"user","message":{"content":[{"type":"tool_result",'
        '"tool_use_id":"t","content":[{"type":"text","text":"' + big + '"}]}]}}\n'
    )
    trace = trace_from_claude_stream(agent_stdout=stream, model="anthropic/claude")
    assert trace.observability.truncated is True
    result = next(e for e in trace.events if e.type == EVENT_TOOL_RESULT)
    assert "truncated" in (result.output or "")


def test_codex_policy_event_truncation_is_reflected_in_observability():
    policy = [{"event_type": "policy_block", "command": "x"}] * 257
    trace = trace_from_codex_events(
        agent_stdout=CODEX_STREAM,
        model="deepseek/deepseek-v4-flash",
        policy_events=policy,
    )
    assert trace.observability.truncated is True


def test_nested_policy_field_truncation_is_reflected_in_observability():
    trace = trace_from_codex_events(
        agent_stdout=CODEX_STREAM,
        model="deepseek/deepseek-v4-flash",
        policy_events=[
            {
                "event_type": "policy_block",
                "details": {"model_controlled_output": "x" * 40000},
            }
        ],
    ).to_mapping()
    assert "[truncated " in json.dumps(trace["policy_events"])
    assert trace["observability"]["truncated"] is True


@pytest.mark.parametrize("harness", ["claude_code", "codex", "grok", "terminus_2"])
def test_trace_is_json_serializable(harness):
    trace = _all_traces()[harness]
    assert json.loads(json.dumps(trace)) == trace


def test_policy_events_are_present_and_redacted_in_every_trace():
    policy = [{"event_type": "policy_block", "command": "curl API_KEY=sk-or-v1-abcdefghijklmnop"}]
    builders = (
        trace_from_claude_stream(
            agent_stdout=CLAUDE_STREAM, model="anthropic/claude", policy_events=policy
        ),
        trace_from_codex_events(
            agent_stdout=CODEX_STREAM, model="openai/codex", policy_events=policy
        ),
        trace_from_grok(
            agent_stdout='{"text":"Listed files."}',
            model="x-ai/grok-4",
            session_artifacts=_grok_session_artifacts(GROK_UPDATES),
            policy_events=policy,
        ),
        trace_from_terminus_2(
            agent_stdout=TERMINUS_STDOUT,
            model="deepseek/deepseek-v4-flash",
            session_artifacts=_terminus_session_artifacts(),
            policy_events=policy,
        ),
    )
    for trace in builders:
        mapping = trace.to_mapping()
        assert mapping["policy_events"][0]["event_type"] == "policy_block"
        assert mapping["observability"]["redaction_applied"] is True
        assert "sk-or-v1-abcdefghijklmnop" not in json.dumps(mapping)


def test_event_payloads_are_bounded_redacted_and_linked_to_policy_evidence():
    command = "curl API_KEY=sk-or-v1-abcdefghijklmnop " + ("x" * 20000)
    stream = (
        '{"type":"assistant","message":{"content":[{"type":"tool_use",'
        '"id":"t","name":"Bash","input":{"command":'
        + json.dumps(command)
        + '}}]}}\n'
        '{"type":"result","subtype":"success","result":"done"}\n'
    )
    trace = trace_from_claude_stream(
        agent_stdout=stream,
        model="deepseek/deepseek-v4-flash",
        policy_events=[{"event_type": "policy_block", "command": "curl"}],
    ).to_mapping()
    call = next(event for event in trace["events"] if event["type"] == EVENT_TOOL_CALL)
    assert len(call["arguments"]["command"]) < 17000
    assert "sk-or-v1-abcdefghijklmnop" not in json.dumps(trace)
    assert call["policy_event_refs"] == ["policy-0000"]
    assert trace["policy_events"][0]["trace_event_seqs"] == [call["seq"]]
    assert trace["observability"]["truncated"] is True


def test_cost_source_is_only_emitted_when_cost_is_available():
    priced = trace_from_claude_stream(
        agent_stdout=CLAUDE_STREAM, model="deepseek/deepseek-v4-flash"
    ).to_mapping()["usage"]
    assert priced["total_cost"] is not None
    assert priced["cost_source"] == "pricing_table"

    unpriced = trace_from_grok(
        agent_stdout='{"text":"done"}',
        model="unknown/model",
        session_artifacts=_grok_session_artifacts(GROK_UPDATES),
    ).to_mapping()["usage"]
    assert unpriced["total_cost"] is None
    assert "cost_source" not in unpriced


def test_policy_normalization_does_not_claim_redaction_for_clean_evidence():
    trace = trace_from_claude_stream(
        agent_stdout=CLAUDE_STREAM,
        model="deepseek/deepseek-v4-flash",
        policy_events=[{"event_type": "policy_block", "command": "sudo"}],
    ).to_mapping()
    assert trace["observability"]["redaction_applied"] is False


def test_structured_credentials_are_key_aware_redacted_from_durable_trace():
    raw_values = {
        "api_key": "plain-secret-value",
        "Authorization": "Bearer super-secret-credential",
        "Proxy-Authorization": "Basic c3VwZXItc2VjcmV0",
        "password": "correct-horse-battery-staple",
        "x-api-key": "provider-key-value",
        "provider_note": "AKIA1234567890ABCDEF",
    }
    stream = (
        '{"type":"assistant","message":{"content":[{"type":"tool_use",'
        '"id":"t","name":"Bash","input":'
        + json.dumps({"headers": raw_values})
        + '}]}}\n'
        '{"type":"result","subtype":"success","result":"done"}\n'
    )
    trace = trace_from_claude_stream(
        agent_stdout=stream,
        model="deepseek/deepseek-v4-flash",
        policy_events=[{"event_type": "policy_block", "request": {"headers": raw_values}}],
    ).to_mapping()
    serialized = json.dumps(trace)
    assert "[REDACTED]" in serialized
    assert trace["observability"]["redaction_applied"] is True
    for raw in raw_values.values():
        assert raw not in serialized


def test_structured_credentials_redact_camel_case_without_broad_key_matches():
    secrets = {
        "clientSecret": "raw-client-secret",
        "accessToken": "raw-access-token",
        "refreshToken": "raw-refresh-token",
        "privateKey": "raw-private-key",
        "dbPassword": "raw-db-password",
    }
    benign = {
        "monkey": "keep-monkey",
        "keyboard": "keep-keyboard",
        "tokenizer": "keep-tokenizer",
        "publicKey": "keep-public-key",
    }
    trace = trace_from_claude_stream(
        agent_stdout=CLAUDE_STREAM,
        model="deepseek/deepseek-v4-flash",
        policy_events=[
            {
                "event_type": "policy_block",
                "details": {**secrets, **benign},
            }
        ],
    ).to_mapping()
    serialized = json.dumps(trace)
    for raw in secrets.values():
        assert raw not in serialized
    for raw in benign.values():
        assert raw in serialized
    assert trace["observability"]["redaction_applied"] is True


def test_all_trace_event_string_fields_are_bounded_and_redacted():
    oversized = "x" * 20000
    event = TraceEvent(
        seq=0,
        type=EVENT_TOOL_CALL,
        timestamp=oversized,
        text=oversized,
        tool_call_id="TOKEN=raw-call-secret",
        tool_name=oversized,
        arguments={"api_key": "raw-argument-secret"},
        output=oversized,
        status=oversized,
        stop_reason="Authorization: Bearer raw-stop-secret",
        message=oversized,
        policy_event_refs=[oversized, "TOKEN=raw-policy-secret"],
    ).to_mapping()
    serialized = json.dumps(event)
    assert "raw-call-secret" not in serialized
    assert "raw-argument-secret" not in serialized
    assert "raw-stop-secret" not in serialized
    assert "raw-policy-secret" not in serialized
    for key in (
        "timestamp",
        "text",
        "tool_name",
        "output",
        "status",
        "message",
    ):
        assert len(event[key]) < 17000


def test_harness_event_scalar_sanitization_updates_observability():
    stream = (
        '{"type":"assistant","timestamp":"TOKEN=raw-timestamp-secret",'
        '"message":{"content":[{"type":"tool_use",'
        '"id":"TOKEN=raw-id-secret","name":"'
        + ("x" * 20000)
        + '","input":{}}]}}\n'
        '{"type":"result","subtype":"success","result":"done"}\n'
    )
    trace = trace_from_claude_stream(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    ).to_mapping()
    serialized = json.dumps(trace)
    assert "raw-timestamp-secret" not in serialized
    assert "raw-id-secret" not in serialized
    assert trace["observability"]["redaction_applied"] is True
    assert trace["observability"]["truncated"] is True


@pytest.mark.parametrize("terminal_type", ["turn.failed", "run.failed"])
def test_codex_failed_terminal_emits_error_and_clears_progress(terminal_type):
    stream = (
        '{"type":"item.completed","item":{"type":"agent_message",'
        '"text":"working..."}}\n'
        + json.dumps(
            {
                "type": terminal_type,
                "error": {"message": "context length exceeded"},
            }
        )
        + "\n"
    )
    trace = trace_from_codex_events(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    )
    assert trace.final_result is None
    assert trace.observability.complete is True
    assert trace.events[-1].type == EVENT_ERROR
    assert trace.events[-1].message == "context length exceeded"


def test_claude_failed_terminal_clears_progress_even_with_empty_error_text():
    stream = (
        '{"type":"assistant","message":{"content":['
        '{"type":"text","text":"working..."}]}}\n'
        '{"type":"result","subtype":"error_during_execution",'
        '"is_error":true,"result":""}\n'
    )
    trace = trace_from_claude_stream(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    )
    assert trace.final_result is None
    assert trace.events[-1].type == EVENT_ERROR
    assert trace.events[-1].message == ""


def test_grok_failed_terminal_clears_progress_even_with_empty_error_text():
    updates = "\n".join(
        json.dumps(line)
        for line in [
            _grok_update(
                {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": "working..."},
                },
                ts_ms=1_783_860_953_000,
            ),
            _grok_update(
                {
                    "sessionUpdate": "turn_completed",
                    "stop_reason": "error",
                    "agent_result": "",
                },
                ts_ms=1_783_860_954_000,
            ),
        ]
    )
    trace = trace_from_grok(
        agent_stdout="{}",
        model="deepseek/deepseek-v4-flash",
        session_artifacts=_grok_session_artifacts(updates),
    )
    assert trace.final_result is None
    assert trace.events[-1].type == EVENT_ERROR
    assert trace.events[-1].message == ""


def test_grok_incremental_and_terminal_tool_updates_emit_one_final_result():
    updates = "\n".join(
        json.dumps(line)
        for line in [
            _grok_update(
                {
                    "sessionUpdate": "tool_call",
                    "toolCallId": "tc_incremental",
                    "title": "run_terminal_cmd",
                    "status": "pending",
                    "rawInput": {"command": "failing-command"},
                },
                ts_ms=1_783_860_951_000,
            ),
            _grok_update(
                {
                    "sessionUpdate": "tool_call_update",
                    "toolCallId": "tc_incremental",
                    "status": "in_progress",
                    "content": [
                        {
                            "type": "content",
                            "content": {"type": "text", "text": "partial output"},
                        }
                    ],
                },
                ts_ms=1_783_860_952_000,
            ),
            _grok_update(
                {
                    "sessionUpdate": "tool_call_update",
                    "toolCallId": "tc_incremental",
                    "status": "failed",
                    "content": [
                        {
                            "type": "content",
                            "content": {"type": "text", "text": "final failure"},
                        }
                    ],
                    "rawOutput": {"exit_code": 2},
                },
                ts_ms=1_783_860_953_000,
            ),
            _grok_update(
                {
                    "sessionUpdate": "turn_completed",
                    "stop_reason": "end_turn",
                    "agent_result": "done",
                },
                ts_ms=1_783_860_954_000,
            ),
        ]
    )
    trace = trace_from_grok(
        agent_stdout="{}",
        model="deepseek/deepseek-v4-flash",
        session_artifacts=_grok_session_artifacts(updates),
    )
    results = [event for event in trace.events if event.type == EVENT_TOOL_RESULT]
    assert len(results) == 1
    assert results[0].tool_call_id == "tc_incremental"
    assert results[0].output == "final failure"
    assert results[0].status == "failed"
    assert results[0].exit_code == 2
    assert results[0].is_error is True


def test_codex_malformed_json_marks_trace_lossy_and_incomplete():
    stream = (
        '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
        "{ malformed json\n"
        '{"type":"turn.completed"}\n'
    )
    trace = trace_from_codex_events(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    )
    assert trace.observability.parse_error_count == 1
    assert trace.observability.truncated is True
    assert trace.observability.complete is False


def test_cache_tokens_are_separate_from_total_tokens():
    stream = (
        '{"type":"assistant","message":{"content":[]}}\n'
        '{"type":"result","subtype":"success","result":"done",'
        '"usage":{"input_tokens":10,"output_tokens":2,'
        '"cache_read_input_tokens":4,"cache_creation_input_tokens":1}}\n'
    )
    usage = trace_from_claude_stream(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    ).usage
    assert usage["input_tokens"] == 15
    assert usage["output_tokens"] == 2
    assert usage["cache_read_tokens"] == 4
    assert usage["cache_write_tokens"] == 1
    assert usage["total_tokens"] == 17


def test_claude_missing_event_timestamps_are_explicitly_unobservable():
    trace = trace_from_claude_stream(
        agent_stdout=CLAUDE_STREAM, model="deepseek/deepseek-v4-flash"
    )
    assert "per_event_timestamps" in trace.observability.unobservable_fields


def test_codex_native_usage_has_same_pricing_fallback_as_other_harnesses():
    stream = (
        '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
        '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}\n'
    )
    usage = trace_from_codex_events(
        agent_stdout=stream, model="deepseek/deepseek-v4-flash"
    ).usage
    assert usage["total_cost"] is not None
    assert usage["cost_source"] == "pricing_table"


def test_cached_usage_and_fallback_cost_are_identical_across_harnesses(monkeypatch):
    pricing_inputs: list[tuple[int, int, int, int]] = []

    def fake_openrouter_cost(
        _model,
        *,
        input_tokens,
        output_tokens,
        cache_read_tokens=0,
        cache_write_tokens=0,
    ):
        pricing_inputs.append(
            (input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
        )
        return (
            input_tokens
            + (output_tokens * 10)
            + (cache_read_tokens * 0.25)
            + (cache_write_tokens * 2)
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.pricing.openrouter_cost",
        fake_openrouter_cost,
    )
    claude = trace_from_claude_stream(
        agent_stdout=(
            '{"type":"result","subtype":"success","result":"done",'
            '"usage":{"input_tokens":6,"output_tokens":2,'
            '"cache_read_input_tokens":4}}\n'
        ),
        model="test/model",
    ).usage
    codex = trace_from_codex_events(
        agent_stdout=(
            '{"type":"item.completed","item":{"type":"agent_message",'
            '"text":"done"}}\n'
            '{"type":"turn.completed","usage":{"input_tokens":10,'
            '"output_tokens":2,"cached_input_tokens":4}}\n'
        ),
        model="test/model",
    ).usage
    grok_updates = json.dumps(
        _grok_update(
            {
                "sessionUpdate": "turn_completed",
                "stop_reason": "end_turn",
                "agent_result": "done",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cached_input_tokens": 4,
                },
            },
            ts_ms=1_783_860_954_000,
        )
    )
    grok = trace_from_grok(
        agent_stdout="{}",
        model="test/model",
        session_artifacts=_grok_session_artifacts(grok_updates),
    ).usage

    for usage in (claude, codex, grok):
        assert usage == {
            "input_tokens": 10,
            "output_tokens": 2,
            "cache_read_tokens": 4,
            "cache_write_tokens": 0,
            "total_tokens": 12,
            "total_cost": 27.0,
            "cost_source": "pricing_table",
        }
    assert pricing_inputs == [(6, 2, 4, 0)] * 3
