"""Canonical harness-neutral execution trace.

Every registered harness emits its run activity in a different native format:

* Claude Code streams newline-delimited ``stream-json`` on stdout.
* Codex streams ``exec --json`` events on stdout.
* Grok Build CLI writes an ACP ``session/update`` stream to
  ``$GROK_HOME/sessions/<cwd>/<session-id>/updates.jsonl`` — its stdout
  ``--output-format json`` object is only the final message, so the full
  event stream (reasoning, tool calls, tool results, usage) is *only*
  observable through the session log.

To make every harness analyzable with one schema for later taxonomy work, this
module defines a single ``CanonicalTrace`` shape and one builder per harness
that normalizes the native format into it. The builders live here (not on the
adapters) so the schema and its semantics are defined in exactly one place; the
adapters expose them through ``HarnessAdapter.canonical_trace``.

Design contract (identical across harnesses):

* ``events`` is an ordered list; each event has a monotonically increasing
  ``seq`` and a ``timestamp`` (ISO-8601, or ``null`` when the harness cannot
  observe it — never silently dropped).
* Tool calls and their results correlate through ``tool_call_id``.
* ``observability`` records the capture source and every place fidelity was
  lost — parse errors, truncation, redaction, and fields the harness cannot
  expose (``unobservable_fields``) — so an unavailable field is always
  explicit rather than mistaken for absent behavior.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CANONICAL_TRACE_SCHEMA_VERSION = "1"

EVENT_ASSISTANT_MESSAGE = "assistant_message"
EVENT_REASONING = "reasoning"
EVENT_TOOL_CALL = "tool_call"
EVENT_TOOL_RESULT = "tool_result"
EVENT_ERROR = "error"
EVENT_FINAL_RESULT = "final_result"

SOURCE_CLAUDE_STREAM_JSON = "claude_stream_json"
SOURCE_CODEX_EXEC_JSON = "codex_exec_json"
SOURCE_GROK_SESSION_UPDATES = "grok_session_updates_jsonl"
SOURCE_GROK_FINAL_OBJECT = "grok_final_object"

_FIELD_LIMIT = 16000
_COLLECTION_LIMIT = 256

_TERMINAL_TOOL_STATUSES = {"completed", "failed", "error", "cancelled", "canceled"}


def _bounded(text: str | None) -> tuple[str | None, bool]:
    """Cap a field to ``_FIELD_LIMIT`` chars; return (value, truncated)."""

    if text is None:
        return None, False
    text = _redact_secret_text(text)
    if len(text) <= _FIELD_LIMIT:
        return text, False
    return text[:_FIELD_LIMIT] + f"\n... [truncated {len(text) - _FIELD_LIMIT} chars]", True


def _credential_like_key(value: str) -> bool:
    """Whether a structured field name conventionally carries a secret."""

    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    normalized = re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")
    exact = {
        "authorization",
        "proxy_authorization",
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "key",
        "api_key",
        "apikey",
        "access_key",
        "access_key_id",
        "secret_access_key",
        "private_key",
        "auth_token",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "credential",
        "credentials",
        "cookie",
        "set_cookie",
    }
    secret_suffixes = (
        "_password",
        "_passwd",
        "_passphrase",
        "_secret",
        "_token",
        "_api_key",
        "_apikey",
        "_access_key",
        "_private_key",
        "_credential",
        "_credentials",
    )
    return normalized in exact or normalized.endswith(secret_suffixes)


def _sanitize_value(value: Any) -> Any:
    """Recursively redact and bound JSON-like native payloads."""

    if isinstance(value, str):
        return _bounded(value)[0]
    if isinstance(value, dict):
        items = list(value.items())
        sanitized: dict[str, Any] = {}
        for key, item in items[:_COLLECTION_LIMIT]:
            raw_key = str(key)
            clean_key = _bounded(raw_key)[0] or ""
            sanitized[clean_key] = (
                "[REDACTED]"
                if _credential_like_key(raw_key)
                else _sanitize_value(item)
            )
        if len(items) > _COLLECTION_LIMIT:
            sanitized["__truncated__"] = f"[truncated {len(items) - _COLLECTION_LIMIT} mapping items]"
        return sanitized
    if isinstance(value, (list, tuple)):
        items = list(value)
        sanitized = [_sanitize_value(item) for item in items[:_COLLECTION_LIMIT]]
        if len(items) > _COLLECTION_LIMIT:
            sanitized.append(
                f"[truncated {len(items) - _COLLECTION_LIMIT} collection items]"
            )
        return sanitized
    return value


def _trace_has_redaction(events: list["TraceEvent"]) -> bool:
    return any(
        "[REDACTED]" in json.dumps(event.to_mapping(), ensure_ascii=False)
        for event in events
    )


def _trace_has_truncation(events: list["TraceEvent"]) -> bool:
    return any(
        "[truncated " in json.dumps(event.to_mapping(), ensure_ascii=False)
        for event in events
    )


@dataclass
class TraceEvent:
    """One ordered event in a canonical trace.

    ``seq`` and ``timestamp`` are always serialized (``timestamp`` as ``null``
    when unobservable). Type-specific fields are serialized only when set.
    """

    seq: int
    type: str
    timestamp: str | None = None
    text: str | None = None
    tool_call_id: str | None = None
    tool_name: str | None = None
    arguments: Any | None = None
    output: str | None = None
    status: str | None = None
    exit_code: int | None = None
    is_error: bool | None = None
    stop_reason: str | None = None
    message: str | None = None
    policy_event_refs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for field_name in (
            "timestamp",
            "text",
            "tool_call_id",
            "tool_name",
            "output",
            "status",
            "stop_reason",
            "message",
        ):
            value = getattr(self, field_name)
            if value is not None:
                setattr(self, field_name, _bounded(str(value))[0])
        self.arguments = _sanitize_value(self.arguments)
        sanitized_refs = _sanitize_value(self.policy_event_refs)
        self.policy_event_refs = (
            [str(value) for value in sanitized_refs]
            if isinstance(sanitized_refs, list)
            else []
        )

    def to_mapping(self) -> dict[str, Any]:
        mapping: dict[str, Any] = {
            "seq": self.seq,
            "type": self.type,
            "timestamp": self.timestamp,
        }
        for key in (
            "text",
            "tool_call_id",
            "tool_name",
            "arguments",
            "output",
            "status",
            "exit_code",
            "is_error",
            "stop_reason",
            "message",
            "policy_event_refs",
        ):
            value = getattr(self, key)
            if value is not None:
                mapping[key] = value
        return mapping


@dataclass
class TraceObservability:
    """Completeness / fidelity metadata for a canonical trace."""

    source: str
    complete: bool
    truncated: bool = False
    parse_error_count: int = 0
    redaction_applied: bool = False
    unobservable_fields: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "complete": self.complete,
            "truncated": self.truncated,
            "parse_error_count": self.parse_error_count,
            "redaction_applied": self.redaction_applied,
            "unobservable_fields": list(self.unobservable_fields),
            "notes": list(self.notes),
        }


@dataclass
class CanonicalTrace:
    """Harness-neutral execution trace, ready for JSON export."""

    harness: str
    model: str
    events: list[TraceEvent]
    observability: TraceObservability
    usage: dict[str, Any] | None = None
    final_result: str | None = None
    policy_events: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = CANONICAL_TRACE_SCHEMA_VERSION

    def to_mapping(self) -> dict[str, Any]:
        tool_calls = sum(1 for e in self.events if e.type == EVENT_TOOL_CALL)
        assistant_messages = sum(
            1 for e in self.events if e.type == EVENT_ASSISTANT_MESSAGE
        )
        return {
            "schema_version": self.schema_version,
            "harness": self.harness,
            "model": self.model,
            "event_count": len(self.events),
            "assistant_message_count": assistant_messages,
            "tool_call_count": tool_calls,
            "final_result": self.final_result,
            "usage": self.usage,
            "observability": self.observability.to_mapping(),
            "policy_events": self.policy_events,
            "events": [event.to_mapping() for event in self.events],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_mapping(), indent=indent, ensure_ascii=False)


def _iso_from_epoch_ms(value: Any) -> str | None:
    try:
        ms = float(value)
    except (TypeError, ValueError):
        return None
    return (
        datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _iso_from_epoch_s(value: Any) -> str | None:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return (
        datetime.fromtimestamp(seconds, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


class _SeqCounter:
    def __init__(self) -> None:
        self._value = -1

    def next(self) -> int:
        self._value += 1
        return self._value


def trace_from_claude_stream(
    *,
    agent_stdout: str,
    model: str,
    pricing_model: str | None = None,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    from boundarybench.terminalbench.daytona_transcript import (
        _assistant_blocks,
        _message_dict,
        _sum_nonzero_turn_usage,
        _tool_result_text,
        _usage_from_event,
        claude_stream_diagnostics,
        parse_claude_stream,
    )

    events_raw = parse_claude_stream(agent_stdout)
    seq = _SeqCounter()
    events: list[TraceEvent] = []
    truncated = False
    usage_counts: dict[str, int] = {}
    final_text: str | None = None

    def _ts(event: dict[str, Any]) -> str | None:
        raw = event.get("timestamp")
        return raw if isinstance(raw, str) and raw.strip() else None

    for event in events_raw:
        etype = event.get("type")
        timestamp = _ts(event)
        if etype == "assistant":
            for block in _assistant_blocks(event):
                btype = block.get("type")
                if btype == "thinking" and block.get("thinking"):
                    text, was_trunc = _bounded(str(block["thinking"]))
                    truncated = truncated or was_trunc
                    events.append(
                        TraceEvent(seq.next(), EVENT_REASONING, timestamp, text=text)
                    )
                elif btype == "text" and block.get("text"):
                    text, was_trunc = _bounded(str(block["text"]))
                    truncated = truncated or was_trunc
                    final_text = str(block["text"])
                    events.append(
                        TraceEvent(
                            seq.next(), EVENT_ASSISTANT_MESSAGE, timestamp, text=text
                        )
                    )
                elif btype == "tool_use":
                    events.append(
                        TraceEvent(
                            seq.next(),
                            EVENT_TOOL_CALL,
                            timestamp,
                            tool_call_id=str(block.get("id", "")) or None,
                            tool_name=str(block.get("name", "")) or None,
                            arguments=block.get("input") or {},
                        )
                    )
        elif etype == "user":
            for block in _message_dict(event).get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                output, was_trunc = _bounded(_tool_result_text(block.get("content")))
                truncated = truncated or was_trunc
                exit_code = block.get("exit_code")
                events.append(
                    TraceEvent(
                        seq.next(),
                        EVENT_TOOL_RESULT,
                        timestamp,
                        tool_call_id=str(block.get("tool_use_id", "")) or None,
                        output=output,
                        is_error=bool(block["is_error"])
                        if "is_error" in block
                        else None,
                        status="failed" if block.get("is_error") else "completed",
                        exit_code=int(exit_code)
                        if isinstance(exit_code, (int, str))
                        and str(exit_code).lstrip("-").isdigit()
                        else None,
                    )
                )
        elif etype == "result":
            usage_counts = _usage_from_event(event)
            is_error = bool(event.get("is_error")) or str(
                event.get("subtype") or ""
            ).lower().startswith("error")
            result_text = str(event.get("result") or "")
            if is_error:
                final_text = None
            if is_error or result_text:
                if not is_error:
                    final_text = result_text
                text, was_trunc = _bounded(result_text)
                truncated = truncated or was_trunc
                events.append(
                    TraceEvent(
                        seq.next(),
                        EVENT_ERROR if is_error else EVENT_FINAL_RESULT,
                        timestamp,
                        text=None if is_error else text,
                        message=text if is_error else None,
                        is_error=is_error if is_error else None,
                        stop_reason=str(event.get("subtype") or "") or None,
                    )
                )

    if not any(usage_counts.values()):
        usage_counts = _sum_nonzero_turn_usage(events_raw)
    usage = _usage_mapping(
        usage_counts,
        model=pricing_model or model,
        input_includes_cache=False,
    )

    diagnostics = claude_stream_diagnostics(agent_stdout)
    parse_errors = int(diagnostics.get("agent_stdout_parse_error_count") or 0)
    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    truncated = truncated or _trace_has_truncation(events) or bool(
        final_text and len(final_text) > _FIELD_LIMIT
    ) or _policy_events_truncated(normalized_policy_events)
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
        source=SOURCE_CLAUDE_STREAM_JSON,
        complete=bool(diagnostics.get("agent_stdout_result_event_present"))
        and parse_errors == 0,
        truncated=truncated or bool(diagnostics.get("agent_stdout_truncated_or_malformed")),
        parse_error_count=parse_errors,
        redaction_applied=(
            _policy_events_changed(policy_events)
            or _trace_has_redaction(events)
        ),
        unobservable_fields=unobservable,
    )
    if not diagnostics.get("agent_stdout_result_event_present"):
        observability.notes.append("no result event in stream (run cut off)")
    return CanonicalTrace(
        harness="claude_code",
        model=model,
        events=events,
        observability=observability,
        usage=usage,
        final_result=_bounded(final_text)[0],
        policy_events=normalized_policy_events,
    )


def trace_from_codex_events(
    *,
    agent_stdout: str,
    model: str,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    from boundarybench.harness.codex import (
        _AGENT_MESSAGE_TYPES,
        _event_container,
        _event_text,
        _event_type,
        _parse_codex_events,
        codex_stream_diagnostics,
    )

    events_raw = _parse_codex_events(agent_stdout)
    seq = _SeqCounter()
    events: list[TraceEvent] = []
    truncated = False
    final_text: str | None = None
    usage: dict[str, Any] | None = None
    saw_timestamp = False
    saw_terminal_event = False
    terminal_failed = False
    failed_terminal_types = {
        "turn_failed",
        "turn.failed",
        "run_failed",
        "run.failed",
    }
    emitted_calls: set[str] = set()

    for event in events_raw:
        container = _event_container(event)
        etype = _event_type(event)
        if etype in {
            "turn_completed",
            "turn.completed",
            "turn_failed",
            "turn.failed",
            "run_completed",
            "run.completed",
            "run_failed",
            "run.failed",
        }:
            saw_terminal_event = True
        timestamp = None
        raw_ts = event.get("timestamp") or container.get("timestamp")
        if isinstance(raw_ts, str) and raw_ts.strip():
            timestamp = raw_ts.strip()
            saw_timestamp = True

        if etype in _AGENT_MESSAGE_TYPES:
            text = _event_text(event)
            if text:
                bounded, was_trunc = _bounded(text)
                truncated = truncated or was_trunc
                final_text = text
                events.append(
                    TraceEvent(
                        seq.next(), EVENT_ASSISTANT_MESSAGE, timestamp, text=bounded
                    )
                )
        elif etype in {"agent_reasoning", "reasoning"}:
            text = _event_text(event)
            if text:
                bounded, was_trunc = _bounded(text)
                truncated = truncated or was_trunc
                events.append(
                    TraceEvent(seq.next(), EVENT_REASONING, timestamp, text=bounded)
                )
        elif etype == "command_execution" or etype == "exec_command" or etype.endswith(
            "command_begin"
        ) or etype.endswith("command_end"):
            _append_codex_command(
                event, container, etype, seq, events, timestamp, emitted_calls
            )
            if _codex_command_truncated(container):
                truncated = True
        elif etype in failed_terminal_types:
            terminal_failed = True
            final_text = None
            events.append(
                TraceEvent(
                    seq.next(),
                    EVENT_ERROR,
                    timestamp,
                    message=_codex_terminal_error_message(event, container),
                )
            )
            parsed = _codex_usage(container, model=model)
            if parsed is not None:
                usage = parsed
        elif etype == "error":
            text = _event_text(event) or str(container.get("message") or "")
            events.append(
                TraceEvent(seq.next(), EVENT_ERROR, timestamp, message=text or None)
            )
        else:
            parsed = _codex_usage(container, model=model)
            if parsed is not None:
                usage = parsed

    unobservable: list[str] = []
    if not saw_timestamp:
        unobservable.append("per_event_timestamps")
    if usage is None:
        unobservable.append("usage")

    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    diagnostics = codex_stream_diagnostics(agent_stdout)
    parse_errors = int(diagnostics.get("agent_stdout_parse_error_count") or 0)
    truncated = truncated or _trace_has_truncation(events) or bool(
        final_text and len(final_text) > _FIELD_LIMIT
    ) or _policy_events_truncated(normalized_policy_events) or bool(
        diagnostics.get("agent_stdout_truncated_or_malformed")
    )
    observability = TraceObservability(
        source=SOURCE_CODEX_EXEC_JSON,
        complete=saw_terminal_event and parse_errors == 0,
        truncated=truncated,
        parse_error_count=parse_errors,
        unobservable_fields=unobservable,
    )
    if terminal_failed:
        observability.notes.append(
            "terminal failure captured; final_result intentionally absent"
        )
    elif final_text is None:
        observability.notes.append("no assistant message observed in codex stream")
    elif not saw_terminal_event:
        observability.notes.append("no terminal turn event observed in codex stream")
    observability.redaction_applied = (
        _policy_events_changed(policy_events) or _trace_has_redaction(events)
    )
    return CanonicalTrace(
        harness="codex",
        model=model,
        events=events,
        observability=observability,
        usage=usage,
        final_result=_bounded(final_text)[0],
        policy_events=normalized_policy_events,
    )


def _append_codex_command(
    event: dict[str, Any],
    container: dict[str, Any],
    etype: str,
    seq: _SeqCounter,
    events: list[TraceEvent],
    timestamp: str | None,
    emitted_calls: set[str],
) -> None:
    """Emit a tool_call + (on completion) tool_result for a Codex command.

    Codex reports each command as an ``item.started`` + ``item.completed``
    pair (and, on older builds, a ``*_begin`` / ``*_end`` pair). The start
    emits the tool_call; the completion emits only the correlated tool_result
    — unless the call was never seen as a start (a lone completed item), in
    which case both are emitted so the call is not dropped.
    """

    call_id = str(
        container.get("id")
        or container.get("call_id")
        or event.get("id")
        or ""
    ) or None
    is_completion = (
        event.get("type") == "item.completed"
        or container.get("status") in {"completed", "failed"}
        or etype.endswith("command_end")
    )
    command = container.get("command") or container.get("aggregated_command")
    if not is_completion:
        if call_id:
            emitted_calls.add(call_id)
        events.append(
            TraceEvent(
                seq.next(),
                EVENT_TOOL_CALL,
                timestamp,
                tool_call_id=call_id,
                tool_name="run_terminal_cmd",
                arguments={"command": command} if command is not None else {},
                status="in_progress",
            )
        )
        return
    if call_id is not None and call_id not in emitted_calls:
        events.append(
            TraceEvent(
                seq.next(),
                EVENT_TOOL_CALL,
                timestamp,
                tool_call_id=call_id,
                tool_name="run_terminal_cmd",
                arguments={"command": command} if command is not None else {},
            )
        )
    output_raw = (
        container.get("aggregated_output")
        or container.get("output")
        or container.get("stdout")
        or ""
    )
    output, _ = _bounded(str(output_raw))
    exit_code = container.get("exit_code")
    status = container.get("status") or (
        "completed" if str(exit_code) in {"0", "None"} else "failed"
    )
    events.append(
        TraceEvent(
            seq.next(),
            EVENT_TOOL_RESULT,
            timestamp,
            tool_call_id=call_id,
            output=output,
            status=str(status),
            exit_code=int(exit_code)
            if isinstance(exit_code, int)
            or (isinstance(exit_code, str) and exit_code.lstrip("-").isdigit())
            else None,
        )
    )


def _codex_command_truncated(container: dict[str, Any]) -> bool:
    output = (
        container.get("aggregated_output")
        or container.get("output")
        or container.get("stdout")
        or ""
    )
    return len(str(output)) > _FIELD_LIMIT


def _codex_terminal_error_message(
    event: dict[str, Any], container: dict[str, Any]
) -> str:
    """Extract a terminal failure message across flat/wrapped Codex dialects."""

    error = container.get("error") or event.get("error")
    if isinstance(error, dict):
        for key in ("message", "detail", "code", "type"):
            value = error.get(key)
            if value is not None:
                return str(value)
        return json.dumps(error, ensure_ascii=False)
    if error is not None:
        return str(error)
    for key in ("message", "detail"):
        value = container.get(key) or event.get(key)
        if value is not None:
            return str(value)
    return ""


def _codex_usage(
    container: dict[str, Any], *, model: str | None
) -> dict[str, Any] | None:
    usage = container.get("usage") or container.get("token_usage")
    if not isinstance(usage, dict):
        return None
    counts = {
        "input": _int(usage, "input_tokens", "prompt_tokens"),
        "output": _int(usage, "output_tokens", "completion_tokens"),
        "cache_read": _int(usage, "cached_input_tokens", "cache_read_input_tokens"),
        "cache_write": _int(usage, "cache_creation_input_tokens"),
    }
    return _usage_mapping(counts, model=model, input_includes_cache=True)


def trace_from_grok(
    *,
    agent_stdout: str,
    model: str,
    session_artifacts: dict[str, Any] | None,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    updates = _grok_updates_content(session_artifacts)
    if updates is None:
        return _grok_trace_from_final_object(
            agent_stdout=agent_stdout,
            model=model,
            policy_events=policy_events,
        )
    return _grok_trace_from_updates(
        updates=updates,
        agent_stdout=agent_stdout,
        model=model,
        session_artifacts=session_artifacts,
        policy_events=policy_events,
    )


def _grok_updates_content(session_artifacts: dict[str, Any] | None) -> str | None:
    """The richest ``updates.jsonl`` body exported from the grok session dir."""

    if not isinstance(session_artifacts, dict):
        return None
    best: str | None = None
    best_lines = -1
    for entry in session_artifacts.get("files") or []:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if not path.endswith("/updates.jsonl") and not path.endswith("updates.jsonl"):
            continue
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        lines = content.count("\n")
        if lines > best_lines:
            best, best_lines = content, lines
    return best


def _grok_signals(session_artifacts: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(session_artifacts, dict):
        return None
    for entry in session_artifacts.get("files") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("path") or "").endswith("signals.json"):
            content = entry.get("content")
            if isinstance(content, str) and content.strip():
                try:
                    obj = json.loads(content)
                except json.JSONDecodeError:
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def _grok_trace_from_updates(
    *,
    updates: str,
    agent_stdout: str,
    model: str,
    session_artifacts: dict[str, Any] | None,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    seq = _SeqCounter()
    events: list[TraceEvent] = []
    truncated = False
    parse_errors = 0
    final_text: str | None = None
    usage: dict[str, Any] | None = None
    saw_exit_code = False
    saw_turn_completed = False

    pending_kind: str | None = None
    pending_text: list[str] = []
    pending_ts: str | None = None
    open_tools: dict[str, dict[str, Any]] = {}

    def flush_pending() -> None:
        nonlocal pending_kind, pending_text, pending_ts, truncated, final_text
        if pending_kind is None:
            return
        joined = "".join(pending_text)
        etype = (
            EVENT_ASSISTANT_MESSAGE
            if pending_kind == "agent_message_chunk"
            else EVENT_REASONING
        )
        if joined.strip():
            if etype == EVENT_ASSISTANT_MESSAGE:
                final_text = joined
            text, was_trunc = _bounded(joined)
            truncated = truncated or was_trunc
            events.append(TraceEvent(seq.next(), etype, pending_ts, text=text))
        pending_kind, pending_text, pending_ts = None, [], None

    def upsert_tool_result(
        *,
        call_id: str | None,
        timestamp: str | None,
        output_text: str,
        status: str | None,
        exit_code: int | None,
        terminal: bool,
    ) -> None:
        """Coalesce incremental ACP updates into one canonical tool result."""

        nonlocal truncated
        record = open_tools.setdefault(call_id or "_orphan", {})
        output, was_trunc = _bounded(output_text or None)
        truncated = truncated or was_trunc
        previous_output = record.get("output")
        if output is not None and (
            terminal
            or not isinstance(previous_output, str)
            or len(output) >= len(previous_output)
        ):
            record["output"] = output
        if status is not None:
            record["status"] = _bounded(status)[0]
        if exit_code is not None:
            record["exit_code"] = exit_code
        if timestamp is not None:
            record["timestamp"] = _bounded(timestamp)[0]

        final_status = str(record.get("status") or "").casefold()
        final_exit_code = record.get("exit_code")
        failed = final_status in {"failed", "error", "cancelled", "canceled"} or (
            isinstance(final_exit_code, int) and final_exit_code != 0
        )
        is_error = True if failed else (False if terminal else None)
        result_event = record.get("result_event")
        if isinstance(result_event, TraceEvent):
            result_event.timestamp = record.get("timestamp")
            result_event.output = record.get("output")
            result_event.status = record.get("status")
            result_event.exit_code = final_exit_code
            result_event.is_error = is_error
            return

        result_event = TraceEvent(
            seq.next(),
            EVENT_TOOL_RESULT,
            record.get("timestamp"),
            tool_call_id=call_id,
            output=record.get("output"),
            status=record.get("status"),
            exit_code=final_exit_code,
            is_error=is_error,
        )
        events.append(result_event)
        record["result_event"] = result_event

    for line in updates.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if not isinstance(payload, dict):
            continue
        params = payload.get("params")
        if not isinstance(params, dict):
            continue
        update = params.get("update")
        if not isinstance(update, dict):
            continue
        kind = update.get("sessionUpdate")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        timestamp = _iso_from_epoch_ms(meta.get("agentTimestampMs")) or _iso_from_epoch_s(
            payload.get("timestamp")
        )

        if kind in {"agent_message_chunk", "agent_thought_chunk"}:
            if pending_kind is not None and pending_kind != kind:
                flush_pending()
            if pending_kind is None:
                pending_kind, pending_ts = kind, timestamp
            pending_text.append(_acp_content_text(update.get("content")))
        elif kind == "tool_call":
            flush_pending()
            call_id = _grok_tool_id(update)
            arguments = update.get("rawInput")
            if not isinstance(arguments, dict):
                arguments = update.get("input") if isinstance(update.get("input"), dict) else {}
            events.append(
                TraceEvent(
                    seq.next(),
                    EVENT_TOOL_CALL,
                    timestamp,
                    tool_call_id=call_id,
                    tool_name=str(update.get("title") or update.get("kind") or "") or None,
                    arguments=arguments,
                    status=str(update.get("status") or "") or None,
                )
            )
            open_tools[call_id or f"_{seq._value}"] = {}
        elif kind == "tool_call_update":
            call_id = _grok_tool_id(update)
            status = str(update.get("status") or "") or None
            output_text = _acp_content_text(update.get("content"))
            raw_output = update.get("rawOutput")
            if not output_text and raw_output is not None:
                output_text = (
                    json.dumps(raw_output)
                    if not isinstance(raw_output, str)
                    else raw_output
                )
            exit_code = _grok_exit_code(update)
            if exit_code is not None:
                saw_exit_code = True
            terminal = (status or "").lower() in _TERMINAL_TOOL_STATUSES
            if terminal or output_text or exit_code is not None:
                flush_pending()
                upsert_tool_result(
                    call_id=call_id,
                    timestamp=timestamp,
                    output_text=output_text,
                    status=status,
                    exit_code=exit_code,
                    terminal=terminal,
                )
        elif kind == "retry_state" and str(update.get("type") or "").lower() == "failed":
            flush_pending()
            message, was_trunc = _bounded(str(update.get("message") or ""))
            truncated = truncated or was_trunc
            events.append(
                TraceEvent(
                    seq.next(),
                    EVENT_ERROR,
                    timestamp,
                    message=message,
                    status=str(update.get("error_type") or "") or None,
                )
            )
        elif kind == "turn_completed":
            flush_pending()
            saw_turn_completed = True
            stop_reason = str(update.get("stop_reason") or "") or None
            result_text = str(update.get("agent_result") or "")
            terminal_failed = (stop_reason or "").casefold() in {
                "error",
                "failed",
                "cancelled",
                "canceled",
            }
            update_usage = _grok_usage_from_update(update)
            if update_usage is not None:
                usage = update_usage
            if terminal_failed:
                final_text = None
            if terminal_failed or result_text.strip():
                if not terminal_failed:
                    final_text = result_text
                text, was_trunc = _bounded(result_text)
                truncated = truncated or was_trunc
                events.append(
                    TraceEvent(
                        seq.next(),
                        EVENT_ERROR if terminal_failed else EVENT_FINAL_RESULT,
                        timestamp,
                        text=None if terminal_failed else text,
                        message=text if terminal_failed else None,
                        stop_reason=stop_reason,
                    )
                )
    flush_pending()

    if usage is None:
        usage = _grok_usage_from_signals(_grok_signals(session_artifacts))
    if usage is not None and usage.get("total_cost") is None:
        total_cost = _cost_for(model, usage)
        if total_cost is not None:
            usage["total_cost"] = total_cost
            usage["cost_source"] = "pricing_table"

    unobservable: list[str] = []
    if not saw_exit_code:
        unobservable.append("tool_exit_code")
    if usage is None:
        unobservable.append("usage")

    artifacts_truncated = bool(
        isinstance(session_artifacts, dict) and session_artifacts.get("truncated")
    )
    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    truncated = truncated or _trace_has_truncation(events) or bool(
        final_text and len(final_text) > _FIELD_LIMIT
    ) or _policy_events_truncated(normalized_policy_events)
    observability = TraceObservability(
        source=SOURCE_GROK_SESSION_UPDATES,
        complete=saw_turn_completed and parse_errors == 0 and not artifacts_truncated,
        truncated=truncated or artifacts_truncated,
        parse_error_count=parse_errors,
        redaction_applied=(
            _policy_events_changed(policy_events)
            or _trace_has_redaction(events)
        ),
        unobservable_fields=unobservable,
    )
    if artifacts_truncated:
        observability.notes.append(
            "session export truncated by the runner capture cap"
        )
    if not saw_turn_completed:
        observability.notes.append("no turn_completed update (run cut off)")
    return CanonicalTrace(
        harness="grok",
        model=model,
        events=events,
        observability=observability,
        usage=usage,
        final_result=_bounded(final_text)[0],
        policy_events=normalized_policy_events,
    )


def _grok_trace_from_final_object(
    *,
    agent_stdout: str,
    model: str,
    policy_events: list[dict[str, Any]] | None = None,
) -> CanonicalTrace:
    """Fallback when the grok session log is unavailable.

    Grok's ``--output-format json`` stdout is only the final message, so the
    per-event stream cannot be recovered. Emit the final result and mark every
    stream-only field explicitly unobservable — the run is not treated as
    having no tool activity, only as having none *observable* here.
    """

    from boundarybench.harness.grok import _grok_final_text, _parse_grok_json

    seq = _SeqCounter()
    events: list[TraceEvent] = []
    final_text = _grok_final_text(agent_stdout)
    obj = _parse_grok_json(agent_stdout)
    is_error = isinstance(obj, dict) and obj.get("type") == "error"

    if is_error:
        message, _ = _bounded(str(obj.get("message") or ""))
        events.append(TraceEvent(seq.next(), EVENT_ERROR, None, message=message))
    elif final_text:
        text, _ = _bounded(final_text)
        events.append(
            TraceEvent(
                seq.next(),
                EVENT_FINAL_RESULT,
                None,
                text=text,
                stop_reason=str(obj.get("stopReason")) if isinstance(obj, dict) else None,
            )
        )

    normalized_policy_events = _normalize_policy_events(policy_events)
    _link_policy_events(events, normalized_policy_events)
    truncated = (
        bool(final_text and len(final_text) > _FIELD_LIMIT)
        or _trace_has_truncation(events)
        or _policy_events_truncated(normalized_policy_events)
    )
    observability = TraceObservability(
        source=SOURCE_GROK_FINAL_OBJECT,
        complete=False,
        truncated=truncated,
        redaction_applied=(
            _policy_events_changed(policy_events)
            or _trace_has_redaction(events)
        ),
        unobservable_fields=[
            "reasoning",
            "tool_calls",
            "tool_results",
            "tool_exit_code",
            "per_event_timestamps",
            "usage",
        ],
        notes=[
            "grok session update log unavailable; captured only the final "
            "stdout object. Tool activity is unobservable here, not absent."
        ],
    )
    return CanonicalTrace(
        harness="grok",
        model=model,
        events=events,
        observability=observability,
        usage=None,
        final_result=_bounded(final_text)[0],
        policy_events=normalized_policy_events,
    )


def _acp_content_text(content: Any) -> str:
    """Text out of an ACP content value (dict, list, or nested ``content``)."""

    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        inner = content.get("content")
        if inner is not None and inner is not content:
            return _acp_content_text(inner)
        return ""
    if isinstance(content, list):
        return "".join(_acp_content_text(item) for item in content)
    return ""


def _grok_tool_id(update: dict[str, Any]) -> str | None:
    for key in ("toolCallId", "tool_call_id", "toolCallID", "id"):
        value = update.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value)
    return None


def _grok_exit_code(update: dict[str, Any]) -> int | None:
    for key in ("exit_code", "exitCode"):
        value = update.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.lstrip("-").isdigit():
            return int(value)
    raw_output = update.get("rawOutput")
    if isinstance(raw_output, dict):
        for key in ("exit_code", "exitCode"):
            value = raw_output.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.lstrip("-").isdigit():
                return int(value)
    return None


def _grok_usage_from_update(update: dict[str, Any]) -> dict[str, Any] | None:
    usage = update.get("usage")
    if not isinstance(usage, dict):
        return None
    counts = {
        "input": _int(usage, "input_tokens", "prompt_tokens"),
        "output": _int(usage, "output_tokens", "completion_tokens"),
        "cache_read": _int(usage, "cache_read_input_tokens", "cached_input_tokens"),
        "cache_write": _int(usage, "cache_creation_input_tokens"),
    }
    return _usage_mapping(counts, model=None, input_includes_cache=True)


def _grok_usage_from_signals(signals: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(signals, dict):
        return None
    candidates: list[dict[str, Any]] = [signals]
    for value in signals.values():
        if isinstance(value, dict):
            candidates.append(value)
    for candidate in candidates:
        counts = {
            "input": _int(candidate, "input_tokens", "prompt_tokens"),
            "output": _int(candidate, "output_tokens", "completion_tokens"),
            "cache_read": _int(candidate, "cache_read_input_tokens", "cached_input_tokens"),
            "cache_write": _int(candidate, "cache_creation_input_tokens"),
        }
        if any(counts.values()):
            return _usage_mapping(counts, model=None, input_includes_cache=True)
    return None


def _cost_for(model: str | None, usage: dict[str, Any]) -> float | None:
    if not model:
        return None
    try:
        from boundarybench.terminalbench.pricing import openrouter_cost

        cache_read = int(usage.get("cache_read_tokens") or 0)
        cache_write = int(usage.get("cache_write_tokens") or 0)
        fresh_input = max(
            int(usage.get("input_tokens") or 0) - cache_read - cache_write,
            0,
        )
        return openrouter_cost(
            model,
            input_tokens=fresh_input,
            output_tokens=int(usage.get("output_tokens") or 0),
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
        )
    except Exception:  # noqa: BLE001 - pricing is best-effort metadata
        return None


def _int(mapping: dict[str, Any], *keys: str) -> int:
    for key in keys:
        try:
            value = int(mapping.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value:
            return value
    return 0


def _usage_mapping(
    counts: dict[str, int],
    *,
    model: str | None,
    input_includes_cache: bool,
) -> dict[str, Any] | None:
    """Normalize provider usage to one cache-inclusive input contract.

    Canonical ``input_tokens`` includes cached prompt tokens, matching
    OpenAI/OpenRouter accounting. Anthropic reports fresh input separately, so
    Claude adds cache buckets; Codex/Grok already report cache as a subset.
    Fallback pricing always receives fresh input plus separate cache buckets.
    """

    if not any(counts.values()):
        return None
    cached_input = counts["cache_read"] + counts["cache_write"]
    if input_includes_cache:
        canonical_input = counts["input"]
        fresh_input = max(canonical_input - cached_input, 0)
    else:
        fresh_input = counts["input"]
        canonical_input = fresh_input + cached_input
    total_cost: float | None = None
    if model:
        try:
            from boundarybench.terminalbench.pricing import openrouter_cost

            total_cost = openrouter_cost(
                model,
                input_tokens=fresh_input,
                output_tokens=counts["output"],
                cache_read_tokens=counts["cache_read"],
                cache_write_tokens=counts["cache_write"],
            )
        except Exception:  # noqa: BLE001 - pricing is best-effort metadata
            total_cost = None
    mapping = {
        "input_tokens": canonical_input,
        "output_tokens": counts["output"],
        "cache_read_tokens": counts["cache_read"],
        "cache_write_tokens": counts["cache_write"],
        "total_tokens": canonical_input + counts["output"],
        "total_cost": total_cost,
    }
    if total_cost is not None:
        mapping["cost_source"] = "pricing_table"
    return mapping


def _normalize_policy_events(events: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Keep policy evidence in the trace with bounded, JSON-safe fields.

    Policy telemetry is already structured by the sandbox, but command/output
    fields can contain model-controlled text.  Bound and redact strings before
    the trace is written to durable GCS evidence; retain the event shape so all
    registered harnesses expose policy evidence identically.
    """

    if not events:
        return []
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events[:_COLLECTION_LIMIT]):
        if not isinstance(event, dict):
            continue
        clean = _sanitize_value(event)
        clean["policy_event_id"] = f"policy-{index:04d}"
        normalized.append(clean)
    if len(events) > _COLLECTION_LIMIT:
        normalized.append(
            {
                "event_type": "trace_truncation",
                "policy_event_id": "policy-truncation",
                "truncated": True,
                "omitted_count": len(events) - _COLLECTION_LIMIT,
            }
        )
    return normalized


def _policy_events_truncated(events: list[dict[str, Any]] | None) -> bool:
    normalized = events or []
    return any(
        isinstance(event, dict) and event.get("truncated") for event in normalized
    ) or "[truncated " in json.dumps(normalized, ensure_ascii=False)


def _policy_events_changed(events: list[dict[str, Any]] | None) -> bool:
    """Whether sanitizing policy telemetry changed a source value."""

    if not events:
        return False
    return any(
        isinstance(event, dict) and _sanitize_value(event) != event for event in events
    )


def _link_policy_events(
    events: list[TraceEvent], policy_events: list[dict[str, Any]]
) -> None:
    """Attach stable policy ids to matching tool events when telemetry allows."""

    for policy in policy_events:
        policy_id = str(policy.get("policy_event_id") or "")
        needles = [
            str(policy.get(key) or "")
            for key in ("command", "exec_path", "path", "target")
        ]
        needles = [needle for needle in needles if needle]
        matches: list[int] = []
        if needles:
            for event in events:
                if event.type not in {EVENT_TOOL_CALL, EVENT_TOOL_RESULT}:
                    continue
                haystack = json.dumps(event.to_mapping(), ensure_ascii=False)
                if any(needle in haystack for needle in needles):
                    matches.append(event.seq)
                    if policy_id and policy_id not in event.policy_event_refs:
                        event.policy_event_refs.append(policy_id)
        policy["trace_event_seqs"] = matches


def _redact_secret_text(value: str) -> str:
    patterns = (
        r"(?i)(?:authorization|proxy-authorization)\s*[=:]\s*"
        r"(?:bearer|basic)\s+[A-Za-z0-9_./+=:-]+",
        r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9_./+=:-]{8,}",
        r"(?i)(?:OPENROUTER_API_KEY|CODEX_OPENROUTER_API_KEY|GROK_OPENROUTER_API_KEY|"
        r"TERMINUS_OPENROUTER_API_KEY|"
        r"ANTHROPIC_AUTH_TOKEN|API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|"
        r"CLIENT_SECRET|ACCESS_KEY|PRIVATE_KEY)\s*[=:]\s*[^\s,;]+",
        r"sk-or-v1-[A-Za-z0-9_./-]{16,}",
        r"(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})",
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        r"AIza[0-9A-Za-z_-]{35}",
        r"xox[baprs]-[A-Za-z0-9-]{16,}",
    )
    for pattern in patterns:
        value = re.sub(pattern, "[REDACTED]", value)
    return value
