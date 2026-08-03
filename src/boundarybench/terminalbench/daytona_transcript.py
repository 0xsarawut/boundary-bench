"""Translate Claude Code's stream-json transcript into Inspect messages.

The agent (Claude Code) runs inside Daytona and emits a ``stream-json``
transcript. To make the run observable in the Inspect viewer with normalized
turns, tool calls, reasoning, model, and usage, we translate that transcript
into Inspect ``ChatMessage`` objects and a ``ModelOutput`` rather than leaving
it as opaque metadata. The model interaction itself still happens in Claude
Code; this only records it in Inspect's normal shape.

We also render a standalone human-readable Markdown transcript per task
(``render_task_transcript_markdown``) so a run can be read end-to-end for
failure analysis without the Inspect viewer.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from inspect_ai.model import (
    ChatCompletionChoice,
    ChatMessage,
    ChatMessageAssistant,
    ChatMessageTool,
    ChatMessageUser,
    Content,
    ContentReasoning,
    ContentText,
    ModelOutput,
    ModelUsage,
)
from inspect_ai.tool import ToolCall

from boundarybench.policy_surfaces.markers import POLICY_BLOCKED_OUTPUT_MARKERS
from boundarybench.terminalbench.pricing import openrouter_cost
from boundarybench.terminalbench.provider_error_markers import (
    PROVIDER_ERROR_MARKERS,
    PROVIDER_ERROR_MAX_TURNS,
    PROVIDER_HTTP_CONTEXT_MARKERS,
    PROVIDER_HTTP_STATUS_MARKERS,
)

_MARKDOWN_BLOCK_LIMIT = 4000


@dataclass(frozen=True)
class ProviderErrorInfo:
    """Structured description of a detected provider/auth failure."""

    marker: str
    detail: str

    def to_metadata(self) -> dict[str, str]:
        return {"marker": self.marker, "detail": self.detail}


def detect_provider_auth_error(
    agent_stdout: str,
    *,
    max_turns: int = PROVIDER_ERROR_MAX_TURNS,
) -> ProviderErrorInfo | None:
    """Return error info when agent stdout indicates a provider/auth failure.

    Detection requires *both* a matching marker *and* very few assistant turns
    so that a transient 429 retry in a long productive run is not miscounted.
    """

    if not agent_stdout:
        return None

    events = parse_claude_stream(agent_stdout)
    turns = sum(1 for e in events if e.get("type") == "assistant")
    if turns > max_turns:
        return None

    low = agent_stdout.lower()

    for marker in PROVIDER_ERROR_MARKERS:
        if marker in low:
            return _provider_error_info(agent_stdout, low, marker)

    for marker in PROVIDER_HTTP_STATUS_MARKERS:
        if marker in low and _has_provider_http_context(agent_stdout, low, marker):
            return _provider_error_info(agent_stdout, low, marker)

    for event in reversed(events):
        if event.get("type") != "result":
            continue
        result_text = str(event.get("result") or "").lower()
        error_text = str(event.get("error") or "").lower()
        for marker in PROVIDER_ERROR_MARKERS:
            if marker in result_text or marker in error_text:
                snippet = (
                    str(event.get("result") or event.get("error") or "")
                    .replace("\n", " ")
                    .strip()
                )
                return ProviderErrorInfo(marker=marker, detail=snippet[:200])
        event_text = str(event.get("result") or event.get("error") or "")
        event_low = event_text.lower()
        for marker in PROVIDER_HTTP_STATUS_MARKERS:
            if marker in event_low and _has_provider_http_context(
                event_text, event_low, marker
            ):
                return _provider_error_info(event_text, event_low, marker)

    return None


def _provider_error_info(
    text: str,
    low: str,
    marker: str,
    *,
    context_chars: int = 60,
) -> ProviderErrorInfo:
    idx = low.index(marker)
    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(marker) + context_chars)
    snippet = text[start:end].replace("\n", " ").strip()
    return ProviderErrorInfo(marker=marker, detail=snippet[:200])


def _has_provider_http_context(text: str, low: str, marker: str) -> bool:
    idx = low.index(marker)
    start = max(0, idx - 120)
    end = min(len(text), idx + len(marker) + 120)
    snippet = low[start:end]
    return any(context in snippet for context in PROVIDER_HTTP_CONTEXT_MARKERS)


def parse_claude_stream(stdout: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = _salvage_truncated_result_event(line)
            if payload is None:
                continue
            events.append(payload)
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


USAGE_SOURCE_RESULT_EVENT = "result_event"
USAGE_SOURCE_PARTIAL_EVENTS = "partial_events"
USAGE_SOURCE_NONE = "none"


@dataclass(frozen=True)
class _StreamScan:
    """Harness-agnostic shape of a JSON-lines agent-stdout stream.

    The line-level scan — JSON parse errors, non-JSON prose lines, the last
    complete event ``type``, and the recovered event list — is identical for
    every harness dialect; only the interpretation of which event is the run's
    terminal/usage event differs. ``claude_stream_diagnostics`` and the Codex
    ``codex_stream_diagnostics`` both build on this so those harness-agnostic
    fields stay identical (same BigQuery columns, same meaning).
    """

    parse_error_count: int
    non_json_line_count: int
    last_complete_event_type: str | None
    complete_result_event: bool
    salvaged_result_event: bool
    events: list[dict[str, Any]]


def _scan_json_stream(stdout: str) -> _StreamScan:
    parse_error_count = 0
    non_json_line_count = 0
    last_complete_event_type: str | None = None
    complete_result_event = False
    salvaged_result_event = False
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            if not _looks_like_json_stream_line(line):
                non_json_line_count += 1
                continue
            parse_error_count += 1
            salvaged = _salvage_truncated_result_event(line)
            if salvaged is not None:
                salvaged_result_event = True
                events.append(salvaged)
            continue
        if isinstance(payload, dict):
            event_type = payload.get("type")
            if event_type is not None:
                last_complete_event_type = str(event_type)
            if event_type == "result":
                complete_result_event = True
            events.append(payload)
    return _StreamScan(
        parse_error_count=parse_error_count,
        non_json_line_count=non_json_line_count,
        last_complete_event_type=last_complete_event_type,
        complete_result_event=complete_result_event,
        salvaged_result_event=salvaged_result_event,
        events=events,
    )


def claude_stream_diagnostics(stdout: str) -> dict[str, Any]:
    scan = _scan_json_stream(stdout)
    events = scan.events
    result_event_present = scan.complete_result_event or scan.salvaged_result_event
    result_event_usage_present = any(
        any(_usage_from_event(event).values())
        for event in events
        if event.get("type") == "result"
    )
    partial_usage_present = any(_sum_nonzero_turn_usage(events).values())
    if result_event_usage_present:
        usage_source = USAGE_SOURCE_RESULT_EVENT
    elif partial_usage_present:
        usage_source = USAGE_SOURCE_PARTIAL_EVENTS
    else:
        usage_source = USAGE_SOURCE_NONE
    usage_present = usage_source != USAGE_SOURCE_NONE
    return {
        "agent_stdout_parse_error_count": scan.parse_error_count,
        "agent_stdout_non_json_line_count": scan.non_json_line_count,
        "agent_stdout_last_complete_event_type": scan.last_complete_event_type,
        "agent_stdout_truncated_or_malformed": scan.parse_error_count > 0,
        "agent_stdout_result_event_present": result_event_present,
        "agent_stdout_final_result_event_present": scan.complete_result_event,
        "agent_stdout_result_event_missing": not result_event_present,
        "agent_stdout_result_event_usage_present": result_event_usage_present,
        "agent_model_usage_present": usage_present,
        "agent_model_usage_source": usage_source,
        "agent_model_usage_recovered": usage_present and not scan.complete_result_event,
    }


DIAGNOSTICS_DIALECT_CLAUDE = "claude"
DIAGNOSTICS_DIALECT_CODEX = "codex"
DIAGNOSTICS_DIALECT_TERMINUS_2 = "terminus_2"

_CODEX_STREAM_MARKERS = (
    '"turn.completed"',
    '"turn.started"',
    '"turn.failed"',
    '"item.completed"',
    '"item.started"',
    '"command_execution"',
    '"token_count"',
)


def stream_diagnostics(
    agent_stdout: str, *, harness: str | None = None
) -> dict[str, Any]:
    """Harness-aware agent-stdout stream diagnostics.

    Claude Code emits a stream-json transcript ending in a ``type=="result"``
    event; Codex emits a different vocabulary (``turn.completed`` / ``token_count``
    / item-wrapped events) and never a Claude ``result`` event, so the
    Claude-shaped ``result_event_*`` fields are meaningless — and misleadingly
    hard-false — on a Codex run. This dispatches to the dialect matching the
    harness so every field is honest, WITHOUT changing the metadata keys (same
    BigQuery columns). The applied dialect is recorded under
    ``agent_stdout_diagnostics_dialect`` (metadata_json only; not a BQ column).
    """

    dialect = _diagnostics_dialect(harness, agent_stdout)
    if dialect == DIAGNOSTICS_DIALECT_CODEX:
        from boundarybench.harness.codex import codex_stream_diagnostics

        diagnostics = codex_stream_diagnostics(agent_stdout)
    elif dialect == DIAGNOSTICS_DIALECT_TERMINUS_2:
        from boundarybench.harness.terminus_2 import (
            terminus_2_stream_diagnostics,
        )

        diagnostics = terminus_2_stream_diagnostics(agent_stdout)
    else:
        diagnostics = claude_stream_diagnostics(agent_stdout)
    diagnostics["agent_stdout_diagnostics_dialect"] = dialect
    return diagnostics


def _diagnostics_dialect(harness: str | None, agent_stdout: str) -> str:
    """Pick the stream dialect: explicit harness first, else auto-detect.

    The diagnostics call site (``TerminalBenchRunResult.to_metadata``) always
    knows the harness, so dispatch is explicit there. Auto-detection from the
    event vocabulary is only the fallback for callers without a harness label;
    every registered non-Codex harness (claude_code, grok) speaks the Claude
    stream-json dialect, so their diagnostics are unchanged.
    """

    name = (harness or "").strip().lower()
    if name == "codex":
        return DIAGNOSTICS_DIALECT_CODEX
    if name == "terminus_2":
        return DIAGNOSTICS_DIALECT_TERMINUS_2
    if name:
        return DIAGNOSTICS_DIALECT_CLAUDE
    return (
        DIAGNOSTICS_DIALECT_CODEX
        if _looks_like_codex_stream(agent_stdout)
        else DIAGNOSTICS_DIALECT_CLAUDE
    )


def _looks_like_codex_stream(agent_stdout: str) -> bool:
    if not agent_stdout:
        return False
    if '"type":"result"' in agent_stdout or '"type": "result"' in agent_stdout:
        return False
    return any(marker in agent_stdout for marker in _CODEX_STREAM_MARKERS)


def _looks_like_json_stream_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _extract_json_object_after(text: str, key: str) -> dict[str, Any] | None:
    key_pos = text.find(key)
    if key_pos < 0:
        return None
    start = text.find("{", key_pos)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for idx, char in enumerate(text[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    payload = json.loads(text[start : idx + 1])
                except json.JSONDecodeError:
                    return None
                return payload if isinstance(payload, dict) else None
    return None


def _salvage_truncated_result_event(line: str) -> dict[str, Any] | None:
    """Recover usage from a truncated Claude ``result`` line when possible."""

    if '"type":"result"' not in line and '"type": "result"' not in line:
        return None
    usage = _extract_json_object_after(line, '"usage"')
    if not usage:
        return None
    event: dict[str, Any] = {
        "type": "result",
        "subtype": "truncated",
        "usage": usage,
        "usage_recovered": True,
    }
    total_cost = re.search(r'"total_cost_usd"\s*:\s*([0-9.]+)', line)
    if total_cost:
        event["total_cost_usd"] = float(total_cost.group(1))
    return event


def _tool_result_text(content: Any) -> str:
    if isinstance(content, list):
        return "\n".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
    return str(content or "")


def _assistant_blocks(event: dict[str, Any]) -> list[dict[str, Any]]:
    blocks = _message_dict(event).get("content") or []
    return [b for b in blocks if isinstance(b, dict)]


def _int_usage(usage: dict[str, Any], *keys: str) -> int:
    for key in keys:
        try:
            value = int(usage.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value:
            return value
    return 0


def _message_dict(event: dict[str, Any]) -> dict[str, Any]:
    """The event's ``message`` as a dict, or ``{}`` when it is not one.

    Claude stream events wrap content/usage in a dict ``message``; other harness
    formats (e.g. Codex ``--json``) can put a plain STRING there. Returning ``{}``
    for a non-dict keeps the Claude-stream diagnostics/transcript parsing from
    crashing on non-Claude output -- it simply finds no Claude-shaped fields.
    """

    message = event.get("message")
    return message if isinstance(message, dict) else {}


def _usage_from_event(event: dict[str, Any]) -> dict[str, int]:
    raw = event.get("usage")
    if not isinstance(raw, dict):
        raw = _message_dict(event).get("usage")
    usage = raw if isinstance(raw, dict) else {}
    return {
        "input": _int_usage(usage, "input_tokens"),
        "output": _int_usage(usage, "output_tokens"),
        "cache_read": _int_usage(
            usage, "cache_read_input_tokens", "input_tokens_cache_read"
        ),
        "cache_write": _int_usage(
            usage, "cache_creation_input_tokens", "input_tokens_cache_write"
        ),
    }


def _sum_nonzero_turn_usage(events: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for event in events:
        if event.get("type") == "result":
            continue
        usage = _usage_from_event(event)
        if any(usage.values()):
            for key, value in usage.items():
                totals[key] += value
    return totals


def _usage_model_usage(
    model: str,
    usage: dict[str, int],
    *,
    input_includes_cache: bool = False,
) -> ModelUsage | None:
    if not any(usage.values()):
        return None
    cached_input = usage["cache_read"] + usage["cache_write"]
    fresh_input = (
        max(usage["input"] - cached_input, 0)
        if input_includes_cache
        else usage["input"]
    )
    total_tokens = (
        usage["input"] + usage["output"]
        if input_includes_cache
        else sum(usage.values())
    )
    cost = openrouter_cost(
        model,
        input_tokens=fresh_input,
        output_tokens=usage["output"],
        cache_read_tokens=usage["cache_read"],
        cache_write_tokens=usage["cache_write"],
    )
    return ModelUsage(
        input_tokens=usage["input"],
        output_tokens=usage["output"],
        total_tokens=total_tokens,
        input_tokens_cache_read=usage["cache_read"] or None,
        input_tokens_cache_write=usage["cache_write"] or None,
        total_cost=cost,
    )


def claude_transcript_to_inspect(
    *, prompt: str, agent_stdout: str, model: str, pricing_model: str | None = None
) -> tuple[list[ChatMessage], ModelOutput]:
    """Build (messages, output) from the Claude Code transcript.

    Assistant turns carry interleaved reasoning (``thinking``) and text plus
    structured tool calls; tool results are labelled with the tool name so the
    viewer reads as a normal model conversation.
    """

    events = parse_claude_stream(agent_stdout)
    cost_model = pricing_model or model
    messages: list[ChatMessage] = [ChatMessageUser(content=prompt)]
    tool_names: dict[str, str] = {}
    final_text = ""
    usage: ModelUsage | None = None

    for event in events:
        etype = event.get("type")
        if etype == "assistant":
            content: list[Content] = []
            text_parts: list[str] = []
            tool_calls: list[ToolCall] = []
            for block in _assistant_blocks(event):
                btype = block.get("type")
                if btype == "thinking" and block.get("thinking"):
                    content.append(ContentReasoning(reasoning=str(block["thinking"])))
                elif btype == "text" and block.get("text"):
                    content.append(ContentText(text=str(block["text"])))
                    text_parts.append(str(block["text"]))
                elif btype == "tool_use":
                    tool_id = str(block.get("id", ""))
                    tool_name = str(block.get("name", ""))
                    tool_names[tool_id] = tool_name
                    tool_calls.append(
                        ToolCall(
                            id=tool_id,
                            function=tool_name,
                            arguments=block.get("input") or {},
                        )
                    )
            if text_parts:
                final_text = "\n".join(text_parts)
            messages.append(
                ChatMessageAssistant(
                    content=content if any(
                        isinstance(c, ContentReasoning) for c in content
                    ) else "\n".join(text_parts),
                    tool_calls=tool_calls or None,
                    model=model,
                )
            )
        elif etype == "user":
            blocks = _message_dict(event).get("content") or []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tool_id = str(block.get("tool_use_id", ""))
                    messages.append(
                        ChatMessageTool(
                            content=_tool_result_text(block.get("content")),
                            tool_call_id=tool_id,
                            function=tool_names.get(tool_id),
                        )
                    )
        elif etype == "result":
            usage_counts = _usage_from_event(event)
            usage = _usage_model_usage(cost_model, usage_counts)
            if event.get("result"):
                final_text = str(event["result"])

    if usage is None:
        usage = _usage_model_usage(cost_model, _sum_nonzero_turn_usage(events))

    output = ModelOutput(
        model=model,
        choices=[
            ChatCompletionChoice(
                message=ChatMessageAssistant(content=final_text, model=model),
                stop_reason="stop",
            )
        ],
        usage=usage,
    )
    return messages, output


def extract_blocked_surfaces(
    agent_stdout: str, *, policy: str | None = None
) -> list[dict[str, str]]:
    """Per-task list of policy-hardening blocks the agent hit.

    Maps each tool result that carries an BOUNDARY policy-block marker back to
    the command that tripped it. Uses the precise policy markers (not the broad
    heuristic ones) so ordinary errors aren't miscounted as enforcement.
    """

    if (policy or "").strip().lower() == "none":
        return []

    events = parse_claude_stream(agent_stdout)
    tool_commands: dict[str, str] = {}
    blocks: list[dict[str, str]] = []
    for event in events:
        etype = event.get("type")
        if etype == "assistant":
            for block in _assistant_blocks(event):
                if block.get("type") == "tool_use":
                    args = block.get("input") or {}
                    cmd = args.get("command") if isinstance(args, dict) else None
                    tool_commands[str(block.get("id", ""))] = (
                        str(cmd) if cmd else str(block.get("name", ""))
                    )
        elif etype == "user":
            for block in _message_dict(event).get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                text = _tool_result_text(block.get("content"))
                if not _tool_result_is_policy_denial(block, text):
                    continue
                low = text.lower()
                marker = next(
                    (m for m in POLICY_BLOCKED_OUTPUT_MARKERS if m in low), None
                )
                if marker:
                    blocks.append(
                        {
                            "command": tool_commands.get(
                                str(block.get("tool_use_id", "")), ""
                            ),
                            "marker": marker,
                            "snippet": text.strip()[:200],
                        }
                    )
    return blocks


def _tool_result_is_policy_denial(block: dict[str, Any], text: str) -> bool:
    if bool(block.get("is_error")):
        return True
    try:
        if int(block.get("exit_code")) == 126:
            return True
    except (TypeError, ValueError):
        pass
    return bool(re.search(r"\b(exit code|exit status|exited with)\s*:?\s*126\b", text, re.I))


def stream_activity_summary(agent_stdout: str) -> dict[str, int]:
    """Counts that explain a run's shape: real turns vs. internal-thinking pings.

    A long run can show few conversation messages because the agent spent the
    time looping in internal reasoning — Claude Code emits a ``thinking_tokens``
    system event per reasoning update (not a message). Surfacing the counts makes
    "few messages for a 20-minute run" self-explanatory rather than looking like
    dropped data.
    """

    events = parse_claude_stream(agent_stdout)
    turns = sum(1 for e in events if e.get("type") == "assistant")
    tool_calls = sum(
        1
        for e in events
        if e.get("type") == "assistant"
        for b in _assistant_blocks(e)
        if b.get("type") == "tool_use"
    )
    thinking_updates = sum(
        1
        for e in events
        if e.get("type") == "system" and e.get("subtype") == "thinking_tokens"
    )
    return {
        "assistant_turns": turns,
        "tool_calls": tool_calls,
        "thinking_token_updates": thinking_updates,
    }


def count_recovery_skill_invocations(agent_stdout: str) -> int:
    """Count Claude Code tool-calls that pull up the policy-error-recovery skill.

    Walks the same assistant ``tool_use`` blocks ``stream_activity_summary``
    parses. The real signal (verified against captured claude stream-json, CC
    2.1.215) is a ``Skill`` tool_use — ``name == "Skill"`` and the invoked skill
    under ``input.skill`` (a string; ``input.args`` carries the arg string):

        {"type":"tool_use","name":"Skill",
         "input":{"skill":"policy-error-recovery","args":"..."},"caller":{...}}

    Claude Code delivers the skill body as a synthetic user message, not a Read
    of SKILL.md; the Skill tool_use (name=='Skill', input.skill==<name>) is the
    real signal. This counts MODEL-DRIVEN invocations (the recovery skill's
    description auto-trigger). It would NOT count a slash-form
    ``/policy-error-recovery`` activation, which emits no tool_use — the harness
    does not use the slash form.

    A second arm (any input path ending in ``policy-error-recovery/SKILL.md``) is
    kept as defense but never fires in current CC (no Read of SKILL.md happens);
    it also catches a hand-rolled ``cat .../SKILL.md``. Keyed off the shared
    ``recovery_skill`` constants so it counts exactly the skill dir the renderer
    emits — the leading indicator that the agent actually used the guidance.
    """

    from boundarybench.terminalbench.recovery_skill import (
        RECOVERY_SKILL_FILE,
        RECOVERY_SKILL_NAME,
    )

    skill_file_suffix = f"{RECOVERY_SKILL_NAME}/{RECOVERY_SKILL_FILE}"
    count = 0
    for event in parse_claude_stream(agent_stdout):
        if event.get("type") != "assistant":
            continue
        for block in _assistant_blocks(event):
            if block.get("type") != "tool_use":
                continue
            args = block.get("input")
            if not isinstance(args, dict):
                args = {}
            skill = args.get("skill")
            if (
                str(block.get("name", "")) == "Skill"
                and isinstance(skill, str)
                and RECOVERY_SKILL_NAME in skill
            ):
                count += 1
                continue
            if any(
                isinstance(value, str) and value.endswith(skill_file_suffix)
                for value in args.values()
            ):
                count += 1
    return count


def policy_interaction_metrics(
    agent_stdout: str,
    *,
    policy_events: list[dict[str, Any]] | None,
    task_net_runtime_ms: int | None,
) -> dict[str, Any]:
    block_events = [
        event
        for event in (policy_events or [])
        if event.get("event_type") == "policy_block"
    ]
    block_count = len(block_events)
    target_counts = Counter(_policy_block_target(event) for event in block_events)
    actor_events = [
        event
        for event in block_events
        if str(event.get("attribution_scope") or "") != "domain_proxy_process"
    ]
    process_counts = Counter(
        str(event.get("comm") or event.get("exe") or "").strip()
        for event in actor_events
        if str(event.get("comm") or event.get("exe") or "").strip()
    )
    cmdline_counts = Counter(
        str(event.get("cmdline") or event.get("command") or "").strip()
        for event in actor_events
        if str(event.get("cmdline") or event.get("command") or "").strip()
    )

    first_block_at = min(
        (
            timestamp
            for timestamp in (
                _parse_event_timestamp(event) for event in block_events
            )
            if timestamp
        ),
        default=None,
    )
    return {
        "unique_blocked_target_count": len(target_counts),
        "top_blocked_target_share": (
            max(target_counts.values()) / block_count if block_count else 0.0
        ),
        "blocks_per_minute": _blocks_per_minute(block_count, task_net_runtime_ms),
        "post_first_block_tool_calls": _post_first_block_tool_calls(
            agent_stdout, first_block_at=first_block_at
        ),
        "policy_block_process_counts": _top_counter(process_counts),
        "policy_block_cmdline_counts": _top_counter(cmdline_counts),
    }


def _policy_block_target(event: dict[str, Any]) -> str:
    surface = str(event.get("surface") or "unknown")
    target = event.get("target")
    if target is None:
        target = event.get("command")
    if target is None:
        target = event.get("path")
    if target is None:
        target = "<none>"
    return f"{surface}|{target}"


def _blocks_per_minute(block_count: int, task_net_runtime_ms: int | None) -> float | None:
    if not task_net_runtime_ms or task_net_runtime_ms <= 0:
        return None
    return block_count / (task_net_runtime_ms / 60000)


def _post_first_block_tool_calls(
    agent_stdout: str, *, first_block_at: datetime | None
) -> int | None:
    if first_block_at is None:
        return None
    count = 0
    tool_calls = 0
    timestamped_tool_events = 0
    for event in parse_claude_stream(agent_stdout):
        if event.get("type") != "assistant":
            continue
        event_tool_calls = sum(
            1 for block in _assistant_blocks(event) if block.get("type") == "tool_use"
        )
        if not event_tool_calls:
            continue
        tool_calls += event_tool_calls
        event_at = _parse_event_timestamp(event)
        if event_at is None:
            continue
        timestamped_tool_events += event_tool_calls
        if event_at < first_block_at:
            continue
        count += event_tool_calls
    if tool_calls and timestamped_tool_events == 0:
        return None
    return count


def _parse_event_timestamp(event: dict[str, Any]) -> datetime | None:
    raw = event.get("timestamp")
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _top_counter(counter: Counter[str], *, limit: int = 20) -> dict[str, int]:
    return {
        key: value
        for key, value in sorted(
            counter.items(), key=lambda item: (-item[1], item[0])
        )[:limit]
    }


def _truncate(text: str, limit: int = _MARKDOWN_BLOCK_LIMIT) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


def _fence(text: str, lang: str = "") -> str:
    body = _truncate(text).replace("```", "ʼʼʼ")
    return f"```{lang}\n{body}\n```"


def _init_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in events:
        if event.get("type") == "system" and event.get("subtype") == "init":
            return event
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _benchmark_status_fields(
    benchmark_status: dict[str, Any] | None,
) -> dict[str, str] | None:
    if not isinstance(benchmark_status, dict):
        return None
    task_outcome = str(benchmark_status.get("task_outcome") or "").upper()
    failure_class = str(benchmark_status.get("failure_class") or "").lower()
    if not task_outcome or not failure_class:
        return None
    return {
        "task_outcome": task_outcome,
        "failure_class": failure_class,
        "valid_for_analysis": (
            "yes" if _truthy(benchmark_status.get("valid_for_analysis")) else "no"
        ),
    }


def _status_from_benchmark_status(fields: dict[str, str] | None) -> str | None:
    if not fields:
        return None
    task_outcome = fields["task_outcome"]
    failure_class = fields["failure_class"]
    if task_outcome == "PASS":
        return "✅ PASS"
    if task_outcome == "FAIL":
        return "❌ FAIL (task/model)"
    if task_outcome == "INVALID":
        return "🚫 INVALID (run conditions)"
    if task_outcome != "ERROR":
        return None
    if failure_class in {"provider_auth", "provider_rate_limit", "provider_error"}:
        return "⚠️ ERROR (provider/auth/quota)"
    if failure_class == "hardening_preflight":
        return "⚠️ ERROR (hardening/preflight)"
    if failure_class == "hardening_runtime":
        return "⚠️ ERROR (hardening/runtime)"
    if failure_class in {"verifier_timeout", "verifier_error", "artifact_missing"}:
        return "⚠️ ERROR (verifier/artifact)"
    if failure_class in {"infra_daytona", "infra_resource", "infra_timeout"}:
        return "⚠️ ERROR (infra)"
    return "⚠️ ERROR (unknown)"


def render_task_transcript_markdown(
    *,
    task_id: str,
    prompt: str,
    model: str,
    reward: float,
    answer: str,
    agent_stdout: str,
    timed_out: bool = False,
    policy: str | None = None,
    policy_events: list[dict[str, Any]] | None = None,
    pricing_model: str | None = None,
    benchmark_status: dict[str, Any] | None = None,
) -> str:
    """Render a human-readable end-to-end Markdown transcript for one task.

    This is the artifact for failure analysis: it shows the init context (the
    real model the agent ran, the API key source, the tools it had), every
    turn's reasoning, text, tool calls and tool output, and the final result —
    so a task can be read top-to-bottom without the Inspect viewer.
    """

    events = parse_claude_stream(agent_stdout)
    cost_model = pricing_model or model
    status_fields = _benchmark_status_fields(benchmark_status)
    status = _status_from_benchmark_status(status_fields)
    if status is None:
        if reward > 0:
            status = "✅ PASS"
        elif timed_out:
            status = "⏱️ TIMEOUT (agent cut at deadline)"
        elif answer == "PROVIDER_ERROR":
            status = "🔑 PROVIDER_ERROR (provider/auth failure — not a benchmark FAIL)"
        elif answer == "ERROR":
            status = "⚠️ ERROR"
        else:
            status = "❌ FAIL"

    lines: list[str] = [f"# Terminal-Bench — {task_id}", ""]
    lines.append(f"- **Result:** {status} (reward={reward}, answer={answer})")
    if status_fields:
        lines.append(
            "- **Benchmark status:** "
            f"task_outcome={status_fields['task_outcome']} "
            f"failure_class={status_fields['failure_class']} "
            f"valid_for_analysis={status_fields['valid_for_analysis']}"
        )
    lines.append(f"- **Model (labelled):** {model}")

    init = _init_event(events)
    if init:
        tools = init.get("tools") or []
        tool_text = ", ".join(str(t) for t in tools[:25])
        if len(tools) > 25:
            tool_text += f", … +{len(tools) - 25}"
        lines.append(
            f"- **Agent init:** model=`{init.get('model')}` "
            f"apiKeySource=`{init.get('apiKeySource')}` cwd=`{init.get('cwd')}`"
        )
        if tool_text:
            lines.append(f"- **Tools:** {tool_text}")

    result_event = next(
        (e for e in reversed(events) if e.get("type") == "result"), None
    )
    if result_event and any(_usage_from_event(result_event).values()):
        usage_counts = _usage_from_event(result_event)
        inp = usage_counts["input"]
        out = usage_counts["output"]
        cr = usage_counts["cache_read"]
        cw = usage_counts["cache_write"]
        cost = openrouter_cost(
            cost_model,
            input_tokens=inp,
            output_tokens=out,
            cache_read_tokens=cr,
            cache_write_tokens=cw,
        )
        cost_text = f"${cost:.4f}" if cost is not None else "unpriced"
        lines.append(
            f"- **Usage:** in={inp} out={out} cache_read={cr} "
            f"cache_write={cw} cost={cost_text}"
        )
        if result_event.get("usage_recovered"):
            lines.append("- **Usage recovered:** yes (truncated result event)")
        lines.append(
            f"- **Wall:** {result_event.get('duration_ms', '?')} ms, "
            f"turns={result_event.get('num_turns', '?')}"
        )
    else:
        recovered_usage = _sum_nonzero_turn_usage(events)
        usage = _usage_model_usage(cost_model, recovered_usage)
        if usage:
            cost_text = (
                f"${usage.total_cost:.4f}" if usage.total_cost is not None else "unpriced"
            )
            lines.append(
                f"- **Usage:** in={usage.input_tokens} out={usage.output_tokens} "
                f"cache_read={usage.input_tokens_cache_read or 0} "
                f"cache_write={usage.input_tokens_cache_write or 0} cost={cost_text}"
            )
            lines.append("- **Usage recovered:** yes (summed non-zero turn usage)")

    diagnostics = claude_stream_diagnostics(agent_stdout)
    if diagnostics["agent_stdout_final_result_event_present"]:
        result_event_status = "complete"
    elif diagnostics["agent_stdout_result_event_missing"]:
        result_event_status = "missing"
    else:
        result_event_status = "truncated"
    stream_status = (
        "malformed" if diagnostics["agent_stdout_truncated_or_malformed"] else "clean"
    )
    lines.append(
        "- **Telemetry:** "
        f"result_event={result_event_status} "
        f"usage={diagnostics['agent_model_usage_source']} "
        f"stream={stream_status}"
    )
    if (
        diagnostics["agent_model_usage_present"]
        and not diagnostics["agent_stdout_final_result_event_present"]
    ):
        lines.append(
            "  - _Valid benchmark row with best-effort usage: no complete final "
            "result event, so cost/token totals are recovered from partial events "
            "and may be incomplete._"
        )

    blocked = _structured_policy_blocks(policy_events) or extract_blocked_surfaces(
        agent_stdout, policy=policy
    )
    lines += ["", f"## Policy blocks ({len(blocked)})", ""]
    if not blocked:
        lines.append("_No hardening-policy blocks were triggered._")
    else:
        for b in blocked:
            if "surface" in b:
                target = b.get("command") or b.get("target") or b.get("path")
                target_text = f"`{target}`" if target else "(no target)"
                lines.append(f"- `{b.get('surface')}` → {target_text}")
            else:
                cmd = b.get("command") or "(unknown command)"
                lines.append(f"- `{cmd}` → {b.get('marker')}")
            snippet = (b.get("snippet") or "").strip()
            if snippet:
                lines.append(f"  - {snippet}")

    activity = stream_activity_summary(agent_stdout)
    lines.append(
        "- **Activity:** {turns} assistant turns, {tools} tool calls".format(
            turns=activity["assistant_turns"], tools=activity["tool_calls"]
        )
        + (
            f", {activity['thinking_token_updates']} internal-thinking updates"
            " (no message content — high values mean the agent spent the time"
            " reasoning/looping)"
            if activity["thinking_token_updates"]
            else ""
        )
    )

    lines += ["", "## Prompt", "", _fence(prompt), "", "## Trace", ""]

    turn = 0
    for event in events:
        etype = event.get("type")
        if etype == "assistant":
            turn += 1
            lines.append(f"### Turn {turn} — assistant")
            lines.append("")
            for block in _assistant_blocks(event):
                btype = block.get("type")
                if btype == "thinking" and block.get("thinking"):
                    lines.append("**🧠 reasoning**")
                    lines.append("")
                    for ln in _truncate(str(block["thinking"])).splitlines():
                        lines.append(f"> {ln}")
                    lines.append("")
                elif btype == "text" and block.get("text"):
                    lines.append(_truncate(str(block["text"])))
                    lines.append("")
                elif btype == "tool_use":
                    name = block.get("name", "")
                    args = block.get("input") or {}
                    command = args.get("command") if isinstance(args, dict) else None
                    lines.append(f"**🔧 tool call → `{name}`**")
                    lines.append("")
                    if command is not None:
                        lines.append(_fence(str(command), "bash"))
                    else:
                        lines.append(_fence(json.dumps(args, indent=2), "json"))
                    lines.append("")
        elif etype == "user":
            blocks = _message_dict(event).get("content") or []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    is_error = bool(block.get("is_error"))
                    label = "⛔ tool result (error)" if is_error else "↩︎ tool result"
                    lines.append(f"**{label}**")
                    lines.append("")
                    lines.append(_fence(_tool_result_text(block.get("content"))))
                    lines.append("")

    if result_event and result_event.get("result"):
        lines += ["## Final result", "", _truncate(str(result_event["result"])), ""]

    return "\n".join(lines).rstrip() + "\n"


def _structured_policy_blocks(
    policy_events: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not policy_events:
        return []
    return [
        dict(event)
        for event in policy_events
        if event.get("event_type") == "policy_block"
    ]
