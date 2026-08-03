"""Outcome-blind post-run identification of policy blockages.

The selected N/F/P policy is the source of truth for whether stored evidence
represents a blockage. Target-level errors are collapsed only when the
canonical trace resolves them to one unique tool call. Ambiguous and unlinked
events stay separate so this analysis never invents action attribution.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from boundarybench.daytona.policy_axes import AXIS_PRESETS
from boundarybench.daytona.policy_telemetry import NFTABLES_OBSERVER


POLICY_BLOCKAGE_ANALYSIS_VERSION = "policy-blockages/v3"
COUNTED_EVENT_TYPES = {"policy_block", "policy_block_inferred"}
NETWORK_NATIVE_ERRORS = {"connection_refused", "dns_failure", "http_403"}
MAX_BLOCKED_TRIAL_LEDGER_BYTES = 512 * 1024
POLICY_AXES = ("network", "filesystem", "privilege")
_AXIS_METRICS = ("hit_event_count", "hit_occurrence_count", "blocked_trial_count")
POLICY_BLOCKAGE_ANALYSIS_ROW_FIELDS = (
    "analysis_version",
    "evidence_status",
    "policy_hit_event_count",
    "policy_hit_occurrence_count",
    "blocked_trial_count",
    "blocked_trial_exact_tool_call_count",
    "blocked_trial_ambiguous_trace_event_count",
    "blocked_trial_run_only_event_count",
    *(f"{axis}_{metric}" for axis in POLICY_AXES for metric in _AXIS_METRICS),
    "blocked_trials_json",
    "blocked_trials_json_truncated",
)


@dataclass(frozen=True)
class PolicyHit:
    run_id: str
    task_id: str
    policy: str
    event_index: int
    event_type: str
    axis: str
    axis_level: str
    surface: str
    target: str
    operation: str
    observer: str
    native_error: str
    occurrences: int
    evidence_role: str
    trace_event_seqs: tuple[int, ...]
    trace_action_id: str
    tool_call_seq: int | None
    tool_result_seqs: tuple[int, ...]
    tool_name: str
    tool_command: str
    trace_resolution: str

    def to_row(self, *, replicate: int) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "policy": self.policy,
            "replicate": replicate,
            "run_id": self.run_id,
            "event_index": self.event_index,
            "event_type": self.event_type,
            "axis": self.axis,
            "axis_level": self.axis_level,
            "surface": self.surface,
            "target": self.target,
            "operation": self.operation,
            "observer": self.observer,
            "native_error": self.native_error,
            "occurrences": self.occurrences,
            "evidence_role": self.evidence_role,
            "trace_event_seqs": json.dumps(self.trace_event_seqs),
            "trace_action_id": self.trace_action_id,
            "tool_call_seq": self.tool_call_seq,
            "tool_result_seqs": json.dumps(self.tool_result_seqs),
            "tool_name": self.tool_name,
            "tool_command": self.tool_command,
            "trace_resolution": self.trace_resolution,
        }


@dataclass(frozen=True)
class BlockedTrial:
    """One exact blocked tool call or one conservatively retained policy event."""

    run_id: str
    task_id: str
    policy: str
    blocked_trial_id: str
    attribution_level: str
    trace_action_id: str
    tool_call_seq: int | None
    tool_result_seqs: tuple[int, ...]
    trace_event_seqs: tuple[int, ...]
    tool_name: str
    tool_command: str
    trace_resolution: str
    event_indexes: tuple[int, ...]
    axes: tuple[str, ...]
    surfaces: tuple[str, ...]
    target_count: int
    target_examples: tuple[str, ...]
    error_event_count: int
    error_occurrence_count: int

    def to_row(self, *, replicate: int) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "policy": self.policy,
            "replicate": replicate,
            "run_id": self.run_id,
            **self.to_compact_mapping(),
            "tool_command": self.tool_command,
            "target_examples": json.dumps(self.target_examples),
        }

    def to_compact_mapping(self) -> dict[str, Any]:
        """Return the bounded per-blockage payload exported to BigQuery."""

        return {
            "blocked_trial_id": self.blocked_trial_id,
            "attribution_level": self.attribution_level,
            "trace_action_id": self.trace_action_id or None,
            "tool_call_seq": self.tool_call_seq,
            "tool_result_seqs": list(self.tool_result_seqs),
            "trace_event_seqs": list(self.trace_event_seqs),
            "tool_name": self.tool_name or None,
            "trace_resolution": self.trace_resolution,
            "event_indexes": list(self.event_indexes),
            "axes": list(self.axes),
            "surfaces": list(self.surfaces),
            "target_count": self.target_count,
            "error_event_count": self.error_event_count,
            "error_occurrence_count": self.error_occurrence_count,
        }


@dataclass(frozen=True)
class PolicyBlockageAnalysis:
    hits: tuple[PolicyHit, ...]
    trials: tuple[BlockedTrial, ...]
    excluded_event_count: int
    inactive_axis_event_count: int
    unknown_axis_event_count: int
    duplicate_evidence_event_count: int
    possible_echo_event_count: int
    ambiguous_network_event_count: int
    probe_contaminated_counter_event_count: int
    probe_contaminated_counter_observed_packets: int
    evidence_status: str
    trace_complete: bool
    trace_truncated: bool
    policy_event_truncated: bool

    @property
    def hit_count(self) -> int:
        return sum(hit.occurrences for hit in self.hits)

    @property
    def blocked_trial_count(self) -> int:
        return len(self.trials)

    def axis_counts(self) -> dict[str, dict[str, int]]:
        return axis_rollup(self.hits, self.trials)

    def analysis_row_fields(self) -> dict[str, Any]:
        """Analysis fields of one policy_blockage_analysis table row."""

        metadata = self.to_metadata_mapping()
        ledger_json, ledger_truncated = _bounded_trial_ledger_json(self.trials)
        fields: dict[str, Any] = {
            "analysis_version": metadata["version"],
            "evidence_status": self.evidence_status,
            "policy_hit_event_count": metadata["policy_hit_event_count"],
            "policy_hit_occurrence_count": metadata["policy_hit_occurrence_count"],
            "blocked_trial_count": metadata["blocked_trial_count"],
            "blocked_trial_exact_tool_call_count": metadata["attribution_counts"][
                "exact_tool_call"
            ],
            "blocked_trial_ambiguous_trace_event_count": metadata["attribution_counts"][
                "ambiguous_trace_policy_event"
            ],
            "blocked_trial_run_only_event_count": metadata["attribution_counts"][
                "run_only_policy_event"
            ],
            "blocked_trials_json": ledger_json,
            "blocked_trials_json_truncated": ledger_truncated,
        }
        for axis, counts in self.axis_counts().items():
            for metric in _AXIS_METRICS:
                fields[f"{axis}_{metric}"] = counts[metric]
        return fields

    def to_metadata_mapping(self) -> dict[str, Any]:
        """Return summary metadata without duplicating the BigQuery ledger."""

        attribution_counts = defaultdict(int)
        for trial in self.trials:
            attribution_counts[trial.attribution_level] += 1
        return {
            "version": POLICY_BLOCKAGE_ANALYSIS_VERSION,
            "evidence_status": self.evidence_status,
            "policy_hit_event_count": len(self.hits),
            "policy_hit_occurrence_count": self.hit_count,
            "blocked_trial_count": self.blocked_trial_count,
            "attribution_counts": {
                "exact_tool_call": attribution_counts["exact_tool_call"],
                "ambiguous_trace_policy_event": attribution_counts[
                    "ambiguous_trace_policy_event"
                ],
                "run_only_policy_event": attribution_counts["run_only_policy_event"],
            },
            "excluded_counts": {
                "unsupported_event": self.excluded_event_count,
                "inactive_axis": self.inactive_axis_event_count,
                "unknown_axis": self.unknown_axis_event_count,
                "duplicate_evidence": self.duplicate_evidence_event_count,
                "possible_echo": self.possible_echo_event_count,
                "ambiguous_network": self.ambiguous_network_event_count,
                "probe_contaminated_counter": (
                    self.probe_contaminated_counter_event_count
                ),
                "probe_contaminated_packets": (
                    self.probe_contaminated_counter_observed_packets
                ),
            },
        }


def axis_rollup(
    hits: Sequence[PolicyHit], trials: Sequence[BlockedTrial]
) -> dict[str, dict[str, int]]:
    """Per-axis counts; see the POLICY_AXES note for the sum identities."""

    counts = {axis: dict.fromkeys(_AXIS_METRICS, 0) for axis in POLICY_AXES}
    for hit in hits:
        bucket = counts.get(hit.axis)
        if bucket is None:
            continue
        bucket["hit_event_count"] += 1
        bucket["hit_occurrence_count"] += hit.occurrences
    for trial in trials:
        for axis in trial.axes:
            bucket = counts.get(axis)
            if bucket is None:
                continue
            bucket["blocked_trial_count"] += 1
    return counts


def axis_level(policy: str, axis: str) -> str | None:
    preset = AXIS_PRESETS.get(policy)
    if preset is None:
        raise ValueError(f"unknown policy {policy!r}")
    return {
        "network": preset.network.value,
        "filesystem": preset.filesystem.value,
        "privilege": preset.privilege.value,
    }.get(axis)


def axis_is_blocking(policy: str, axis: str) -> bool:
    return _level_is_blocking(axis_level(policy, axis))


def _level_is_blocking(level: str | None) -> bool:
    if not level or len(level) < 2:
        return False
    try:
        return int(level[1:]) > 0
    except ValueError:
        return False


def analyze_policy_blockages(
    *,
    policy: str,
    policy_events: Sequence[Any],
    policy_events_available: bool = True,
    full_trace: Mapping[str, Any] | None = None,
    run_id: str = "",
    task_id: str = "",
) -> PolicyBlockageAnalysis:
    """Identify policy-matched blockages without consulting task outcome."""

    if policy not in AXIS_PRESETS:
        raise ValueError(f"unknown policy {policy!r}")

    trace = full_trace if isinstance(full_trace, Mapping) else {}
    trace_policy_events = trace.get("policy_events") or []
    if not isinstance(trace_policy_events, list):
        trace_policy_events = []
    canonical_events = trace.get("events") or []
    if not isinstance(canonical_events, list):
        canonical_events = []
    observability = trace.get("observability") or {}
    if not isinstance(observability, Mapping):
        observability = {}

    hits: list[PolicyHit] = []
    excluded = 0
    inactive_axis = 0
    unknown_axis = 0
    duplicate_evidence = 0
    possible_echo = 0
    ambiguous_network = 0
    probe_counter_events = 0
    probe_counter_packets = 0
    trace_index = _index_canonical_events(canonical_events)
    trace_events_by_id: dict[str, Mapping[str, Any]] = {}
    duplicate_trace_ids: set[str] = set()
    for trace_event in trace_policy_events:
        if not isinstance(trace_event, Mapping):
            continue
        trace_event_id = str(trace_event.get("policy_event_id") or "")
        if not trace_event_id:
            continue
        if trace_event_id in trace_events_by_id:
            duplicate_trace_ids.add(trace_event_id)
        else:
            trace_events_by_id[trace_event_id] = trace_event
    for trace_event_id in duplicate_trace_ids:
        del trace_events_by_id[trace_event_id]
    use_positional_fallback = not trace_events_by_id and not duplicate_trace_ids
    trace_cursor = 0
    for index, raw_event in enumerate(policy_events):
        if not isinstance(raw_event, Mapping):
            excluded += 1
            continue
        candidate_index = trace_cursor
        trace_cursor += 1
        event_type = str(raw_event.get("event_type") or "")
        if event_type not in COUNTED_EVENT_TYPES:
            excluded += 1
            continue
        axis = str(raw_event.get("axis") or "")
        level = axis_level(policy, axis)
        if level is None:
            unknown_axis += 1
            continue
        if not _level_is_blocking(level):
            inactive_axis += 1
            continue

        candidate: Mapping[str, Any] | None
        if use_positional_fallback:
            positional = (
                trace_policy_events[candidate_index]
                if candidate_index < len(trace_policy_events)
                else None
            )
            candidate = positional if isinstance(positional, Mapping) else None
        else:
            candidate = trace_events_by_id.get(f"policy-{index:04d}")
        event_for_display = (
            candidate
            if isinstance(candidate, Mapping) and not candidate.get("truncated")
            else raw_event
        )
        trace_event_seqs = _trace_event_seqs(event_for_display)
        trace_action = _resolve_trace_action(trace_index, trace_event_seqs)
        observer = str(raw_event.get("observer") or "")
        native_error = str(raw_event.get("native_error") or "")
        observed_count = _positive_count(raw_event.get("hit_count"))

        if event_type == "policy_block" and observer == NFTABLES_OBSERVER:
            probe_counter_events += 1
            probe_counter_packets += observed_count
            continue

        if event_type == "policy_block_inferred":
            if raw_event.get("superseded_by"):
                duplicate_evidence += 1
                continue
            if (
                axis == "network"
                and native_error.casefold() not in NETWORK_NATIVE_ERRORS
            ):
                ambiguous_network += 1
                continue
            evidence_role = "policy-matched-native-denial"
        else:
            evidence_role = "authoritative-policy-event"

        hits.append(
            PolicyHit(
                run_id=run_id,
                task_id=task_id,
                policy=policy,
                event_index=index,
                event_type=event_type,
                axis=axis,
                axis_level=level or "",
                surface=str(raw_event.get("surface") or ""),
                target=str(raw_event.get("target") or ""),
                operation=_operation(event_for_display),
                observer=observer,
                native_error=native_error,
                occurrences=observed_count,
                evidence_role=evidence_role,
                trace_event_seqs=trace_event_seqs,
                trace_action_id=trace_action[0],
                tool_call_seq=trace_action[1],
                tool_result_seqs=trace_action[2],
                tool_name=trace_action[3],
                tool_command=trace_action[4],
                trace_resolution=trace_action[5],
            )
        )

    authoritative_axes: dict[str, set[str]] = {}
    for hit in hits:
        if hit.event_type == "policy_block":
            actions = authoritative_axes.setdefault(hit.axis, set())
            if hit.trace_action_id:
                actions.add(hit.trace_action_id)
    if authoritative_axes:
        retained: list[PolicyHit] = []
        for hit in hits:
            covered_actions = authoritative_axes.get(hit.axis)
            is_possible_echo = (
                hit.event_type == "policy_block_inferred"
                and covered_actions is not None
                and (
                    not hit.trace_action_id
                    or hit.trace_action_id in covered_actions
                )
            )
            if is_possible_echo:
                possible_echo += 1
                continue
            retained.append(hit)
        hits = retained

    trials = _group_blocked_trials(hits)
    policy_event_truncated = any(
        isinstance(event, Mapping) and bool(event.get("truncated"))
        for event in trace_policy_events
    )
    trace_complete = observability.get("complete") is True
    trace_truncated = bool(observability.get("truncated"))
    if not policy_events_available:
        evidence_status = "unavailable"
    elif trace_complete and not trace_truncated and not policy_event_truncated:
        evidence_status = "complete"
    elif policy_events or trace:
        evidence_status = "partial"
    else:
        evidence_status = "unavailable"

    return PolicyBlockageAnalysis(
        hits=tuple(hits),
        trials=trials,
        excluded_event_count=excluded,
        inactive_axis_event_count=inactive_axis,
        unknown_axis_event_count=unknown_axis,
        duplicate_evidence_event_count=duplicate_evidence,
        possible_echo_event_count=possible_echo,
        ambiguous_network_event_count=ambiguous_network,
        probe_contaminated_counter_event_count=probe_counter_events,
        probe_contaminated_counter_observed_packets=probe_counter_packets,
        evidence_status=evidence_status,
        trace_complete=trace_complete,
        trace_truncated=trace_truncated,
        policy_event_truncated=policy_event_truncated,
    )


def _group_blocked_trials(hits: Sequence[PolicyHit]) -> tuple[BlockedTrial, ...]:
    grouped: dict[tuple[str, str], list[PolicyHit]] = defaultdict(list)
    for hit in hits:
        if hit.trace_action_id:
            key = ("exact_tool_call", hit.trace_action_id)
        elif hit.trace_event_seqs:
            key = ("ambiguous_trace_policy_event", f"event-{hit.event_index:04d}")
        else:
            key = ("run_only_policy_event", f"event-{hit.event_index:04d}")
        grouped[key].append(hit)

    trials: list[BlockedTrial] = []
    for (attribution_level, action_key), grouped_hits in grouped.items():
        ordered = sorted(grouped_hits, key=lambda hit: hit.event_index)
        first = ordered[0]
        targets = tuple(sorted({hit.target for hit in ordered if hit.target}))
        trials.append(
            BlockedTrial(
                run_id=first.run_id,
                task_id=first.task_id,
                policy=first.policy,
                blocked_trial_id=(
                    f"tool-call:{action_key}"
                    if attribution_level == "exact_tool_call"
                    else f"policy-event:{first.event_index:04d}"
                ),
                attribution_level=attribution_level,
                trace_action_id=first.trace_action_id,
                tool_call_seq=first.tool_call_seq,
                tool_result_seqs=tuple(
                    sorted({seq for hit in ordered for seq in hit.tool_result_seqs})
                ),
                trace_event_seqs=tuple(
                    sorted({seq for hit in ordered for seq in hit.trace_event_seqs})
                ),
                tool_name=first.tool_name,
                tool_command=first.tool_command or first.operation,
                trace_resolution=first.trace_resolution,
                event_indexes=tuple(hit.event_index for hit in ordered),
                axes=tuple(sorted({hit.axis for hit in ordered if hit.axis})),
                surfaces=tuple(sorted({hit.surface for hit in ordered if hit.surface})),
                target_count=len(targets),
                target_examples=targets[:10],
                error_event_count=len(ordered),
                error_occurrence_count=sum(hit.occurrences for hit in ordered),
            )
        )
    return tuple(
        sorted(
            trials,
            key=lambda trial: (
                min(trial.event_indexes),
                trial.attribution_level,
                trial.blocked_trial_id,
            ),
        )
    )


def _bounded_trial_ledger_json(
    trials: Sequence[BlockedTrial],
    *,
    max_bytes: int = MAX_BLOCKED_TRIAL_LEDGER_BYTES,
) -> tuple[str, bool]:
    """Encode a valid compact ledger without unbounded BigQuery row growth."""

    if max_bytes < 2:
        raise ValueError("max_bytes must allow an empty JSON array")
    mappings: list[dict[str, Any]] = []
    encoded_size = 2
    for trial in trials:
        mapping = trial.to_compact_mapping()
        encoded = json.dumps(
            mapping,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        added_size = len(encoded) + (1 if mappings else 0)
        if encoded_size + added_size > max_bytes:
            break
        mappings.append(mapping)
        encoded_size += added_size
    return (
        json.dumps(mappings, ensure_ascii=False, separators=(",", ":")),
        len(mappings) != len(trials),
    )


MAX_OCCURRENCES_PER_EVENT = 1_000_000


def _positive_count(value: Any) -> int:
    if isinstance(value, bool):
        return 1
    try:
        numeric = int(value)
    except (TypeError, ValueError, OverflowError):
        return 1
    if numeric < 1:
        return 1
    return min(numeric, MAX_OCCURRENCES_PER_EVENT)


def _trace_event_seqs(event: Mapping[str, Any]) -> tuple[int, ...]:
    values = event.get("trace_event_seqs") or []
    if not isinstance(values, list):
        return ()
    return tuple(value for value in values if isinstance(value, int) and value >= 0)


@dataclass(frozen=True)
class _TraceIndex:
    """Canonical-trace lookups built once per analysis, not per policy event."""

    by_seq: Mapping[int, Mapping[str, Any]]
    by_call_id: Mapping[str, tuple[Mapping[str, Any], ...]]


def _index_canonical_events(canonical_events: Sequence[Any]) -> _TraceIndex:
    events = [event for event in canonical_events if isinstance(event, Mapping)]
    by_seq = {
        event.get("seq"): event for event in events if isinstance(event.get("seq"), int)
    }
    by_call_id: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        call_id = str(event.get("tool_call_id") or "")
        if call_id:
            by_call_id[call_id].append(event)
    return _TraceIndex(
        by_seq=by_seq,
        by_call_id={key: tuple(value) for key, value in by_call_id.items()},
    )


def _resolve_trace_action(
    trace_index: _TraceIndex, trace_event_seqs: Sequence[int]
) -> tuple[str, int | None, tuple[int, ...], str, str, str]:
    if not trace_event_seqs:
        return "", None, (), "", "", "unlinked"

    by_seq = trace_index.by_seq
    linked = [by_seq[seq] for seq in trace_event_seqs if seq in by_seq]
    call_ids = {
        str(event.get("tool_call_id")) for event in linked if event.get("tool_call_id")
    }
    if not call_ids:
        return "", None, (), "", "", "trace_event_without_tool_call_id"
    if len(call_ids) != 1:
        return "", None, (), "", "", "ambiguous_multiple_tool_calls"

    action_id = next(iter(call_ids))
    action_events = trace_index.by_call_id.get(action_id, ())
    calls = [event for event in action_events if event.get("type") == "tool_call"]
    if len(calls) != 1:
        return "", None, (), "", "", "single_tool_call_id_without_unique_call"
    call = calls[0]
    return (
        action_id,
        call.get("seq") if isinstance(call.get("seq"), int) else None,
        tuple(
            sorted(
                event["seq"]
                for event in action_events
                if event.get("type") == "tool_result"
                and isinstance(event.get("seq"), int)
            )
        ),
        str(call.get("tool_name") or ""),
        _tool_command(call),
        "exact_tool_call",
    )


def _tool_command(call: Mapping[str, Any]) -> str:
    arguments = call.get("arguments")
    if isinstance(arguments, Mapping) and arguments.get("command"):
        return str(arguments["command"])[:2_000]
    if arguments:
        try:
            return json.dumps(arguments, ensure_ascii=False, sort_keys=True)[:2_000]
        except (TypeError, ValueError):
            return str(arguments)[:2_000]
    return ""


def _operation(event: Mapping[str, Any]) -> str:
    for key in ("command", "exec_path", "path", "target"):
        value = event.get(key)
        if value:
            return str(value)[:2_000]
    return ""
