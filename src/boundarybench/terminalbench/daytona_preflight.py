"""Terminal-Bench Daytona adapter for shared policy preflight."""

from __future__ import annotations

import fnmatch
import json
import shlex
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaCommandResult,
    DaytonaPolicyHardening,
    run_with_daytona_policy_hardening,
)
from boundarybench.policy_surfaces import ProbeExecution, ProbeResult
from boundarybench.policy_surfaces.preflight import (
    PREFLIGHT_SCHEMA,
    PolicyPreflightSpec,
    PolicyProofPlan,
    PolicyProofProbe,
    PreflightFailedError,
    PreflightResult,
    build_policy_proof_plan_from_spec,
    build_preflight_result,
    evaluate_policy_proof_probe,
    policy_evidence_seen as contains_preflight_policy_evidence,
    preflight_fixture_commands,
    raise_if_preflight_failed,
    unsupported_policy_probe_result,
)
from boundarybench.terminalbench.policies import HardeningPolicy


__all__ = [
    "PREFLIGHT_SCHEMA",
    "PolicyProofPlan",
    "PolicyProofProbe",
    "PreflightFailedError",
    "PreflightResult",
    "build_policy_proof_plan",
    "run_preflight",
]

_PREFLIGHT_CWD = "/home/daytona"
_POLICY_EVENT_LOG = "/tmp/boundarybench-policy-events.jsonl"


def build_policy_proof_plan(policy: HardeningPolicy) -> PolicyProofPlan:
    """Translate a Terminal-Bench hardening policy into a shared proof plan."""

    return build_policy_proof_plan_from_spec(
        PolicyPreflightSpec(
            policy=policy.name,
            overlays=policy.overlays,
            config=policy.config,
            agent_user=policy.agent_user,
            run_agent_as_root=policy.run_agent_as_root,
        )
    )


def run_preflight(
    sandbox: Any,
    *,
    policy: HardeningPolicy,
    daytona_policy_hardening: DaytonaPolicyHardening,
    cwd: str = _PREFLIGHT_CWD,
    setup_fixtures: bool = True,
) -> PreflightResult:
    """Run the selected policy proof plan before the agent starts."""

    proof_plan = build_policy_proof_plan(policy)
    if setup_fixtures:
        _install_preflight_fixtures(sandbox, proof_plan=proof_plan)

    results = tuple(
        _run_probe(
            sandbox=sandbox,
            policy=policy,
            daytona_policy_hardening=daytona_policy_hardening,
            probe=probe,
            cwd=cwd,
            enforcement_mode=policy.enforcement_mode,
        )
        for probe in proof_plan.probes
    )
    preflight = build_preflight_result(proof_plan, results)
    raise_if_preflight_failed(preflight)
    return preflight


def _run_probe(
    *,
    sandbox: Any,
    policy: HardeningPolicy,
    daytona_policy_hardening: DaytonaPolicyHardening,
    probe: PolicyProofProbe,
    cwd: str,
    enforcement_mode: str = "legacy",
) -> ProbeResult:
    if probe.unsupported_reason:
        return unsupported_policy_probe_result(probe)

    started_at = time.perf_counter()
    try:
        _clear_policy_events(sandbox)
        result = run_with_daytona_policy_hardening(
            sandbox,
            daytona_policy_hardening=daytona_policy_hardening,
            command=probe.command,
            cwd=cwd,
            timeout=probe.timeout_seconds,
            isolate_network=policy.isolate_network,
            block_network=policy.block_network,
            block_child_shell_network=policy.block_child_shell_network,
            env=probe.env or None,
            run_as_root=policy.run_agent_as_root,
            short_command=True,
            enforcement_mode=enforcement_mode,
        )
        policy_events = _read_policy_events(sandbox)
    except Exception:
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=probe.probe_id,
            phase="policy_preflight_probe",
            started_at=started_at,
            status="error",
            rule_id=probe.rule_id,
            surface=probe.surface,
        )
        raise

    matching_events = _matching_policy_events(probe, policy_events)
    if _exec_path_target_unavailable(probe, result):
        evaluated = replace(
            probe,
            required_for_benchmark=False,
            policy_evidence_required=False,
        ).to_probe_result(
            observed="not_applicable",
            status="not_applicable",
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            message="absolute executable target is not present in this task image",
        )
        _print_phase_timing(
            component="terminalbench_daytona",
            identifier=probe.probe_id,
            phase="policy_preflight_probe",
            started_at=started_at,
            status=evaluated.status,
            rule_id=probe.rule_id,
            surface=probe.surface,
            exit_code=result.exit_code,
            policy_evidence_seen=evaluated.policy_evidence_seen,
        )
        return evaluated

    execution = ProbeExecution(
        case_id=probe.probe_id,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        policy_evidence_seen=(
            None
            if not probe.policy_evidence_required
            else contains_preflight_policy_evidence(
                result.stdout,
                result.stderr,
                block_message=daytona_policy_hardening.block_message,
            )
            or bool(matching_events)
        ),
        policy_evidence_id=(
            None if not matching_events else str(matching_events[0].get("event_type"))
        ),
        metadata={
            "runner": "daytona_policy_hardening_preflight",
            "rule_id": probe.rule_id,
            "probe_id": probe.probe_id,
            "policy_events": list(matching_events[:5]),
            "unmatched_policy_events": [
                event for event in policy_events if event not in matching_events
            ][:5],
        },
    )
    evaluated = evaluate_policy_proof_probe(probe, execution)
    _print_phase_timing(
        component="terminalbench_daytona",
        identifier=probe.probe_id,
        phase="policy_preflight_probe",
        started_at=started_at,
        status=evaluated.status,
        rule_id=probe.rule_id,
        surface=probe.surface,
        exit_code=result.exit_code,
        policy_evidence_seen=evaluated.policy_evidence_seen,
    )
    return evaluated


def _install_preflight_fixtures(
    sandbox: Any, *, proof_plan: PolicyProofPlan
) -> None:
    command = " && ".join(preflight_fixture_commands(proof_plan))
    if not command:
        return
    result = sandbox.process.exec(command, timeout=30)
    if getattr(result, "exit_code", 1) != 0:
        failed = PreflightResult(
            passed=False,
            proof_plan=proof_plan,
            results=(),
            failed_probes=(),
        )
        output = getattr(result, "result", "") or ""
        raise PreflightFailedError(
            f"preflight fixture setup failed: {output}", result=failed
        )


def _print_phase_timing(
    *,
    component: str,
    identifier: str,
    phase: str,
    started_at: float,
    status: str,
    **fields: object,
) -> None:
    elapsed_ms = max(0, int((time.perf_counter() - started_at) * 1000))
    details = " ".join(
        f"{key}={_phase_timing_value(value)}" for key, value in fields.items()
    )
    suffix = f" {details}" if details else ""
    print(
        "phase_timing "
        f"component={component} "
        f"id={_phase_timing_value(identifier)} "
        f"phase={phase} "
        f"elapsed_ms={elapsed_ms} "
        f"status={status}"
        f"{suffix}",
        flush=True,
    )


def _phase_timing_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value).replace(" ", "_")


def _clear_policy_events(sandbox: Any) -> None:
    try:
        sandbox.process.exec(f"rm -f {shlex.quote(_POLICY_EVENT_LOG)}", timeout=15)
    except Exception:
        pass


def _read_policy_events(sandbox: Any) -> tuple[dict[str, Any], ...]:
    try:
        result = sandbox.process.exec(
            f"cat {shlex.quote(_POLICY_EVENT_LOG)} 2>/dev/null || true",
            timeout=15,
        )
    except Exception:
        return ()
    output = getattr(result, "result", "") or ""
    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return tuple(events)


def _matching_policy_events(
    probe: PolicyProofProbe, events: tuple[dict[str, Any], ...]
) -> tuple[dict[str, Any], ...]:
    matches: list[dict[str, Any]] = []
    rule_target = _rule_target(probe.rule_id)
    for event in events:
        surface = event.get("surface")
        event_target = event.get("target")
        event_command = event.get("command")
        if probe.surface == "command":
            if surface == "command" and event_command == rule_target:
                matches.append(event)
        elif probe.surface == "exec-path":
            if surface == "command" and event_command == Path(rule_target).name:
                matches.append(event)
        elif probe.surface == "file-read":
            if surface == "path" and _path_event_matches(rule_target, event_target):
                matches.append(event)
        elif probe.surface == "file-write":
            if surface == "tee_write" and _pattern_event_matches(
                rule_target, event_target
            ):
                matches.append(event)
        elif probe.surface == "network":
            if surface == "network" and event_target in {"connect", "sendto", "sendmsg"}:
                matches.append(event)
    return tuple(matches)


def _rule_target(rule_id: str) -> str:
    if ":" not in rule_id:
        return rule_id
    return rule_id.split(":", 1)[1]


def _path_event_matches(rule_target: str, event_target: Any) -> bool:
    if not isinstance(event_target, str):
        return False
    if event_target == rule_target:
        return True
    normalized = rule_target.rstrip("/")
    return bool(normalized) and event_target.startswith(normalized + "/")


def _pattern_event_matches(rule_target: str, event_target: Any) -> bool:
    if not isinstance(event_target, str):
        return False
    if event_target == rule_target:
        return True
    return fnmatch.fnmatch(event_target, rule_target)


def _exec_path_target_unavailable(
    probe: PolicyProofProbe, result: DaytonaCommandResult
) -> bool:
    if probe.surface != "exec-path" or result.exit_code != 127:
        return False
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "no such file or directory" in output
