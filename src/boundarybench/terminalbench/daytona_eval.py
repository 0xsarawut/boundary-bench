"""Inspect task that runs Terminal-Bench tasks in hardened Daytona sandboxes.

Each sample provisions a Daytona sandbox from the task's own Docker image, runs
the agent (Claude Code driving an OpenRouter model) under the policy-hardening
boundary, and scores with Harbor's official verifier. Because this is a real
Inspect task, `inspect eval` writes a standard `.eval` log (to GCS via
`--log-dir gs://...`) that the hosted Inspect viewer can read.

The Inspect-level model is nominal: the solver does not call `generate()`; the
real agent is Claude Code inside Daytona. Pass `--model mockllm/model`.
"""

from __future__ import annotations

import asyncio
import functools
import os
import re
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput, ModelUsage
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, Solver, TaskState, solver

import boundarybench.benchmarks.common.daytona as benchmark_daytona
from boundarybench.benchmarks.common.status_taxonomy import (
    DAYTONA_CONNECTION_MARKERS,
    DAYTONA_LIFECYCLE_MARKERS,
    RESOURCE_FAILURE_MARKERS,
    attach_benchmark_status,
)
from boundarybench.provenance import runtime_provenance
from boundarybench.terminalbench.daytona import (
    DaytonaVerifierResult,
    VERIFIER_OBSERVATION_PROCESS_STARTED,
    VERIFIER_OBSERVATION_TESTS_UPLOADED_AFTER_AGENT,
    load_terminalbench_daytona_bundle,
    run_daytona_harbor_verifier,
    verifier_max_attempts,
)
from boundarybench.terminalbench.daytona_transcript import (
    ProviderErrorInfo,
)
from boundarybench.terminalbench.daytona_constants import (
    DEFAULT_AGENT_WORKDIR,
    DEFAULT_OPENROUTER_MODEL,
)
from boundarybench.terminalbench.task_config import (
    AgentProcessDispositionResolution,
    AgentSessionLifecycleResolution,
    HarborVerifierEnvironmentResolution,
    DaytonaVerifierLifecycleResolution,
    resolve_agent_process_disposition,
    resolve_agent_session_lifecycle,
    resolve_daytona_verifier_lifecycle,
    resolve_terminalbench_workspace,
    terminalbench_workspace_from_bundle,
)
from boundarybench.terminalbench.daytona_preflight import (
    PreflightFailedError,
    run_preflight,
)
from boundarybench.daytona.apparmor_capability import (
    run_apparmor_capability_probe,
    unique_apparmor_probe_profile_name,
)
from boundarybench.harness.claims import HardeningClaims
from boundarybench.harness.adapter import (
    effort_level_source,
    normalize_effort_level,
)
from boundarybench.harness.registry import DEFAULT_HARNESS, get_harness_adapter
from boundarybench.harness.secrets import provider_api_key_from_managed_env
from boundarybench.terminalbench.daytona_run import (
    AGENT_LISTENER_PROBE_COMMAND,
    cleanup_verifier_artifacts,
    daytona_task_resource_attempts,
    export_verifier_artifacts,
    import_verifier_artifacts,
    _print_phase_timing,
    provision_clean_verifier_sandbox,
    provision_hardened_task_sandbox,
    read_agent_version,
    _run_harness_post_agent_cleanup,
    run_terminalbench_agent_in_daytona as run_terminalbench_task_in_daytona,
    _run_with_phase_timing_capture,
    _sandbox_id,
    task_docker_image,
    TerminalBenchAgentRunResult,
    TerminalBenchRunResult,
)
from boundarybench.daytona.runtime_policy_probes import (
    DaytonaRuntimeProbeSuiteError,
    RUNTIME_POLICY_PROBE_WORKSPACE,
    ensure_runtime_policy_probe_suite_passed,
    run_runtime_policy_probe_suite_in_sandbox,
)
from boundarybench.daytona.agentsh_session import (
    prepare_daytona_agentsh_session,
)
from boundarybench.terminalbench.harbor import DEFAULT_TERMINAL_BENCH_2_1_REF
from boundarybench.terminalbench.custom_policy import compile_custom_policy
from boundarybench.terminalbench.task_applicability import (
    NOT_APPLICABLE,
    all_task_ids,
    applicability_metadata,
    policy_applicability,
    policy_applicability_reason,
)
from boundarybench.terminalbench.policies import (
    DEFAULT_POLICY_NAME,
    resolve_policy,
    resolve_policy_for_run,
)
from boundarybench.terminalbench.policy_prompt import (
    POLICY_PROMPT_OFF,
    POLICY_PROMPT_ON,
    build_policy_prompt_provenance,
    render_policy_prompt,
    validate_policy_prompt,
)
from boundarybench.terminalbench.recovery_skill import (
    RECOVERY_BUNDLE_OFF,
    RECOVERY_BUNDLE_ON,
    build_recovery_bundle_provenance,
    render_recovery_bundle,
    validate_recovery_bundle,
)
from boundarybench.daytona.hardening_config import (
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
    DaytonaHardeningConfig,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)

_HARBOR_LOAD_LOCK = threading.Lock()


DEFAULT_TASK_MAX_ATTEMPTS = 3
TRANSIENT_RETRY_BACKOFF_SEC = 5
DEFAULT_AGENT_TIMEOUT_SEC = benchmark_daytona.DEFAULT_AGENT_TIMEOUT_SEC
DAYTONA_MAX_PARALLEL = benchmark_daytona.DAYTONA_MAX_PARALLEL
APPARMOR_CAPABILITY_PROBE_ENV = "BOUNDARYBENCH_APPARMOR_CAPABILITY_PROBE"
max_concurrent = benchmark_daytona.max_concurrent
_UNSCORED_INFRA_FAILURE_CLASSES = {
    "infra_daytona",
    "infra_resource",
    "infra_timeout",
    "verifier_timeout",
    "verifier_error",
}


def _native_model_usage(accounting: dict[str, Any] | None) -> ModelUsage | None:
    """Build a ModelUsage from the OpenRouter accounting-proxy summary.

    Returns None when the proxy captured no responses, so callers fall back to
    the harness adapter's own usage. ``total_cost`` is OpenRouter's native
    charged cost — extracted, not computed from a list price.
    """

    if not accounting or not accounting.get("records"):
        return None
    input_tokens = int(accounting.get("input_tokens") or 0)
    output_tokens = int(accounting.get("output_tokens") or 0)
    cache_read = int(accounting.get("cache_read_tokens") or 0)
    cache_write = int(accounting.get("cache_write_tokens") or 0)
    cost = accounting.get("cost")
    cost_complete = accounting.get("cost_complete") is True
    total_cost = (
        float(cost)
        if cost_complete
        and isinstance(cost, (int, float))
        and not isinstance(cost, bool)
        else None
    )
    return ModelUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=int(
            accounting.get("total_tokens") or (input_tokens + output_tokens)
        ),
        input_tokens_cache_read=cache_read or None,
        input_tokens_cache_write=cache_write or None,
        total_cost=total_cost,
    )


def _merge_native_accounting(
    accumulated: dict[str, Any] | None,
    current: Any,
) -> dict[str, Any] | None:
    """Accumulate proxy accounting across charged task attempts.

    Retried attempts are separately provisioned but still billed. Preserve all
    captured records and token/cache totals. A cost is trustworthy only when
    every contributing summary explicitly reports the real boolean ``True`` for
    ``cost_complete`` and supplies a numeric cost.
    """

    if not isinstance(current, dict):
        return accumulated
    raw_record_count = current.get("records")
    record_count = (
        raw_record_count
        if isinstance(raw_record_count, int) and not isinstance(raw_record_count, bool)
        else 0
    )
    if record_count <= 0:
        return accumulated

    prior = accumulated or {}

    def numeric(value: Any) -> int | float:
        return (
            value
            if isinstance(value, (int, float)) and not isinstance(value, bool)
            else 0
        )

    input_tokens = int(numeric(prior.get("input_tokens"))) + int(
        numeric(current.get("input_tokens"))
    )
    output_tokens = int(numeric(prior.get("output_tokens"))) + int(
        numeric(current.get("output_tokens"))
    )
    current_cost = current.get("cost")
    prior_cost = prior.get("cost")
    cost = float(numeric(prior_cost)) + float(numeric(current_cost))
    current_cost_complete = (
        current.get("cost_complete") is True
        and isinstance(current_cost, (int, float))
        and not isinstance(current_cost, bool)
    )
    prior_cost_complete = (
        True if accumulated is None else prior.get("cost_complete") is True
    )
    return {
        "records": int(numeric(prior.get("records"))) + record_count,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": int(numeric(prior.get("cache_read_tokens")))
        + int(numeric(current.get("cache_read_tokens"))),
        "cache_write_tokens": int(numeric(prior.get("cache_write_tokens")))
        + int(numeric(current.get("cache_write_tokens"))),
        "total_tokens": input_tokens + output_tokens,
        "cost": cost,
        "cost_complete": prior_cost_complete and current_cost_complete,
    }


def _env_agent_timeout() -> int:
    return benchmark_daytona.env_agent_timeout()


def _env_policy() -> str:
    return os.environ.get("BOUNDARYBENCH_POLICY") or DEFAULT_POLICY_NAME


def _env_block_message() -> str | None:
    return os.environ.get("BOUNDARYBENCH_POLICY_BLOCK_MESSAGE")


def _env_task_max_attempts() -> int:
    raw = os.environ.get("BOUNDARYBENCH_TASK_MAX_ATTEMPTS")
    return max(1, int(raw)) if raw else DEFAULT_TASK_MAX_ATTEMPTS


def _apparmor_capability_probe_enabled() -> bool:
    return os.environ.get(APPARMOR_CAPABILITY_PROBE_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _runner_executor() -> ThreadPoolExecutor:
    return benchmark_daytona.runner_executor("tb-runner")


def shutdown_runner_executor(*, wait: bool = True) -> None:
    """Release the runner pool so a batch job cannot leave worker threads open."""

    benchmark_daytona.shutdown_runner_executor("tb-runner", wait=wait)


class _TransientTaskAttempt(RuntimeError):
    """An attempt failed before model capability was meaningfully measured."""

    def __init__(
        self, message: str, *, result: TerminalBenchRunResult | None = None
    ) -> None:
        super().__init__(message)
        self.result = result


class _PostAgentVerifierError(RuntimeError):
    """A non-retryable verifier failure after the sealed agent phase."""

    def __init__(
        self,
        message: str,
        *,
        result: TerminalBenchAgentRunResult | TerminalBenchRunResult,
        postflight_verification: dict[str, Any],
        submission_snapshot: dict[str, Any] | None,
    ) -> None:
        super().__init__(message)
        self.result = result
        self.postflight_verification = postflight_verification
        self.submission_snapshot = submission_snapshot


def _failed_attempt_result(
    exc: BaseException,
) -> TerminalBenchRunResult | TerminalBenchAgentRunResult | None:
    if isinstance(exc, (_TransientTaskAttempt, _PostAgentVerifierError)):
        return exc.result
    return None


def _failed_result_metadata(
    result: TerminalBenchRunResult | TerminalBenchAgentRunResult,
) -> dict[str, Any]:
    if isinstance(result, TerminalBenchRunResult):
        return result.to_metadata()
    return {
        "sample_id": result.sample_id,
        "task_name": result.task_name,
        "agent_exit_code": result.agent_exit_code,
        "agent_timed_out": result.agent_timed_out,
        "agent_stdout": result.agent_stdout,
        "agent_stderr": result.agent_stderr,
        "requested_agent_timeout_sec": result.requested_agent_timeout_sec,
        "task_config_agent_timeout_sec": result.task_config_agent_timeout_sec,
        "effective_agent_timeout_sec": result.effective_agent_timeout_sec,
        "hardening_config": result.hardening_config,
        "policy_prompt_provenance": result.policy_prompt_provenance,
        "recovery_bundle_provenance": result.recovery_bundle_provenance,
        "policy_events": result.policy_events,
        "policy_event_count": len(result.policy_events),
        "preflight": result.preflight,
        "runtime_policy_probe_report": result.runtime_policy_probe_report,
        "openrouter_accounting": result.openrouter_accounting,
        "agentsh_agent_wrapped": result.agentsh_agent_wrapped,
        "agentsh_session_id": result.agentsh_session_id,
        "agentsh_policy_session": result.agentsh_policy_session,
        "agent_workdir": result.agent_workdir,
        "workspace_root": result.workspace_root,
        "harness_session_artifacts": result.harness_session_artifacts,
        "effort_level": result.effort_level,
        "effort_level_source": result.effort_level_source,
        "effort_level_applied": result.effort_level_applied,
    }


_TRANSIENT_ERROR_MARKERS = (
    *DAYTONA_LIFECYCLE_MARKERS,
    *DAYTONA_CONNECTION_MARKERS,
    "max retries exceeded",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
)


_RESOURCE_ERROR_MARKERS = RESOURCE_FAILURE_MARKERS


_TRANSIENT_INFRA_RESOURCE_RETRY_BLOCKERS = (
    *DAYTONA_LIFECYCLE_MARKERS,
    *DAYTONA_CONNECTION_MARKERS,
    "max retries exceeded",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
)


def _is_transient_task_error(exc: BaseException) -> bool:
    if isinstance(exc, (PreflightFailedError, _PostAgentVerifierError)):
        return False
    if isinstance(exc, _TransientTaskAttempt):
        return True
    text = f"{type(exc).__name__}: {exc!r}".lower()
    return any(marker in text for marker in _TRANSIENT_ERROR_MARKERS)


def _is_resource_task_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc!r}".lower()
    return any(marker in text for marker in _RESOURCE_ERROR_MARKERS)


def _is_transient_infra_task_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc!r}".lower()
    return any(marker in text for marker in _TRANSIENT_INFRA_RESOURCE_RETRY_BLOCKERS)


def _is_cleanup_delete_race(exc: BaseException) -> bool:
    class_name = exc.__class__.__name__.lower()
    message = f"{exc!s} {exc!r}".lower()
    return (
        "notfound" in class_name
        or "not found" in message
        or "already deleted" in message
        or "404" in message
    )


def _extract_provider_error_from_attempt(
    exc: BaseException,
    harness_adapter: Any,
) -> ProviderErrorInfo | None:
    """Check whether a failed attempt carries a provider/auth error.

    The exception may be a ``_TransientTaskAttempt`` whose attached
    ``TerminalBenchRunResult`` has agent stdout we can scan. Detection is
    delegated to the harness adapter so each harness classifies its own output
    format (Claude's stream vs Codex's ``--json`` events).
    """

    if isinstance(exc, _TransientTaskAttempt) and exc.result is not None:
        return harness_adapter.provider_auth_error(exc.result.agent_stdout)
    return None


def _exception_metadata(exc: BaseException) -> dict[str, str]:
    """Compact exception details for .eval metadata and cloud diagnostics."""

    metadata = {
        "error_type": type(exc).__name__,
        "error_message": str(exc)[:2000],
        "error_traceback": "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )[:8000],
    }
    sandbox_id = getattr(exc, "sandbox_id", None)
    if sandbox_id not in (None, ""):
        metadata["sandbox_id"] = str(sandbox_id)
    return metadata


def _attach_sandbox_id(exc: BaseException, sandbox_id: str | None) -> None:
    """Best-effort attach the provisioned sandbox ID to an escaping failure."""

    if sandbox_id is None:
        return
    try:
        setattr(exc, "sandbox_id", sandbox_id)
    except Exception:  # noqa: BLE001 - preserve the original task failure
        pass


def _phase_timing_exception_metadata(exc: BaseException) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    phase_timings_ms = getattr(exc, "phase_timings_ms", None)
    if isinstance(phase_timings_ms, dict):
        metadata["phase_timings_ms"] = phase_timings_ms
    phase_timing_details = getattr(exc, "phase_timing_details", None)
    if isinstance(phase_timing_details, list):
        metadata["phase_timing_details"] = phase_timing_details
    task_net_runtime_ms = getattr(exc, "task_net_runtime_ms", None)
    if task_net_runtime_ms is not None:
        metadata["task_net_runtime_ms"] = task_net_runtime_ms
    return metadata


def _benchmark_failure_class(metadata: dict[str, Any]) -> str:
    status = metadata.get("benchmark_status")
    if isinstance(status, dict):
        return str(status.get("failure_class") or "")
    return ""


def _with_harness_health_domains(
    config: DaytonaHardeningConfig, adapter: Any
) -> DaytonaHardeningConfig:
    """Overlay the running harness's health/telemetry domains onto ``config``.

    The network axis selects a harness-agnostic base egress allowlist; each
    harness's own vendor health backend (Claude Code -> api.anthropic.com;
    Codex -> chatgpt.com) is a per-harness overlay applied here at runtime. The
    overlay adds only the running harness's declarations; a domain already in
    the selected base remains reachable independently. Returns ``config``
    unchanged when domain egress is not gated
    (N0 has no domain wall — nothing to allow), when the adapter exposes no
    health domains, or when they are already present (order-preserving de-dup).
    """

    if not config.domain_egress_enabled:
        return config
    health_domains = getattr(adapter, "health_egress_domains", ())
    if not health_domains:
        return config
    merged = list(config.egress_domain_allowlist)
    for domain in health_domains:
        if domain not in merged:
            merged.append(domain)
    if tuple(merged) == config.egress_domain_allowlist:
        return config
    return replace(config, egress_domain_allowlist=tuple(merged))


def _with_harness_home_carveouts(
    config: DaytonaHardeningConfig, adapter: Any
) -> DaytonaHardeningConfig:
    """Overlay the running harness's home runtime dirs onto the F3 carveouts.

    Filesystem-axis mirror of ``_with_harness_health_domains``: the config's
    default carveout list covers the shared cache dirs (plus Claude Code's
    ``.claude``); the running harness's own runtime home (for example codex
    ``.codex``, grok ``.grok``, or Terminus-2 ``.terminus-2``) is overlaid here
    so its machinery keeps working under F3
    (read-only home) while the rest of home stays frozen. No-op when the
    adapter declares nothing new; harmless below F3 (the renderer only reads
    the list at ``read_only`` scope).
    """

    subdirs = getattr(adapter, "home_runtime_subdirs", ())
    if not subdirs:
        return config
    merged = list(config.f3_home_carveout_subdirs)
    for sub in subdirs:
        if sub not in merged:
            merged.append(sub)
    if tuple(merged) == config.f3_home_carveout_subdirs:
        return config
    return replace(config, f3_home_carveout_subdirs=tuple(merged))


def _resolve_verifier_lifecycle(
    bundle: Any,
    *,
    task_id: str,
    harbor_ref: str,
) -> DaytonaVerifierLifecycleResolution:
    """Resolve and fail closed on verifier lifecycles we cannot reproduce."""

    declared_mode = getattr(bundle, "verifier_environment_mode", None)
    declared_source = getattr(bundle, "verifier_environment_mode_source", None)
    if declared_mode is None:
        raise RuntimeError(
            "verifier error: Harbor verifier environment mode is missing"
        )
    if declared_mode not in ("shared", "separate"):
        raise RuntimeError(
            f"verifier error: unsupported Harbor verifier environment mode: "
            f"{declared_mode!r}"
        )
    if declared_source not in (
        "verifier.environment_mode",
        "verifier.environment",
        "harbor_default",
    ):
        raise RuntimeError(
            "verifier error: unsupported Harbor verifier environment source: "
            f"{declared_source!r}"
        )
    verifier_user = getattr(bundle, "verifier_user", None)
    if verifier_user not in (None, "", "root", "0"):
        raise RuntimeError(
            "verifier error: hardened verification requires a root verifier, "
            f"got verifier_user={verifier_user!r}"
        )

    lifecycle = resolve_daytona_verifier_lifecycle(
        task_id=task_id,
        harbor_ref=harbor_ref,
        declared=HarborVerifierEnvironmentResolution(
            mode=declared_mode,
            source=declared_source,
        ),
    )
    if lifecycle.effective_mode not in ("shared", "separate"):
        raise RuntimeError(
            "verifier error: unsupported effective verifier lifecycle: "
            f"{lifecycle.effective_mode!r}"
        )

    metadata = getattr(bundle, "metadata", None)
    harbor_config = (
        metadata.get("harbor_config") if isinstance(metadata, dict) else None
    )
    verifier_config = (
        harbor_config.get("verifier") if isinstance(harbor_config, dict) else None
    )
    has_distinct_verifier_environment = (
        isinstance(verifier_config, dict)
        and verifier_config.get("environment") is not None
    )
    if (
        lifecycle.declared_source == "verifier.environment"
        or has_distinct_verifier_environment
    ):
        raise RuntimeError(
            "verifier error: a distinct Harbor verifier environment is not "
            "supported by the Daytona runner"
        )

    if lifecycle.effective_mode == "separate":
        artifacts = (
            harbor_config.get("artifacts") if isinstance(harbor_config, dict) else None
        )
        if artifacts:
            raise RuntimeError(
                "verifier error: Harbor artifact handoff is not supported; "
                "only the resolved explicit regular files may cross the clean "
                "verifier boundary"
            )
    elif lifecycle.handoff_paths:
        raise RuntimeError(
            "verifier error: shared verification cannot declare handoff paths"
        )
    return lifecycle


def _verifier_lifecycle_metadata(
    lifecycle: DaytonaVerifierLifecycleResolution,
) -> dict[str, Any]:
    return {
        "handoff_paths": list(lifecycle.handoff_paths),
        "harbor_verifier_environment_mode": lifecycle.declared_mode,
        "harbor_verifier_environment_mode_source": lifecycle.declared_source,
        "effective_verifier_environment_mode": lifecycle.effective_mode,
        "effective_verifier_environment_mode_source": lifecycle.effective_source,
        "verifier_lifecycle_override_reason": lifecycle.override_reason,
    }


def _cleanup_outcome_metadata(
    *,
    separate: bool,
    agent_vm_deleted: bool,
    verifier_vm_delete_attempted: bool,
    verifier_vm_deleted: bool | None,
    handoff_snapshot_cleanup_attempted: bool,
    handoff_snapshot_cleaned: bool | None,
    cleanup_errors: list[Exception],
) -> dict[str, Any]:
    if not separate:
        status = "pending_shared_sandbox_delete"
    elif cleanup_errors:
        status = "failed"
    elif not agent_vm_deleted:
        status = "pending_agent_sandbox_delete"
    else:
        status = "complete"
    return {
        "status": status,
        **(
            {
                "shared_sandbox_delete_attempted": False,
                "shared_sandbox_deleted": None,
            }
            if not separate
            else {}
        ),
        "verifier_vm_delete_attempted": verifier_vm_delete_attempted,
        "verifier_vm_deleted": verifier_vm_deleted,
        "handoff_snapshot_cleanup_attempted": handoff_snapshot_cleanup_attempted,
        "handoff_snapshot_cleaned": handoff_snapshot_cleaned,
    }


def _capture_listener_evidence(sandbox: Any) -> str | None:
    """Root snapshot of listening sockets; evidence for when a live daemon disappears."""

    if sandbox is None:
        return None
    try:
        probe = sandbox.process.exec(AGENT_LISTENER_PROBE_COMMAND, timeout=30)
        return (getattr(probe, "result", "") or "")[:4000]
    except Exception as exc:
        return f"listener-probe-error: {exc!r}"[:4000]


def _cleanup_preserved_agent_session(sandbox: Any, session_id: str | None) -> str:
    if session_id is None:
        return "not_preserved"
    if sandbox is None:
        return "sandbox_deleted"
    try:
        sandbox.process.delete_session(session_id)
        return "deleted"
    except Exception as exc:
        return f"delete_failed: {exc!r}"[:500]


def _postflight_verification_metadata(
    *,
    harbor_ref: str,
    lifecycle: DaytonaVerifierLifecycleResolution,
    agent_process_disposition: AgentProcessDispositionResolution,
    agent_session_lifecycle: AgentSessionLifecycleResolution,
    agent_session_id: str | None,
    agent_session_preserved: bool,
    verifier_session_id: str | None,
    post_agent_listeners: str | None,
    pre_verifier_listeners: str | None,
    handoff_exported: bool,
    agent_vm_deleted: bool,
    verifier_vm_provisioned: bool,
    tests_uploaded_after_agent: bool,
    verifier_process_started: bool,
    verifier_completed: bool,
    agent_pid_namespace_isolation_requested: bool,
    agent_pid_namespace_isolated: bool,
    cleanup_outcome: dict[str, Any],
    agent_sandbox_id: str,
    verifier_sandbox_id: str | None,
    image: str,
    agent_workdir: str,
    workspace_root: str,
    verifier_user: str | None,
    verifier_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    separate = lifecycle.effective_mode == "separate"
    return {
        "enabled": True,
        "mode": (
            "harbor_separate_clean_daytona"
            if separate
            else "harbor_shared_same_daytona"
        ),
        "clean_verifier_vm": verifier_vm_provisioned,
        "clean_verifier_process": verifier_process_started,
        "handoff_exported": handoff_exported,
        "agent_vm_deleted": agent_vm_deleted,
        "verifier_vm_provisioned": verifier_vm_provisioned,
        "verifier_started": verifier_process_started,
        "verifier_process_started": verifier_process_started,
        "verifier_completed": verifier_completed,
        "cleanup_outcome": cleanup_outcome,
        "verifier_hardening": False,
        "agent_hardening_lifted": False,
        "global_hardening_lifted": False,
        "agent_completed_before_verifier": True,
        "agent_process_disposition": agent_process_disposition.disposition,
        "agent_process_disposition_source": agent_process_disposition.source,
        "agent_process_disposition_reason": agent_process_disposition.reason,
        "agent_pid_namespace_isolation_requested": (
            agent_pid_namespace_isolation_requested
        ),
        "agent_pid_namespace_isolation_observed": agent_pid_namespace_isolated,
        "agent_pid_namespace_isolated": agent_pid_namespace_isolated,
        "tests_uploaded_after_agent": tests_uploaded_after_agent,
        "live_state_preserved": not separate,
        "agent_session_lifecycle": agent_session_lifecycle.lifecycle,
        "agent_session_lifecycle_source": agent_session_lifecycle.source,
        "agent_session_lifecycle_reason": agent_session_lifecycle.reason,
        "agent_session_lifecycle_evidence": agent_session_lifecycle.service_evidence,
        "agent_session_preserved": agent_session_preserved,
        "agent_session_id": agent_session_id,
        "verifier_session_id": verifier_session_id,
        "verifier_fresh_session": bool(
            agent_session_id
            and verifier_session_id
            and agent_session_id != verifier_session_id
        ),
        "post_agent_listeners": post_agent_listeners,
        "pre_verifier_listeners": pre_verifier_listeners,
        "agent_sandbox_id": agent_sandbox_id,
        "verifier_sandbox_id": verifier_sandbox_id,
        "verifier_image": image,
        "verifier_workspace": agent_workdir,
        "workspace_root": workspace_root,
        "verifier_user": verifier_user,
        "verifier_identity": verifier_identity,
        "handoff_transport": (
            "explicit_regular_files"
            if handoff_exported
            else ("none" if not separate else None)
        ),
        "harbor_ref": harbor_ref,
        **_verifier_lifecycle_metadata(lifecycle),
    }


def _completed_terminalbench_result(
    *,
    agent: TerminalBenchAgentRunResult,
    verifier: DaytonaVerifierResult,
    sandbox_id: str | None,
    handoff_metadata: dict[str, Any] | None,
    postflight_verification: dict[str, Any],
    agent_version: str | None,
    agent_workdir_source: str,
    harness_name: str,
) -> TerminalBenchRunResult:
    return TerminalBenchRunResult(
        sample_id=agent.sample_id,
        task_name=agent.task_name,
        prompt=agent.prompt,
        reward=verifier.value,
        answer=verifier.answer,
        agent_exit_code=agent.agent_exit_code,
        agent_stdout=agent.agent_stdout,
        agent_stderr=agent.agent_stderr,
        agent_timed_out=agent.agent_timed_out,
        requested_agent_timeout_sec=agent.requested_agent_timeout_sec,
        task_config_agent_timeout_sec=agent.task_config_agent_timeout_sec,
        effective_agent_timeout_sec=agent.effective_agent_timeout_sec,
        sandbox_id=sandbox_id,
        verifier=verifier,
        hardening_config=agent.hardening_config,
        policy_prompt_provenance=agent.policy_prompt_provenance,
        recovery_bundle_provenance=agent.recovery_bundle_provenance,
        policy_events=agent.policy_events,
        preflight=agent.preflight,
        runtime_policy_probe_report=agent.runtime_policy_probe_report,
        agentsh_agent_wrapped=agent.agentsh_agent_wrapped,
        agentsh_session_id=agent.agentsh_session_id,
        agentsh_policy_session=agent.agentsh_policy_session,
        openrouter_accounting=agent.openrouter_accounting,
        submission_snapshot=handoff_metadata,
        postflight_verification=postflight_verification,
        agent_version=agent_version,
        agent_workdir=agent.agent_workdir,
        agent_workdir_source=agent_workdir_source,
        workspace_root=agent.workspace_root,
        harness_session_artifacts=agent.harness_session_artifacts,
        harness=harness_name,
        effort_level=agent.effort_level,
        effort_level_source=agent.effort_level_source,
        effort_level_applied=agent.effort_level_applied,
    )


def run_one_hardened_task(
    task_id: str,
    *,
    ref: str,
    model: str,
    openrouter_api_key: str,
    agent_timeout_sec: int = DEFAULT_AGENT_TIMEOUT_SEC,
    policy: str = DEFAULT_POLICY_NAME,
    block_message: str | None = None,
    harness: str = DEFAULT_HARNESS,
    effort: str | None = None,
    policy_prompt: str = POLICY_PROMPT_OFF,
    recovery_bundle: str = RECOVERY_BUNDLE_OFF,
) -> TerminalBenchRunResult:
    return _run_with_phase_timing_capture(
        _run_one_hardened_task_impl,
        task_id,
        ref=ref,
        model=model,
        openrouter_api_key=openrouter_api_key,
        agent_timeout_sec=agent_timeout_sec,
        policy=policy,
        block_message=block_message,
        harness=harness,
        effort=effort,
        policy_prompt=policy_prompt,
        recovery_bundle=recovery_bundle,
    )


def _run_one_hardened_task_impl(
    task_id: str,
    *,
    ref: str,
    model: str,
    openrouter_api_key: str,
    agent_timeout_sec: int = DEFAULT_AGENT_TIMEOUT_SEC,
    policy: str = DEFAULT_POLICY_NAME,
    block_message: str | None = None,
    harness: str = DEFAULT_HARNESS,
    effort: str | None = None,
    policy_prompt: str = POLICY_PROMPT_OFF,
    recovery_bundle: str = RECOVERY_BUNDLE_OFF,
) -> TerminalBenchRunResult:
    """Provision, run, verify, and tear down one task under the named policy.

    ``policy`` selects which BoundaryBench overlays are applied on top of the
    Daytona/task-image baseline.
    """

    verifier_max_attempts()

    from daytona_sdk import Daytona

    total_started = time.perf_counter()
    harness_adapter = get_harness_adapter(harness)
    selected = resolve_policy_for_run(policy)
    if selected.enforcement_mode == "native" and selected.name in AXIS_PRESETS:
        base_config = build_daytona_config_from_axes(
            AXIS_PRESETS[selected.name], task_id=task_id
        )
    else:
        base_config = selected.config
    hardening_config = (
        base_config.with_block_message(block_message)
        if block_message is not None
        else base_config
    )
    hardening_config = _with_harness_health_domains(hardening_config, harness_adapter)
    config_pre_carveout = hardening_config
    hardening_config = _with_harness_home_carveouts(hardening_config, harness_adapter)
    policy_prompt_fragment: str | None = None
    allowlist_file_content: str | None = None
    policy_prompt_bundle = None
    if policy_prompt == POLICY_PROMPT_ON:
        policy_prompt_bundle = render_policy_prompt(
            policy=selected,
            config=hardening_config,
            infra_domains=(
                *DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
                *getattr(harness_adapter, "health_egress_domains", ()),
            ),
        )
        if policy_prompt_bundle is not None:
            policy_prompt_fragment = policy_prompt_bundle.fragment
            allowlist_file_content = policy_prompt_bundle.allowlist_file_content
    agent_home = (
        "/root" if selected.agent_user == "root" else f"/home/{selected.agent_user}"
    )
    recovery_bundle_obj = None
    recovery_bundle_files: list[tuple[str, str, str]] = []
    if recovery_bundle == RECOVERY_BUNDLE_ON:
        recovery_bundle_obj = render_recovery_bundle(
            policy=selected,
            config=config_pre_carveout,
            harness_adapter=harness_adapter,
            infra_domains=(
                *DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
                *getattr(harness_adapter, "health_egress_domains", ()),
            ),
            agent_home=agent_home,
        )
        if recovery_bundle_obj is not None:
            recovery_bundle_files = [
                (file.remote_path, file.content, file.chmod)
                for file in recovery_bundle_obj.files
            ]
    recovery_bundle_provenance = build_recovery_bundle_provenance(
        bundle=recovery_bundle_obj, knob=recovery_bundle
    )
    daytona = Daytona()
    phase_started = time.perf_counter()
    phase_status = "success"
    with _HARBOR_LOAD_LOCK:
        try:
            bundle = load_terminalbench_daytona_bundle(task_id=task_id, harbor_ref=ref)
        except Exception:
            phase_status = "error"
            raise
        finally:
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_id,
                phase="harbor_task_load",
                started_at=phase_started,
                status=phase_status,
            )
    policy_prompt_provenance = build_policy_prompt_provenance(
        task_text=bundle.input,
        bundle=policy_prompt_bundle,
    )
    requested_agent_timeout_sec = agent_timeout_sec
    task_config_agent_timeout_sec = getattr(bundle, "agent_timeout_sec", None)
    agent_timeout_sec = _effective_agent_timeout_sec(
        requested_agent_timeout_sec, task_config_agent_timeout_sec
    )
    verifier_timeout_sec = getattr(bundle, "verifier_timeout_sec", agent_timeout_sec)
    verifier_lifecycle = _resolve_verifier_lifecycle(
        bundle,
        task_id=task_id,
        harbor_ref=ref,
    )
    agent_process_disposition = resolve_agent_process_disposition(
        task_id=task_id,
        harbor_ref=ref,
        declared=HarborVerifierEnvironmentResolution(
            mode=verifier_lifecycle.declared_mode,
            source=verifier_lifecycle.declared_source,
        ),
    )
    agent_session_lifecycle = resolve_agent_session_lifecycle(
        task_id=task_id, harbor_ref=ref
    )
    preserve_agent_session = (
        agent_session_lifecycle.lifecycle == "preserve_until_verified"
    )
    image = task_docker_image(bundle)
    workspace = (
        terminalbench_workspace_from_bundle(bundle)
        if getattr(bundle, "task_dir", None) is not None
        else resolve_terminalbench_workspace(DEFAULT_AGENT_WORKDIR)
    )
    agent_workdir = workspace.workdir
    workspace_root = workspace.workspace_root
    agent_workdir_source = (
        "default" if agent_workdir == DEFAULT_AGENT_WORKDIR else "task_image"
    )
    resource_attempts = daytona_task_resource_attempts(bundle)
    for resource_attempt, resources in enumerate(resource_attempts, start=1):
        sandbox = None
        sandbox_id = None
        postflight_for_shared_cleanup: dict[str, Any] | None = None
        agent_phase_completed = False
        preserved_agent_session_id: str | None = None
        pre_verifier_listeners: str | None = None
        isolate_agent_pid_namespace = agent_process_disposition.disposition == "reap"
        if preserve_agent_session and isolate_agent_pid_namespace:
            raise RuntimeError(
                f"task {task_id}: agent session lifecycle preserve_until_verified "
                "conflicts with reap disposition (PID namespace teardown would kill "
                "the live service)"
            )
        agent_pid_namespace_isolated = False
        try:
            phase_started = time.perf_counter()
            sandbox, hardening = provision_hardened_task_sandbox(
                daytona,
                image=image,
                resources=resources,
                hardening_config=hardening_config,
                run_agent_as_root=selected.run_agent_as_root,
                install_policy_hardening=(
                    bool(selected.overlays) or selected.enforcement_mode == "native"
                ),
                install_landlock_mac_runner=selected.full_mac_enforcement,
                enforcement_mode=selected.enforcement_mode,
                harness=harness_adapter,
                effort_level=normalize_effort_level(harness_adapter, effort),
                command_timeout_sec=max(agent_timeout_sec, verifier_timeout_sec),
                workdir=workspace_root,
                task_id=task_id,
                recovery_bundle_files=recovery_bundle_files,
            )
            sandbox_id = _sandbox_id(sandbox)
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_id,
                phase="sandbox_provision_attempt",
                started_at=phase_started,
                status="success",
                resource_attempt=resource_attempt,
            )
            agent_version = read_agent_version(
                sandbox,
                harness=harness_adapter,
                run_as_root=selected.run_agent_as_root,
            )
            preflight = None
            runtime_policy_probe_report = None
            agentsh_session_id = None
            agentsh_policy_session = None
            if hardening is not None:
                phase_started = time.perf_counter()
                phase_status = "success"
                try:
                    preflight_result = run_preflight(
                        sandbox,
                        policy=selected,
                        daytona_policy_hardening=hardening,
                    )
                    preflight = preflight_result.to_compact_metadata()
                except Exception:
                    phase_status = "error"
                    raise
                finally:
                    _print_phase_timing(
                        component="terminalbench_daytona",
                        identifier=task_id,
                        phase="policy_preflight",
                        started_at=phase_started,
                        status=phase_status,
                    )
                phase_started = time.perf_counter()
                mac_capability_probe = None
                if _apparmor_capability_probe_enabled():
                    mac_report = run_apparmor_capability_probe(
                        sandbox,
                        profile_name=unique_apparmor_probe_profile_name(),
                    )
                    mac_capability_probe = mac_report.to_metadata()
                    _print_phase_timing(
                        component="terminalbench_daytona",
                        identifier=task_id,
                        phase="apparmor_capability_probe",
                        started_at=phase_started,
                        status=mac_report.status,
                        supported=mac_report.supported,
                    )
                    phase_started = time.perf_counter()
                phase_status = "success"
                probe_count = 0
                try:
                    report = run_runtime_policy_probe_suite_in_sandbox(
                        sandbox,
                        daytona_policy_hardening=hardening,
                        policy_id=selected.name,
                        policy_name=selected.name,
                        overlays=selected.overlays,
                        agent_user=selected.agent_user,
                        workspace=RUNTIME_POLICY_PROBE_WORKSPACE,
                        isolate_network=selected.isolate_network,
                        block_network=selected.block_network,
                        block_child_shell_network=selected.block_child_shell_network,
                        unsupported_surfaces=selected.unsupported_surfaces,
                        probe_scope=selected.runtime_probe_scope,
                        mac_capability_probe=mac_capability_probe,
                        full_mac_enforcement=selected.full_mac_enforcement,
                        enforcement_mode=selected.enforcement_mode,
                    )
                    runtime_policy_probe_report = report.to_metadata()
                    probe_count = len(runtime_policy_probe_report.get("results") or [])
                    ensure_runtime_policy_probe_suite_passed(report)
                except Exception:
                    phase_status = "error"
                    raise
                finally:
                    _print_phase_timing(
                        component="terminalbench_daytona",
                        identifier=task_id,
                        phase="runtime_policy_probes",
                        started_at=phase_started,
                        status=phase_status,
                        probe_count=probe_count,
                    )
                if selected.agentsh_policy_config is not None:
                    phase_started = time.perf_counter()
                    phase_status = "success"
                    try:
                        agentsh_session = prepare_daytona_agentsh_session(
                            sandbox,
                            config=selected.agentsh_policy_config,
                            run_id=_agentsh_run_id(task_id, selected.name),
                        )
                        agentsh_session_id = agentsh_session.session_id
                        agentsh_policy_session = agentsh_session.to_metadata()
                    except Exception:
                        phase_status = "error"
                        raise
                    finally:
                        _print_phase_timing(
                            component="terminalbench_daytona",
                            identifier=task_id,
                            phase="agentsh_policy_session",
                            started_at=phase_started,
                            status=phase_status,
                        )
            phase_started = time.perf_counter()
            phase_status = "success"
            agent_sandbox_id = sandbox_id or ""
            try:
                agent = run_terminalbench_task_in_daytona(
                    sandbox,
                    bundle,
                    daytona_policy_hardening=hardening,
                    openrouter_api_key=openrouter_api_key,
                    harness=harness_adapter,
                    model=model,
                    agent_workdir=agent_workdir,
                    workspace_root=workspace_root,
                    agent_timeout_sec=agent_timeout_sec,
                    requested_agent_timeout_sec=requested_agent_timeout_sec,
                    task_config_agent_timeout_sec=task_config_agent_timeout_sec,
                    isolate_network=selected.isolate_network,
                    block_network=selected.block_network,
                    block_child_shell_network=selected.block_child_shell_network,
                    full_mac_enforcement=selected.full_mac_enforcement,
                    run_agent_as_root=selected.run_agent_as_root,
                    hardening_config_metadata=hardening_config.to_metadata(),
                    preflight=preflight,
                    runtime_policy_probe_report=runtime_policy_probe_report,
                    agentsh_session_id=agentsh_session_id,
                    agentsh_policy_session=agentsh_policy_session,
                    enforcement_mode=selected.enforcement_mode,
                    effort_level=effort,
                    policy_prompt_fragment=policy_prompt_fragment,
                    allowlist_file_content=allowlist_file_content,
                    policy_prompt_provenance=policy_prompt_provenance,
                    isolate_agent_pid_namespace=isolate_agent_pid_namespace,
                    preserve_agent_session=preserve_agent_session,
                )
                agent = replace(
                    agent, recovery_bundle_provenance=recovery_bundle_provenance
                )
                agent_phase_completed = True
                agent_pid_namespace_isolated = getattr(
                    agent, "agent_pid_namespace_isolation_observed", False
                )
                if getattr(agent, "agent_session_preserved", False):
                    preserved_agent_session_id = getattr(agent, "agent_session_id", None)
                if isinstance(agent, TerminalBenchRunResult):
                    result = replace(
                        agent,
                        sandbox_id=agent.sandbox_id or sandbox_id,
                    )
                else:
                    phase_verifier_started = time.perf_counter()
                    phase_verifier_status = "success"
                    handoff_snapshot = None
                    handoff_metadata = None
                    verifier_sandbox = sandbox
                    verifier: DaytonaVerifierResult | None = None
                    verifier_identity: dict[str, Any] | None = None
                    handoff_exported = False
                    agent_vm_deleted = False
                    verifier_vm_provisioned = False
                    tests_uploaded_after_agent = False
                    verifier_process_started = False
                    verifier_completed = False
                    verifier_vm_delete_attempted = False
                    verifier_vm_deleted: bool | None = None
                    handoff_snapshot_cleanup_attempted = False
                    handoff_snapshot_cleaned: bool | None = None
                    post_agent_error: Exception | None = None
                    cleanup_errors: list[Exception] = []

                    def observe_verifier_transition(observation: str) -> None:
                        nonlocal tests_uploaded_after_agent
                        nonlocal verifier_process_started
                        if (
                            observation
                            == VERIFIER_OBSERVATION_TESTS_UPLOADED_AFTER_AGENT
                        ):
                            tests_uploaded_after_agent = True
                        elif observation == VERIFIER_OBSERVATION_PROCESS_STARTED:
                            verifier_process_started = True

                    try:
                        if verifier_lifecycle.effective_mode == "separate":
                            handoff_snapshot = export_verifier_artifacts(
                                sandbox,
                                verifier_lifecycle.handoff_paths,
                                workspace_root=workspace_root,
                            )
                            handoff_metadata = handoff_snapshot.to_metadata()
                            handoff_exported = True

                            phase_delete_started = time.perf_counter()
                            phase_delete_status = "success"
                            try:
                                daytona.delete(sandbox)
                            except Exception as exc:
                                phase_delete_status = "error"
                                if not _is_cleanup_delete_race(exc):
                                    raise
                            finally:
                                _print_phase_timing(
                                    component="terminalbench_daytona",
                                    identifier=task_id,
                                    phase="sandbox_delete",
                                    started_at=phase_delete_started,
                                    status=phase_delete_status,
                                )
                            agent_vm_deleted = True
                            sandbox = None
                            verifier_sandbox = None
                            verifier_sandbox = provision_clean_verifier_sandbox(
                                daytona,
                                image=image,
                                resources=resources,
                                workdir=workspace_root,
                                verifier_user=bundle.verifier_user,
                                command_timeout_sec=verifier_timeout_sec,
                            )
                            verifier_vm_provisioned = True
                            import_verifier_artifacts(
                                verifier_sandbox,
                                handoff_snapshot,
                                workspace_root=workspace_root,
                            )

                        pre_verifier_listeners = _capture_listener_evidence(
                            verifier_sandbox
                        )
                        verifier = run_daytona_harbor_verifier(
                            verifier_sandbox,
                            bundle,
                            remote_workdir=agent_workdir,
                            observation_callback=observe_verifier_transition,
                        )
                        verifier_completed = True
                        verifier_identity = verifier.verifier_identity
                        if not isinstance(verifier_identity, dict) or (
                            verifier_identity.get("effective_uid") != 0
                        ):
                            raise RuntimeError(
                                "observed verifier identity is not root: "
                                f"{verifier_identity!r}"
                            )
                    except Exception as exc:
                        phase_verifier_status = "error"
                        post_agent_error = exc
                    finally:
                        if verifier_lifecycle.effective_mode == "separate":
                            if (
                                verifier_sandbox is not None
                                and verifier_sandbox is not sandbox
                            ):
                                verifier_vm_delete_attempted = True
                                phase_delete_started = time.perf_counter()
                                phase_delete_status = "success"
                                try:
                                    daytona.delete(verifier_sandbox)
                                    verifier_vm_deleted = True
                                except Exception as exc:
                                    phase_delete_status = "error"
                                    if not _is_cleanup_delete_race(exc):
                                        phase_verifier_status = "error"
                                        verifier_vm_deleted = False
                                        cleanup_errors.append(exc)
                                    else:
                                        verifier_vm_deleted = True
                                finally:
                                    _print_phase_timing(
                                        component="terminalbench_daytona",
                                        identifier=task_id,
                                        phase="verifier_sandbox_delete",
                                        started_at=phase_delete_started,
                                        status=phase_delete_status,
                                    )
                            if handoff_snapshot is not None:
                                handoff_snapshot_cleanup_attempted = True
                                try:
                                    cleanup_verifier_artifacts(handoff_snapshot)
                                    handoff_snapshot_cleaned = True
                                except Exception as exc:
                                    phase_verifier_status = "error"
                                    handoff_snapshot_cleaned = False
                                    cleanup_errors.append(exc)
                        _print_phase_timing(
                            component="terminalbench_daytona",
                            identifier=task_id,
                            phase="harbor_verifier",
                            started_at=phase_verifier_started,
                            status=phase_verifier_status,
                        )
                    if post_agent_error is not None or cleanup_errors:
                        primary_error = post_agent_error or cleanup_errors[0]
                        all_errors = (
                            [post_agent_error] if post_agent_error else []
                        ) + cleanup_errors
                        cause: Exception = (
                            ExceptionGroup("verifier lifecycle failed", all_errors)
                            if len(all_errors) > 1
                            else all_errors[0]
                        )
                        failed_separate = (
                            verifier_lifecycle.effective_mode == "separate"
                        )
                        failed_verifier_sandbox_id = (
                            _sandbox_id(verifier_sandbox)
                            if verifier_sandbox is not None
                            and (not failed_separate or verifier_sandbox is not sandbox)
                            else None
                        )
                        cleanup_outcome = _cleanup_outcome_metadata(
                            separate=failed_separate,
                            agent_vm_deleted=agent_vm_deleted,
                            verifier_vm_delete_attempted=verifier_vm_delete_attempted,
                            verifier_vm_deleted=verifier_vm_deleted,
                            handoff_snapshot_cleanup_attempted=(
                                handoff_snapshot_cleanup_attempted
                            ),
                            handoff_snapshot_cleaned=handoff_snapshot_cleaned,
                            cleanup_errors=cleanup_errors,
                        )
                        failed_postflight_verification = (
                            _postflight_verification_metadata(
                                harbor_ref=ref,
                                lifecycle=verifier_lifecycle,
                                agent_process_disposition=agent_process_disposition,
                                agent_session_lifecycle=agent_session_lifecycle,
                                agent_session_id=agent.agent_session_id,
                                agent_session_preserved=agent.agent_session_preserved,
                                verifier_session_id=None,
                                post_agent_listeners=(
                                    agent.post_agent_listeners[:4000]
                                    if agent.post_agent_listeners
                                    else None
                                ),
                                pre_verifier_listeners=pre_verifier_listeners,
                                handoff_exported=handoff_exported,
                                agent_vm_deleted=agent_vm_deleted,
                                verifier_vm_provisioned=verifier_vm_provisioned,
                                tests_uploaded_after_agent=(tests_uploaded_after_agent),
                                verifier_process_started=verifier_process_started,
                                verifier_completed=verifier_completed,
                                agent_pid_namespace_isolation_requested=(
                                    isolate_agent_pid_namespace
                                ),
                                agent_pid_namespace_isolated=(
                                    agent_pid_namespace_isolated
                                ),
                                cleanup_outcome=cleanup_outcome,
                                agent_sandbox_id=agent_sandbox_id,
                                verifier_sandbox_id=failed_verifier_sandbox_id,
                                image=image,
                                agent_workdir=agent_workdir,
                                workspace_root=workspace_root,
                                verifier_user=bundle.verifier_user,
                                verifier_identity=verifier_identity,
                            )
                        )
                        postflight_for_shared_cleanup = failed_postflight_verification
                        failed_result: (
                            TerminalBenchAgentRunResult | TerminalBenchRunResult
                        ) = agent
                        if verifier_completed and verifier is not None:
                            failed_result = _completed_terminalbench_result(
                                agent=agent,
                                verifier=verifier,
                                sandbox_id=sandbox_id,
                                handoff_metadata=handoff_metadata,
                                postflight_verification=(
                                    failed_postflight_verification
                                ),
                                agent_version=agent_version,
                                agent_workdir_source=agent_workdir_source,
                                harness_name=harness_adapter.name,
                            )
                        raise _PostAgentVerifierError(
                            f"verifier error: {primary_error}",
                            result=failed_result,
                            postflight_verification=failed_postflight_verification,
                            submission_snapshot=handoff_metadata,
                        ) from cause

                    verifier_sandbox_id = str(getattr(verifier_sandbox, "id", "") or "")
                    separate = verifier_lifecycle.effective_mode == "separate"
                    cleanup_outcome = _cleanup_outcome_metadata(
                        separate=separate,
                        agent_vm_deleted=agent_vm_deleted,
                        verifier_vm_delete_attempted=verifier_vm_delete_attempted,
                        verifier_vm_deleted=verifier_vm_deleted,
                        handoff_snapshot_cleanup_attempted=(
                            handoff_snapshot_cleanup_attempted
                        ),
                        handoff_snapshot_cleaned=handoff_snapshot_cleaned,
                        cleanup_errors=cleanup_errors,
                    )
                    postflight_verification = _postflight_verification_metadata(
                        harbor_ref=ref,
                        lifecycle=verifier_lifecycle,
                        agent_process_disposition=agent_process_disposition,
                        agent_session_lifecycle=agent_session_lifecycle,
                        agent_session_id=agent.agent_session_id,
                        agent_session_preserved=agent.agent_session_preserved,
                        verifier_session_id=verifier.session_id,
                        post_agent_listeners=(
                            agent.post_agent_listeners[:4000]
                            if agent.post_agent_listeners
                            else None
                        ),
                        pre_verifier_listeners=pre_verifier_listeners,
                        handoff_exported=handoff_exported,
                        agent_vm_deleted=agent_vm_deleted,
                        verifier_vm_provisioned=verifier_vm_provisioned,
                        tests_uploaded_after_agent=tests_uploaded_after_agent,
                        verifier_process_started=verifier_process_started,
                        verifier_completed=verifier_completed,
                        agent_pid_namespace_isolation_requested=(
                            isolate_agent_pid_namespace
                        ),
                        agent_pid_namespace_isolated=agent_pid_namespace_isolated,
                        cleanup_outcome=cleanup_outcome,
                        agent_sandbox_id=agent_sandbox_id,
                        verifier_sandbox_id=verifier_sandbox_id,
                        image=image,
                        agent_workdir=agent_workdir,
                        workspace_root=workspace_root,
                        verifier_user=bundle.verifier_user,
                        verifier_identity=verifier_identity,
                    )
                    postflight_for_shared_cleanup = postflight_verification
                    if verifier is None:
                        raise RuntimeError(
                            "verifier lifecycle completed without an official result"
                        )
                    result = _completed_terminalbench_result(
                        agent=agent,
                        verifier=verifier,
                        sandbox_id=sandbox_id,
                        handoff_metadata=handoff_metadata,
                        postflight_verification=postflight_verification,
                        agent_version=agent_version,
                        agent_workdir_source=agent_workdir_source,
                        harness_name=harness_adapter.name,
                    )
            except Exception:
                phase_status = "error"
                raise
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_id,
                phase="task_execute_and_verify",
                started_at=phase_started,
                status=phase_status,
                answer=result.answer,
                reward=result.reward,
            )
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_id,
                phase="hardened_task_total",
                started_at=total_started,
                status="success",
                answer=result.answer,
            )
            return result
        except Exception as exc:
            _attach_sandbox_id(exc, sandbox_id)
            if sandbox is None and not agent_phase_completed:
                _print_phase_timing(
                    component="terminalbench_daytona",
                    identifier=task_id,
                    phase="sandbox_provision_attempt",
                    started_at=phase_started,
                    status="error",
                    resource_attempt=resource_attempt,
                )
            _print_phase_timing(
                component="terminalbench_daytona",
                identifier=task_id,
                phase="hardened_task_total",
                started_at=total_started,
                status="error",
            )
            raise
        finally:
            if preserved_agent_session_id is not None and sandbox is not None:
                _run_harness_post_agent_cleanup(
                    sandbox,
                    harness=harness_adapter,
                    run_as_root=selected.run_agent_as_root,
                )
            agent_session_cleanup = _cleanup_preserved_agent_session(
                sandbox, preserved_agent_session_id
            )
            if postflight_for_shared_cleanup is not None:
                postflight_for_shared_cleanup["agent_session_cleanup"] = (
                    agent_session_cleanup
                )
            if sandbox is not None:
                phase_started = time.perf_counter()
                phase_status = "success"
                sandbox_deleted = False
                try:
                    daytona.delete(sandbox)
                    sandbox_deleted = True
                except Exception as exc:  # noqa: BLE001 - cleanup must not change score
                    phase_status = "error"
                    if _is_cleanup_delete_race(exc):
                        sandbox_deleted = True
                    else:
                        print(
                            f"[terminalbench-daytona] WARN sandbox delete failed: {exc!r}",
                            flush=True,
                        )
                finally:
                    if postflight_for_shared_cleanup is not None:
                        cleanup_outcome = postflight_for_shared_cleanup.get(
                            "cleanup_outcome"
                        )
                        if (
                            postflight_for_shared_cleanup.get("mode")
                            == "harbor_shared_same_daytona"
                            and isinstance(cleanup_outcome, dict)
                        ):
                            cleanup_outcome.update(
                                {
                                    "status": (
                                        "complete" if sandbox_deleted else "failed"
                                    ),
                                    "shared_sandbox_delete_attempted": True,
                                    "shared_sandbox_deleted": sandbox_deleted,
                                }
                            )
                    _print_phase_timing(
                        component="terminalbench_daytona",
                        identifier=task_id,
                        phase="sandbox_delete",
                        started_at=phase_started,
                        status=phase_status,
                    )
    raise RuntimeError(
        f"task {task_id} exhausted {len(resource_attempts)} resource attempts"
    )


def _agentsh_run_id(task_id: str, policy: str) -> str:
    safe_task = re.sub(r"[^A-Za-z0-9-]+", "-", task_id).strip("-") or "task"
    safe_policy = re.sub(r"[^A-Za-z0-9-]+", "-", policy).strip("-") or "policy"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"terminalbench-agentsh-{safe_task}-{safe_policy}-{stamp}"


@solver
def hardened_daytona_solver(
    *,
    ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    model: str = DEFAULT_OPENROUTER_MODEL,
    block_message: str | None = None,
    runner: Any = run_one_hardened_task,
    harness: str = DEFAULT_HARNESS,
    effort: str | None = None,
    policy_prompt: str = POLICY_PROMPT_OFF,
    recovery_bundle: str = RECOVERY_BUNDLE_OFF,
) -> Solver:
    """Run one Terminal-Bench task in a hardened Daytona sandbox per sample.

    The effective agent timeout is the task's ``task.toml [agent].timeout_sec``.
    ``BOUNDARYBENCH_AGENT_TIMEOUT_SEC`` remains only a fallback for
    non-standard samples that do not carry current Terminal-Bench task metadata.

    ``policy_prompt`` ("off"/"on") is the opt-in disclosure knob; "on" prepends
    the resolved ``<environment_policy>`` fragment to each task prompt.
    ``recovery_bundle`` ("off"/"on") is the parallel opt-in knob; "on" writes the
    policy-error-recovery bundle into the sandbox during the unhardened window.
    """

    harness_adapter = get_harness_adapter(harness)
    effective_effort = normalize_effort_level(harness_adapter, effort)
    effective_effort_source = effort_level_source(effort)
    resolved_policy_prompt = validate_policy_prompt(policy_prompt)
    resolved_recovery_bundle = validate_recovery_bundle(recovery_bundle)
    agent_timeout_sec = _env_agent_timeout()
    max_attempts = _env_task_max_attempts()

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        openrouter_api_key = provider_api_key_from_managed_env(
            harness_adapter, purpose="hardened Daytona Terminal-Bench runs"
        )
        task_id = str(
            (state.metadata or {}).get("terminal_bench_task_id") or state.sample_id
        )
        policy = str((state.metadata or {}).get("policy") or _env_policy())
        effective_block_message = block_message
        if effective_block_message is None:
            effective_block_message = (state.metadata or {}).get("block_message")
        if effective_block_message is None:
            effective_block_message = _env_block_message()
        display_model = str(state.model)
        pricing_model = model
        retry_errors: list[str] = []
        accumulated_native_accounting: dict[str, Any] | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                selected_policy = resolve_policy_for_run(policy)
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    _runner_executor(),
                    functools.partial(
                        runner,
                        task_id,
                        ref=ref,
                        model=model,
                        openrouter_api_key=openrouter_api_key,
                        agent_timeout_sec=agent_timeout_sec,
                        policy=policy,
                        block_message=effective_block_message,
                        harness=harness,
                        effort=effective_effort,
                        policy_prompt=resolved_policy_prompt,
                        recovery_bundle=resolved_recovery_bundle,
                    ),
                )
                metadata = result.to_metadata()
                metadata["full_trace"] = _build_full_trace(
                    harness_adapter,
                    agent_stdout=result.agent_stdout,
                    model=pricing_model,
                    session_artifacts=result.harness_session_artifacts,
                    policy_events=result.policy_events,
                )
                metadata["effort_level"] = effective_effort
                metadata["effort_level_source"] = effective_effort_source
                metadata["effort_level_applied"] = harness_adapter.effort_level_applied
                metadata["policy_prompt"] = resolved_policy_prompt
                metadata["recovery_bundle"] = resolved_recovery_bundle
                metadata["policy"] = policy
                metadata["policy_overlays"] = list(selected_policy.overlays)
                metadata["full_mac_enforcement"] = selected_policy.full_mac_enforcement
                metadata["block_message"] = (
                    metadata.get("hardening_config", {}).get("block_message")
                    or effective_block_message
                )
                metadata["agent_user"] = selected_policy.agent_user
                metadata.update(
                    HardeningClaims.derive(
                        policy_applies_hardening=selected_policy.applies_hardening,
                        harness=harness_adapter,
                    ).to_metadata()
                )
                metadata["attempt"] = attempt
                metadata["max_attempts"] = max_attempts
                if (state.metadata or {}).get("runner_provenance"):
                    metadata["runner_provenance"] = state.metadata["runner_provenance"]
                if retry_errors:
                    metadata["retry_errors"] = retry_errors
                attach_benchmark_status(
                    metadata,
                    agent_name=harness_adapter.agent_metadata_name,
                    model=model,
                )
                blocked = harness_adapter.blocked_surfaces(
                    result.agent_stdout, policy=policy
                )
                metadata["blocked_surfaces"] = blocked
                metadata["blocked_surface_count"] = int(
                    metadata.get("policy_block_count") or 0
                ) or len(blocked)
                activity = _activity_with_trace_fallback(
                    harness_adapter.activity_summary(result.agent_stdout),
                    metadata.get("full_trace"),
                )
                metadata["activity"] = activity
                metadata["recovery_skill_invocation_count"] = (
                    harness_adapter.recovery_skill_invocation_count(result.agent_stdout)
                )
                if activity["assistant_turns"] == 0 and not result.agent_timed_out:
                    raise _TransientTaskAttempt(
                        "agent produced zero assistant turns", result=result
                    )
                provider_err = harness_adapter.provider_auth_error(result.agent_stdout)
                if provider_err is not None and result.reward <= 0:
                    raise _TransientTaskAttempt(
                        f"provider/auth error detected: {provider_err.marker}",
                        result=result,
                    )
                accumulated_native_accounting = _merge_native_accounting(
                    accumulated_native_accounting,
                    getattr(result, "openrouter_accounting", None),
                )
                if accumulated_native_accounting is not None:
                    metadata["openrouter_accounting"] = accumulated_native_accounting
                reward, answer = result.reward, result.answer
                messages, output = harness_adapter.parse_transcript(
                    prompt=result.prompt,
                    agent_stdout=result.agent_stdout,
                    model=display_model,
                    pricing_model=pricing_model,
                    session_artifacts=result.harness_session_artifacts,
                )
                native_accounting = accumulated_native_accounting
                native_usage = _native_model_usage(native_accounting)
                if native_usage is not None:
                    stdout_usage_present = bool(
                        metadata.get("agent_model_usage_present")
                    )
                    output.usage = native_usage
                    metadata["agent_model_usage_present"] = True
                    metadata["agent_model_usage_source"] = "openrouter_accounting_proxy"
                    metadata["agent_model_usage_recovered"] = not stdout_usage_present
                metadata["full_trace"] = _trace_with_authoritative_usage(
                    metadata.get("full_trace"), native_usage
                )
                metadata["agent_model_usage_available"] = output.usage is not None
                metadata["agent_model_cost_available"] = bool(
                    output.usage is not None and output.usage.total_cost is not None
                )
                state.messages = messages
                output.metadata = {
                    key: value for key, value in metadata.items() if key != "full_trace"
                }
                state.output = output
                benchmark_daytona.record_model_usage(display_model, output.usage)
                state.metadata["transcript_markdown"] = _annotate_usage_transcript(
                    _annotate_effort_transcript(
                        harness_adapter.transcript_markdown(
                            task_id=task_id,
                            prompt=result.prompt,
                            model=display_model,
                            reward=reward,
                            answer=answer,
                            agent_stdout=result.agent_stdout,
                            timed_out=result.agent_timed_out,
                            policy=policy,
                            pricing_model=pricing_model,
                            benchmark_status=metadata.get("benchmark_status"),
                            policy_events=result.policy_events,
                            session_artifacts=result.harness_session_artifacts,
                        ),
                        effort_level=effective_effort,
                        source=effective_effort_source,
                    ),
                    usage=output.usage,
                )
                break
            except Exception as exc:  # noqa: BLE001 - isolate per-task failures
                is_transient = _is_transient_task_error(exc)
                error_text = repr(exc)[:1000]
                failed_attempt_result = _failed_attempt_result(exc)
                if failed_attempt_result is not None:
                    accumulated_native_accounting = _merge_native_accounting(
                        accumulated_native_accounting,
                        getattr(failed_attempt_result, "openrouter_accounting", None),
                    )
                if is_transient and attempt < max_attempts:
                    retry_errors.append(error_text)
                    await asyncio.sleep(TRANSIENT_RETRY_BACKOFF_SEC * attempt)
                    continue
                provider_err = _extract_provider_error_from_attempt(
                    exc, harness_adapter
                )
                is_preflight_error = isinstance(exc, PreflightFailedError)
                is_runtime_probe_error = isinstance(exc, DaytonaRuntimeProbeSuiteError)
                if is_preflight_error:
                    reward, answer = 0.0, "INVALID"
                elif provider_err is not None:
                    reward, answer = 0.0, "PROVIDER_ERROR"
                else:
                    reward, answer = 0.0, "ERROR"
                try:
                    selected_policy = resolve_policy(policy)
                    policy_overlays = list(selected_policy.overlays)
                    agent_user = selected_policy.agent_user
                    full_mac_enforcement = selected_policy.full_mac_enforcement
                    policy_applies_hardening = selected_policy.applies_hardening
                except Exception:  # noqa: BLE001 - preserve original task error
                    policy_overlays = []
                    agent_user = None
                    full_mac_enforcement = False
                    policy_applies_hardening = False
                failed_result = _failed_attempt_result(exc)
                metadata = (
                    _failed_result_metadata(failed_result)
                    if failed_result is not None
                    else {
                        "task_name": task_id,
                        "reward": 0.0,
                        "answer": "ERROR",
                    }
                )
                if isinstance(exc, _PostAgentVerifierError):
                    metadata["postflight_verification"] = exc.postflight_verification
                    metadata["submission_snapshot"] = exc.submission_snapshot
                if accumulated_native_accounting is not None:
                    metadata["openrouter_accounting"] = accumulated_native_accounting
                runtime_probe_report = (
                    exc.report.to_metadata()
                    if isinstance(exc, DaytonaRuntimeProbeSuiteError)
                    else None
                )
                metadata.update(
                    {
                        "reward": 0.0,
                        "answer": answer,
                        "error": error_text,
                        "policy": policy,
                        "block_message": (
                            metadata.get("hardening_config", {}).get("block_message")
                            or effective_block_message
                        ),
                        "policy_overlays": policy_overlays,
                        "full_mac_enforcement": full_mac_enforcement,
                        "agent_user": agent_user,
                        **HardeningClaims.derive(
                            policy_applies_hardening=policy_applies_hardening,
                            harness=harness_adapter,
                        ).to_metadata(),
                        "effort_level": effective_effort,
                        "effort_level_source": effective_effort_source,
                        "effort_level_applied": harness_adapter.effort_level_applied,
                        "policy_prompt": resolved_policy_prompt,
                        "recovery_bundle": resolved_recovery_bundle,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "transient_error": is_transient,
                        "preflight_failed": is_preflight_error,
                        "runtime_probe_failed": is_runtime_probe_error,
                        "post_agent_verifier_error": isinstance(
                            exc, _PostAgentVerifierError
                        ),
                        "provider_error": provider_err is not None,
                        "provider_error_detail": (
                            provider_err.to_metadata()
                            if provider_err is not None
                            else None
                        ),
                        "runtime_policy_probe_report": runtime_probe_report,
                        **_exception_metadata(exc),
                        **_phase_timing_exception_metadata(exc),
                    }
                )
                session_artifacts = getattr(exc, "harness_session_artifacts", None)
                if isinstance(session_artifacts, dict):
                    metadata["harness_session_artifacts"] = session_artifacts
                if is_preflight_error:
                    metadata["preflight_rejected"] = True
                    metadata["preflight_failed"] = True
                    metadata["preflight"] = exc.to_metadata()
                if (state.metadata or {}).get("runner_provenance"):
                    metadata["runner_provenance"] = state.metadata["runner_provenance"]
                if failed_result is not None:
                    metadata["full_trace"] = _build_full_trace(
                        harness_adapter,
                        agent_stdout=failed_result.agent_stdout,
                        model=pricing_model,
                        session_artifacts=failed_result.harness_session_artifacts,
                        policy_events=failed_result.policy_events,
                    )
                    metadata["blocked_surfaces"] = harness_adapter.blocked_surfaces(
                        failed_result.agent_stdout, policy=policy
                    )
                    metadata["blocked_surface_count"] = len(
                        metadata["blocked_surfaces"]
                    )
                    if metadata.get("policy_block_count"):
                        metadata["blocked_surface_count"] = int(
                            metadata["policy_block_count"]
                        )
                    metadata["activity"] = _activity_with_trace_fallback(
                        harness_adapter.activity_summary(failed_result.agent_stdout),
                        metadata.get("full_trace"),
                    )
                    metadata["recovery_skill_invocation_count"] = (
                        harness_adapter.recovery_skill_invocation_count(
                            failed_result.agent_stdout
                        )
                    )
                if retry_errors:
                    metadata["retry_errors"] = retry_errors
                attach_benchmark_status(
                    metadata,
                    agent_name=harness_adapter.agent_metadata_name,
                    model=model,
                )
                native_usage = _native_model_usage(accumulated_native_accounting)
                if native_usage is not None:
                    stdout_usage_present = bool(
                        metadata.get("agent_model_usage_present")
                    )
                    metadata["agent_model_usage_available"] = True
                    metadata["agent_model_usage_present"] = True
                    metadata["agent_model_usage_source"] = "openrouter_accounting_proxy"
                    metadata["agent_model_usage_recovered"] = not stdout_usage_present
                    metadata["agent_model_cost_available"] = (
                        native_usage.total_cost is not None
                    )
                metadata["full_trace"] = _trace_with_authoritative_usage(
                    metadata.get("full_trace"), native_usage
                )
                state.output = ModelOutput(
                    model=display_model,
                    completion=f"reward={reward} answer={answer}",
                    usage=native_usage,
                    metadata={
                        key: value
                        for key, value in metadata.items()
                        if key != "full_trace"
                    },
                )
                state.metadata["transcript_markdown"] = (
                    _annotate_effort_transcript(
                        harness_adapter.transcript_markdown(
                            task_id=task_id,
                            prompt=failed_result.prompt,
                            model=display_model,
                            reward=0.0,
                            answer=answer,
                            agent_stdout=failed_result.agent_stdout,
                            timed_out=failed_result.agent_timed_out,
                            policy=policy,
                            pricing_model=pricing_model,
                            benchmark_status=metadata.get("benchmark_status"),
                            policy_events=metadata.get("policy_events") or [],
                            session_artifacts=failed_result.harness_session_artifacts,
                        ),
                        effort_level=effective_effort,
                        source=effective_effort_source,
                    )
                    if failed_result is not None
                    else (
                        f"# Terminal-Bench — {task_id}\n\n"
                        f"- **Result:** {answer} (reward=0.0)\n"
                        f"- **Benchmark status:** "
                        f"task_outcome={metadata['benchmark_status']['task_outcome']} "
                        f"failure_class={metadata['benchmark_status']['failure_class']} "
                        f"valid_for_analysis="
                        f"{'yes' if metadata['benchmark_status']['valid_for_analysis'] else 'no'}\n"
                        f"- **Model (labelled):** {display_model}\n"
                        f"- **Effort level:** {effective_effort} "
                        f"({effective_effort_source})\n"
                        f"- **Attempt:** {attempt}/{max_attempts}\n\n"
                        f"{_preflight_failure_transcript_section(metadata)}"
                        f"## Error\n\n```\n{error_text}\n```\n"
                    )
                )
                state.metadata["transcript_markdown"] = _annotate_usage_transcript(
                    state.metadata["transcript_markdown"], usage=native_usage
                )
                benchmark_daytona.record_model_usage(display_model, native_usage)
                break
        state.metadata["terminalbench_daytona"] = metadata
        state.metadata["reward"] = reward
        state.completed = True
        return state

    return solve


def _build_full_trace(
    harness_adapter: Any,
    *,
    agent_stdout: str,
    model: str,
    session_artifacts: dict[str, Any] | None,
    policy_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Build the shared trace without making observability affect scoring."""

    try:
        trace = harness_adapter.canonical_trace(
            agent_stdout=agent_stdout,
            model=model,
            session_artifacts=session_artifacts,
            policy_events=policy_events,
        )
        return trace.to_mapping()
    except Exception as exc:  # noqa: BLE001 - trace export is best effort
        print(
            f"[terminalbench-daytona] WARN canonical trace build failed: {exc!r}",
            flush=True,
        )
        return None


def _activity_with_trace_fallback(
    activity: dict[str, int], trace: Any
) -> dict[str, int]:
    """Recover activity counts from the canonical trace when stdout is cut.

    Some harness runners emit a final error sentinel after doing substantial
    work (for example, Terminus-2 can surface ``CancelledError`` after its ATIF
    trajectory has already recorded many turns).  The official verifier still
    scores the preserved workspace, so treating the sentinel's missing summary
    counters as a zero-turn start discards a valid benchmark outcome and retries
    the whole task.  The canonical trace is built from the harness-native
    session artifacts immediately before this check and is the more complete
    activity source in that case.
    """

    def count(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    normalized = {
        "assistant_turns": count(activity.get("assistant_turns")),
        "tool_calls": count(activity.get("tool_calls")),
    }
    if not isinstance(trace, dict):
        return normalized
    normalized["assistant_turns"] = max(
        normalized["assistant_turns"],
        count(trace.get("assistant_message_count")),
    )
    normalized["tool_calls"] = max(
        normalized["tool_calls"],
        count(trace.get("tool_call_count")),
    )
    return normalized


def _trace_with_authoritative_usage(
    trace: Any, usage: ModelUsage | None
) -> dict[str, Any] | None:
    """Use the accounting proxy as the single cost/token authority when present."""

    if not isinstance(trace, dict) or usage is None:
        return trace if isinstance(trace, dict) else None
    normalized = dict(trace)
    canonical_usage = dict(normalized.get("usage") or {})
    canonical_usage.update(
        {
            "input_tokens": int(usage.input_tokens),
            "output_tokens": int(usage.output_tokens),
            "cache_read_tokens": int(usage.input_tokens_cache_read or 0),
            "cache_write_tokens": int(usage.input_tokens_cache_write or 0),
            "total_tokens": int(usage.total_tokens),
            "total_cost": usage.total_cost,
        }
    )
    if usage.total_cost is not None:
        canonical_usage["cost_source"] = "openrouter_accounting_proxy"
    else:
        canonical_usage.pop("cost_source", None)
    normalized["usage"] = canonical_usage
    return normalized


def _annotate_effort_transcript(
    markdown: str,
    *,
    effort_level: str,
    source: str,
) -> str:
    """Insert the normalized effort label into a harness transcript header."""

    effort_line = f"- **Effort level:** {effort_level} ({source})"
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("- **Model"):
            lines.insert(index + 1, effort_line)
            return "\n".join(lines)
    insert_at = 2 if len(lines) >= 2 else len(lines)
    lines.insert(insert_at, effort_line)
    return "\n".join(lines)


def _annotate_usage_transcript(markdown: str, *, usage: ModelUsage | None) -> str:
    """Render final model usage in the harness-independent transcript header."""

    if usage is None:
        return markdown
    cost_text = f"${usage.total_cost}" if usage.total_cost is not None else "unpriced"
    usage_line = (
        f"- **Usage:** in={usage.input_tokens} out={usage.output_tokens} "
        f"cache_read={usage.input_tokens_cache_read or 0} "
        f"cache_write={usage.input_tokens_cache_write or 0} cost={cost_text}"
    )
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("- **Usage:**"):
            lines[index] = usage_line
            return "\n".join(lines)
    effort_index = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("- **Effort level:**")
    )
    lines.insert(effort_index + 1, usage_line)
    return "\n".join(lines)


def _preflight_failure_transcript_section(metadata: dict[str, Any]) -> str:
    preflight = metadata.get("preflight")
    if not isinstance(preflight, dict):
        return ""
    failed_rules = ", ".join(preflight.get("failed_rule_ids") or []) or "none"
    failed_probes = ", ".join(preflight.get("failed_probe_ids") or []) or "none"
    proof_plan = preflight.get("proof_plan") or {}
    policy = proof_plan.get("policy") if isinstance(proof_plan, dict) else None
    probe_count = preflight.get("probe_count", 0)
    failed_count = preflight.get("failed_count", 0)
    return (
        "## Policy Preflight\n\n"
        f"- **Policy:** {policy or metadata.get('policy') or 'unknown'}\n"
        f"- **Passed:** false\n"
        f"- **Probes:** {probe_count}\n"
        f"- **Failed probes:** {failed_count}\n"
        f"- **Failed rules:** {failed_rules}\n"
        f"- **Failed probe IDs:** {failed_probes}\n\n"
    )


@scorer(metrics=[mean()])
def hardened_daytona_scorer():
    """Surface the official Harbor reward as the Inspect score."""

    async def score(state: TaskState, target: Target) -> Score:
        metadata = (state.metadata or {}).get("terminalbench_daytona") or {}
        reward = float(metadata.get("reward", 0.0))
        blocked = int(metadata.get("blocked_surface_count", 0))
        answer_raw = metadata.get("answer")
        is_provider_error = answer_raw == "PROVIDER_ERROR" or bool(
            metadata.get("provider_error")
        )
        is_preflight_error = answer_raw == "INVALID" and bool(
            metadata.get("preflight_rejected") or metadata.get("preflight_failed")
        )
        if is_provider_error:
            explanation = (
                "PROVIDER_ERROR — provider/auth failure; "
                "not a benchmark FAIL; excluded from benchmark metrics"
            )
            return Score.unscored(
                answer="PROVIDER_ERROR",
                explanation=explanation,
                metadata=metadata,
            )
        if is_preflight_error:
            explanation = (
                "INVALID — hardening preflight failure; "
                "not a benchmark FAIL; excluded from benchmark metrics"
            )
            return Score.unscored(
                answer="INVALID",
                explanation=explanation,
                metadata=metadata,
            )
        failure_class = _benchmark_failure_class(metadata)
        if answer_raw == "ERROR" and failure_class in _UNSCORED_INFRA_FAILURE_CLASSES:
            explanation = (
                f"{failure_class} - infrastructure failure; "
                "not a benchmark FAIL; excluded from benchmark metrics"
            )
            return Score.unscored(
                answer="ERROR",
                explanation=explanation,
                metadata=metadata,
            )
        else:
            explanation = f"Official Harbor verifier reward={reward}"
            if metadata.get("agent_timed_out"):
                explanation += " (agent cut at timeout)"
            explanation += f"; policy blocks={blocked}"
        answer = str(answer_raw or ("PASS" if reward > 0 else "FAIL"))
        return Score(
            value=reward,
            answer=answer,
            explanation=explanation,
            metadata=metadata,
        )

    return score


def _task_ids(task_ids: str | list[str]) -> list[str]:
    if isinstance(task_ids, str):
        return [tid.strip() for tid in task_ids.split(",") if tid.strip()]
    return [str(tid) for tid in task_ids]


def _effective_agent_timeout_sec(
    requested_agent_timeout_sec: int,
    task_agent_timeout_sec: int | None,
) -> int:
    if task_agent_timeout_sec is None:
        return requested_agent_timeout_sec
    return task_agent_timeout_sec


@task
def hardened_terminalbench_daytona(
    task_ids: str | list[str] = "log-summary-date-ranges",
    ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    model: str = DEFAULT_OPENROUTER_MODEL,
    policy: str = DEFAULT_POLICY_NAME,
    block_message: str | None = None,
    harness: str = DEFAULT_HARNESS,
    effort: str | None = None,
    policy_prompt: str = POLICY_PROMPT_OFF,
    recovery_bundle: str = RECOVERY_BUNDLE_OFF,
    include_not_applicable: bool = False,
    all_tasks: bool = False,
    exclude_not_applicable: bool = False,
    harden: str | None = None,
    egress_mode: str | None = None,
    egress_allow: str | None = None,
) -> Task:
    """Run one or more Terminal-Bench tasks in hardened Daytona sandboxes.

    `task_ids` is a comma-separated list (or list) of terminal-bench-2.1 task ids.
    `all_tasks` ignores `task_ids` and runs the full pinned universe (89 tasks);
    conflicted tasks run too and are stamped ``not_applicable``. Pass
    ``exclude_not_applicable=True`` to drop conflicted tasks from the selection
    instead (a no-op under control, where every task is applicable).
    `policy` selects the native N×F×P hardening preset applied to every sample
    ("control" leaves the Daytona/task-image baseline alone); validated up front
    and recorded on each sample so a run can be filtered/compared by policy.

    `harden` builds a custom policy from a plain-language surface selection
    (comma-separated keys from `custom_policy.SURFACES`, e.g.
    "non-root,readonly-os,restrict-egress"); it takes precedence over `policy`.
    `egress_mode` refines `restrict-egress` (trusted | task-only | custom) and
    `egress_allow` supplies a bring-your-own domain allowlist for `custom`.

    Tasks whose own instruction conflicts with the selected policy (see
    ``task_applicability.POLICY_INAPPLICABLE_TASKS``) are rejected up front —
    running them would spend a sandbox and inference on a result that is
    ``not_applicable`` by design. Pass ``include_not_applicable=True`` for
    research sweeps that deliberately execute the full task universe.
    """

    if harden is not None:
        compiled = compile_custom_policy(
            harden, egress_mode=egress_mode, egress_domains=egress_allow
        )
        selected_policy = compiled.policy
        policy = compiled.policy_id
    else:
        selected_policy = resolve_policy_for_run(
            policy
        )
    harness_adapter = get_harness_adapter(harness)
    effective_effort = normalize_effort_level(harness_adapter, effort)
    effective_effort_source = effort_level_source(effort)
    resolved_policy_prompt = validate_policy_prompt(policy_prompt)
    resolved_recovery_bundle = validate_recovery_bundle(recovery_bundle)
    selected_config = (
        selected_policy.config.with_block_message(block_message)
        if block_message is not None
        else selected_policy.config
    )
    selected_config = _with_harness_health_domains(selected_config, harness_adapter)
    selected_config = _with_harness_home_carveouts(selected_config, harness_adapter)
    if include_not_applicable and exclude_not_applicable:
        raise ValueError(
            "include_not_applicable and exclude_not_applicable are mutually "
            "exclusive"
        )
    ids = list(all_task_ids()) if all_tasks else _task_ids(task_ids)
    if exclude_not_applicable:
        ids = [
            tid
            for tid in ids
            if policy_applicability(tid, policy) != NOT_APPLICABLE
        ]
        if not ids:
            raise ValueError(
                f"no tasks left under policy {policy!r} after excluding "
                "not-applicable tasks"
            )
    elif not all_tasks and not include_not_applicable:
        conflicted = [
            tid
            for tid in ids
            if policy_applicability(tid, policy) == NOT_APPLICABLE
        ]
        if conflicted:
            details = "; ".join(
                f"{tid}: {policy_applicability_reason(tid, policy)}"
                for tid in conflicted
            )
            raise ValueError(
                f"task(s) not applicable under policy {policy!r} — {details}. "
                "These tasks conflict with the policy by their own instruction "
                "and cannot pass; run them under policy=control, or pass "
                "include_not_applicable=true (CLI: confirm at the prompt or "
                "pass --yes) to execute them anyway as a research sweep."
            )
    runner_provenance = runtime_provenance()
    samples = [
        Sample(
            id=tid,
            input=tid,
            metadata={
                "terminal_bench_task_id": tid,
                "dataset": "terminal-bench-2.1",
                "dataset_version": "terminal-bench-2.1",
                "harbor_package_ref": ref,
                **HardeningClaims.derive(
                    policy_applies_hardening=selected_policy.applies_hardening,
                    harness=harness_adapter,
                ).to_metadata(),
                "policy": policy,
                "policy_overlays": list(selected_policy.overlays),
                "full_mac_enforcement": selected_policy.full_mac_enforcement,
                "block_message": selected_config.block_message,
                "hardening_config": selected_config.to_metadata(),
                "agent_user": selected_policy.agent_user,
                "agent": harness_adapter.agent_metadata_name,
                "model": model,
                "effort_level": effective_effort,
                "effort_level_source": effective_effort_source,
                "effort_level_applied": harness_adapter.effort_level_applied,
                "policy_prompt": resolved_policy_prompt,
                "recovery_bundle": resolved_recovery_bundle,
                "runner_provenance": runner_provenance,
                **applicability_metadata(tid, policy),
            },
        )
        for tid in ids
    ]
    return Task(
        dataset=MemoryDataset(samples),
        solver=hardened_daytona_solver(
            ref=ref,
            model=model,
            block_message=block_message,
            harness=harness,
            effort=effort,
            policy_prompt=policy_prompt,
            recovery_bundle=recovery_bundle,
        ),
        scorer=hardened_daytona_scorer(),
        sandbox=None,
    )
