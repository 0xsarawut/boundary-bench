from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any


BENCHMARK_STATUS_SCHEMA = "boundarybench.benchmark-status.v1"


class JobStatus(str, enum.Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class EvalArtifactStatus(str, enum.Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    UNKNOWN = "unknown"


class TaskOutcome(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INVALID = "INVALID"


class FailureClass(str, enum.Enum):
    NONE = "none"
    TASK_MODEL = "task_model"
    REFERENCE_SOLUTION = "reference_solution"
    INFRA_DAYTONA = "infra_daytona"
    INFRA_RESOURCE = "infra_resource"
    INFRA_TIMEOUT = "infra_timeout"
    PROVIDER_AUTH = "provider_auth"
    PROVIDER_RATE_LIMIT = "provider_rate_limit"
    PROVIDER_ERROR = "provider_error"
    HARDENING_PREFLIGHT = "hardening_preflight"
    HARDENING_RUNTIME = "hardening_runtime"
    VERIFIER_TIMEOUT = "verifier_timeout"
    VERIFIER_ERROR = "verifier_error"
    ARTIFACT_MISSING = "artifact_missing"
    UNKNOWN = "unknown"


TASK_OUTCOME_ORDER = tuple(outcome.value for outcome in TaskOutcome)
FAILURE_CLASS_ORDER = tuple(failure.value for failure in FailureClass)


@dataclass(frozen=True)
class BenchmarkSummary:
    job_status: JobStatus
    eval_artifact_status: EvalArtifactStatus
    total_tasks: int
    passed: int
    failed: int
    errors: int
    invalid: int
    valid_sample_count: int
    failure_class_counts: dict[str, int] = field(default_factory=dict)
    task_outcome_counts: dict[str, int] = field(default_factory=dict)

    @property
    def invalid_sample_count(self) -> int:
        return self.total_tasks - self.valid_sample_count

    @property
    def has_analysis_signal(self) -> bool:
        return (
            self.valid_sample_count > 0
            and self.job_status == JobStatus.COMPLETED
            and self.eval_artifact_status
            in {EvalArtifactStatus.COMPLETE, EvalArtifactStatus.PARTIAL}
        )

    @property
    def all_samples_valid_for_analysis(self) -> bool:
        return self.total_tasks > 0 and self.valid_sample_count == self.total_tasks

    @property
    def valid_for_analysis(self) -> bool:
        return self.has_analysis_signal and self.all_samples_valid_for_analysis

    @property
    def success_rate(self) -> float | None:
        if self.valid_sample_count == 0:
            return None
        return self.passed / self.valid_sample_count

    def to_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": BENCHMARK_STATUS_SCHEMA,
            "job_status": self.job_status.value,
            "eval_artifact_status": self.eval_artifact_status.value,
            "total_tasks": self.total_tasks,
            "total_samples": self.total_tasks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "invalid": self.invalid,
            "valid_sample_count": self.valid_sample_count,
            "invalid_sample_count": self.invalid_sample_count,
            "has_analysis_signal": self.has_analysis_signal,
            "all_samples_valid_for_analysis": self.all_samples_valid_for_analysis,
            "valid_for_analysis": self.valid_for_analysis,
            "success_rate": self.success_rate,
            "task_outcome_counts": dict(self.task_outcome_counts),
            "failure_class_counts": dict(self.failure_class_counts),
        }


JOB_STATUS_UNKNOWN = JobStatus.UNKNOWN
JOB_STATUS_SUCCEEDED = JobStatus.COMPLETED
JOB_STATUS_FAILED = JobStatus.FAILED

EVAL_ARTIFACT_STATUS_UNKNOWN = EvalArtifactStatus.UNKNOWN
EVAL_ARTIFACT_STATUS_WRITTEN = EvalArtifactStatus.COMPLETE
EVAL_ARTIFACT_STATUS_MISSING = EvalArtifactStatus.MISSING
EVAL_ARTIFACT_STATUS_UNREADABLE = EvalArtifactStatus.UNREADABLE


def sample_benchmark_status(
    metadata: dict[str, Any],
    *,
    job_status: JobStatus | str = JobStatus.UNKNOWN,
    eval_artifact_status: EvalArtifactStatus | str = EvalArtifactStatus.UNKNOWN,
) -> dict[str, Any]:
    """Normalize one benchmark sample into the shared status taxonomy."""

    task_outcome = _task_outcome(metadata)
    failure_class = classify_failure(
        task_outcome,
        error_text=_classification_text(metadata),
        transient_error=bool(metadata.get("transient_error")),
        agent_timed_out=bool(metadata.get("agent_timed_out")),
        verifier_timed_out=_verifier_timed_out(metadata),
        verifier_error=bool(metadata.get("post_agent_verifier_error")),
        preflight_rejected=_preflight_rejected(metadata),
        provider_error=bool(metadata.get("provider_error")),
        reference_solution=(metadata.get("execution_mode") == "reference_solution"),
    )
    return {
        "schema_version": BENCHMARK_STATUS_SCHEMA,
        "job_status": _value(job_status),
        "eval_artifact_status": _value(eval_artifact_status),
        "task_outcome": task_outcome.value,
        "failure_class": failure_class.value,
        "valid_for_analysis": valid_for_analysis(task_outcome, failure_class),
    }


def agent_entity(
    *,
    name: str,
    model: str,
    benchmark_status: dict[str, Any],
) -> dict[str, Any]:
    """Build the agent-shaped metadata block exported alongside sample status."""

    return {
        "name": name,
        "model": model,
        "benchmark_status": dict(benchmark_status),
    }


def attach_benchmark_status(
    metadata: dict[str, Any],
    *,
    agent_name: str,
    model: str,
) -> dict[str, Any]:
    """Attach the shared benchmark status and agent metadata to a sample block."""

    benchmark_status = sample_benchmark_status(metadata)
    metadata["benchmark_status"] = benchmark_status
    metadata["agent_entity"] = agent_entity(
        name=agent_name,
        model=model,
        benchmark_status=benchmark_status,
    )
    return metadata


def eval_artifact_status_from_completeness(
    completeness: Any | None,
) -> EvalArtifactStatus:
    """Map run-completeness metadata onto the benchmark artifact taxonomy."""

    if completeness is None:
        return EvalArtifactStatus.MISSING
    status = str(getattr(completeness, "status", "") or "").lower()
    completed_samples = int(getattr(completeness, "completed_samples", 0) or 0)
    if status == "complete":
        return EvalArtifactStatus.COMPLETE
    if status == "partial":
        return EvalArtifactStatus.PARTIAL
    if status == "empty":
        return EvalArtifactStatus.MISSING
    if status == "error":
        return (
            EvalArtifactStatus.PARTIAL
            if completed_samples > 0
            else EvalArtifactStatus.UNREADABLE
        )
    return EvalArtifactStatus.UNKNOWN


def print_benchmark_summary(
    *,
    log_prefix: str,
    samples: list[Any],
    metadata_key: str,
    job_status: JobStatus | str,
    eval_artifact_status: EvalArtifactStatus | str,
    task_name: str | None = None,
) -> bool:
    """Print a run summary without allowing malformed sample metadata to abort cleanup."""

    task_context = f"task={task_name} " if task_name else ""
    try:
        summary = benchmark_summary(
            sample_statuses_from_samples(
                samples,
                metadata_key=metadata_key,
            ),
            job_status=job_status,
            eval_artifact_status=eval_artifact_status,
        )
        print(
            f"[{log_prefix}] {task_context}benchmark_summary="
            + json.dumps(summary, sort_keys=True),
            flush=True,
        )
        print(
            f"[{log_prefix}] {task_context}benchmark_summary_counts "
            + format_benchmark_summary_counts(summary),
            flush=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001 - status logging must not break cleanup
        print(
            f"[{log_prefix}] WARN {task_context}benchmark_summary failed: {exc!r}",
            flush=True,
        )
        return False


def format_benchmark_summary_counts(summary: dict[str, Any]) -> str:
    """Render run status counts as a compact operator-facing log fragment."""

    return " ".join(
        [
            f"job_status={summary.get('job_status', JobStatus.UNKNOWN.value)}",
            "eval_artifact_status="
            f"{summary.get('eval_artifact_status', EvalArtifactStatus.UNKNOWN.value)}",
            f"valid_for_analysis={str(summary.get('valid_for_analysis')).lower()}",
            f"has_analysis_signal={str(summary.get('has_analysis_signal')).lower()}",
            f"valid_samples={int(summary.get('valid_sample_count') or 0)}",
            f"invalid_samples={int(summary.get('invalid_sample_count') or 0)}",
            _format_count_group(
                "task_outcomes",
                TASK_OUTCOME_ORDER,
                summary.get("task_outcome_counts"),
            ),
            _format_count_group(
                "failure_classes",
                FAILURE_CLASS_ORDER,
                summary.get("failure_class_counts"),
            ),
        ]
    )


def _format_count_group(
    label: str,
    keys: tuple[str, ...],
    counts: Any,
) -> str:
    count_map = counts if isinstance(counts, dict) else {}
    rendered = " ".join(f"{key}={int(count_map.get(key) or 0)}" for key in keys)
    return f"{label} {rendered}"


def benchmark_summary(
    sample_statuses: list[dict[str, Any]],
    *,
    job_status: JobStatus | str,
    eval_artifact_status: EvalArtifactStatus | str,
) -> dict[str, Any]:
    """Aggregate sample statuses into the run-level benchmark summary."""

    task_results = [
        (
            _task_outcome_enum(status["task_outcome"]),
            _failure_class_enum(status["failure_class"]),
        )
        for status in sample_statuses
    ]
    return build_benchmark_summary(
        job_status=job_status,
        eval_artifact_status=eval_artifact_status,
        task_results=task_results,
    ).to_metadata()


def build_benchmark_summary(
    *,
    job_status: JobStatus | str,
    eval_artifact_status: EvalArtifactStatus | str,
    task_results: list[tuple[TaskOutcome | str, FailureClass | str]],
) -> BenchmarkSummary:
    """Build the typed run summary from classified per-task results."""

    job = _job_status(job_status)
    artifact = _eval_artifact_status(eval_artifact_status)
    normalized_results = [
        (_task_outcome_enum(outcome), _failure_class_enum(failure_class))
        for outcome, failure_class in task_results
    ]
    task_outcome_counts = _counts(outcome.value for outcome, _ in normalized_results)
    failure_class_counts = _counts(
        failure_class.value for _, failure_class in normalized_results
    )
    valid_sample_count = sum(
        1
        for outcome, failure_class in normalized_results
        if valid_for_analysis(outcome, failure_class)
    )
    return BenchmarkSummary(
        job_status=job,
        eval_artifact_status=artifact,
        total_tasks=len(normalized_results),
        passed=task_outcome_counts.get(TaskOutcome.PASS.value, 0),
        failed=task_outcome_counts.get(TaskOutcome.FAIL.value, 0),
        errors=task_outcome_counts.get(TaskOutcome.ERROR.value, 0),
        invalid=task_outcome_counts.get(TaskOutcome.INVALID.value, 0),
        valid_sample_count=valid_sample_count,
        failure_class_counts=failure_class_counts,
        task_outcome_counts=task_outcome_counts,
    )


def sample_statuses_from_samples(
    samples: list[Any],
    *,
    metadata_key: str,
) -> list[dict[str, Any]]:
    """Read normalized statuses from Inspect samples, falling back to metadata."""

    statuses: list[dict[str, Any]] = []
    for sample in samples:
        metadata = getattr(sample, "metadata", None) or {}
        benchmark_metadata = metadata.get(metadata_key) or {}
        if not isinstance(benchmark_metadata, dict):
            benchmark_metadata = {}
        status = benchmark_metadata.get("benchmark_status")
        statuses.append(
            status
            if isinstance(status, dict)
            else sample_benchmark_status(benchmark_metadata)
        )
    return statuses


def classify_task_outcome(answer: str) -> TaskOutcome:
    normalized = str(answer or "").strip().upper()
    try:
        return TaskOutcome(normalized)
    except ValueError:
        return TaskOutcome.ERROR


def classify_failure(
    outcome: TaskOutcome | str,
    *,
    error_text: str = "",
    transient_error: bool = False,
    agent_timed_out: bool = False,
    verifier_timed_out: bool = False,
    verifier_error: bool = False,
    preflight_rejected: bool = False,
    provider_error: bool = False,
    reference_solution: bool = False,
) -> FailureClass:
    task_outcome = _task_outcome_enum(outcome)
    text = error_text.lower()

    if reference_solution:
        if task_outcome == TaskOutcome.INVALID or preflight_rejected:
            return FailureClass.HARDENING_PREFLIGHT
        if verifier_timed_out:
            return FailureClass.VERIFIER_TIMEOUT
        if verifier_error:
            return FailureClass.VERIFIER_ERROR
    if task_outcome == TaskOutcome.PASS:
        return FailureClass.NONE
    if task_outcome == TaskOutcome.INVALID or preflight_rejected:
        return FailureClass.HARDENING_PREFLIGHT
    if task_outcome == TaskOutcome.FAIL:
        return (
            FailureClass.REFERENCE_SOLUTION
            if reference_solution
            else FailureClass.TASK_MODEL
        )
    if provider_error:
        if _contains_any(text, _PROVIDER_AUTH_MARKERS):
            return FailureClass.PROVIDER_AUTH
        if _contains_any(text, _PROVIDER_RATE_LIMIT_MARKERS):
            return FailureClass.PROVIDER_RATE_LIMIT
        return FailureClass.PROVIDER_ERROR
    if verifier_timed_out:
        return FailureClass.VERIFIER_TIMEOUT
    if verifier_error:
        return FailureClass.VERIFIER_ERROR
    if _is_daytona_account_capacity_error(text):
        return FailureClass.INFRA_RESOURCE
    if transient_error:
        return FailureClass.INFRA_DAYTONA
    if agent_timed_out:
        return FailureClass.INFRA_TIMEOUT
    if _contains_any(text, _ARTIFACT_MISSING_MARKERS):
        return FailureClass.ARTIFACT_MISSING
    if _contains_any(text, _VERIFIER_ERROR_MARKERS):
        return FailureClass.VERIFIER_ERROR
    if _contains_any(text, _PROVIDER_AUTH_MARKERS):
        return FailureClass.PROVIDER_AUTH
    if _contains_any(text, _RESOURCE_MARKERS):
        return FailureClass.INFRA_RESOURCE
    if _contains_any(text, _PROVIDER_RATE_LIMIT_MARKERS):
        return FailureClass.PROVIDER_RATE_LIMIT
    if _contains_any(text, _PROVIDER_ERROR_MARKERS):
        return FailureClass.PROVIDER_ERROR
    if _contains_any(text, _DAYTONA_MARKERS):
        return FailureClass.INFRA_DAYTONA
    if _contains_any(text, _HARDENING_RUNTIME_MARKERS):
        return FailureClass.HARDENING_RUNTIME
    if _contains_any(text, _HARDENING_PREFLIGHT_MARKERS):
        return FailureClass.HARDENING_PREFLIGHT
    return FailureClass.UNKNOWN


def valid_for_analysis(
    outcome: TaskOutcome | str,
    failure_class: FailureClass | str,
) -> bool:
    return _task_outcome_enum(outcome) in {TaskOutcome.PASS, TaskOutcome.FAIL} and (
        _failure_class_enum(failure_class)
        in {
            FailureClass.NONE,
            FailureClass.TASK_MODEL,
            FailureClass.REFERENCE_SOLUTION,
        }
    )


def is_daytona_account_capacity_error(text: str) -> bool:
    """Return whether text names a retryable Daytona account capacity limit."""

    return _is_daytona_account_capacity_error(text.lower())


def _task_outcome(metadata: dict[str, Any]) -> TaskOutcome:
    raw_answer = str(metadata.get("answer") or "").strip().upper()
    if raw_answer:
        return classify_task_outcome(raw_answer)
    if metadata.get("error"):
        return TaskOutcome.ERROR
    reward = metadata.get("reward")
    try:
        return TaskOutcome.PASS if float(reward) > 0 else TaskOutcome.FAIL
    except (TypeError, ValueError):
        return TaskOutcome.INVALID


def _classification_text(metadata: dict[str, Any]) -> str:
    parts = [
        metadata.get("error"),
        metadata.get("agent_stdout"),
        metadata.get("verifier", {}).get("stdout")
        if isinstance(metadata.get("verifier"), dict)
        else None,
    ]
    return "\n".join(str(part).lower() for part in parts if part)


def _verifier_timed_out(metadata: dict[str, Any]) -> bool:
    verifier = metadata.get("verifier")
    if isinstance(verifier, dict):
        return bool(verifier.get("timed_out"))
    return False


def _preflight_rejected(metadata: dict[str, Any]) -> bool:
    return bool(
        metadata.get("preflight_rejected")
        or metadata.get("harness_start_blocked")
        or metadata.get("preflight_failed")
        or _runtime_policy_probe_failed(metadata)
    )


def _runtime_policy_probe_failed(metadata: dict[str, Any]) -> bool:
    report = metadata.get("runtime_policy_probe_report")
    if not isinstance(report, dict):
        return False
    if report.get("passed") is False:
        return True
    try:
        return int(report.get("required_failed_count") or 0) > 0
    except (TypeError, ValueError):
        return False


def _value(value: enum.Enum | str) -> str:
    return value.value if isinstance(value, enum.Enum) else str(value)


def _task_outcome_enum(value: TaskOutcome | str) -> TaskOutcome:
    return (
        value if isinstance(value, TaskOutcome) else classify_task_outcome(str(value))
    )


def _failure_class_enum(value: FailureClass | str) -> FailureClass:
    if isinstance(value, FailureClass):
        return value
    return FailureClass(str(value))


def _job_status(value: JobStatus | str) -> JobStatus:
    return value if isinstance(value, JobStatus) else JobStatus(str(value))


def _eval_artifact_status(value: EvalArtifactStatus | str) -> EvalArtifactStatus:
    return (
        value
        if isinstance(value, EvalArtifactStatus)
        else EvalArtifactStatus(str(value))
    )


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _is_daytona_account_capacity_error(text: str) -> bool:
    if _contains_any(text, _ACCOUNT_RESOURCE_LIMIT_MARKERS):
        return True
    return _contains_any(text, _DAYTONA_CAPACITY_CONTEXT_MARKERS) and _contains_any(
        text,
        _ACCOUNT_CAPACITY_MARKERS,
    )


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


DAYTONA_LIFECYCLE_MARKERS = (
    "daytonaerror",
    "daytonanotfounderror",
    "daytonavalidationerror",
    "daytonaauthenticationerror",
    "sandbox container not found",
    "sandbox with id or name",
    "no such container",
    "failed to get session command",
    "failed to execute command:",
    "bearer token is invalid",
    "no ip address found",
    "is the sandbox started",
    "runtime layering failed",
)

DAYTONA_CONNECTION_MARKERS = (
    "remote end closed connection",
    "remotedisconnected",
    "connection aborted",
    "connection reset",
    "connection refused",
    "connection timed out",
    "read timed out",
)

DAYTONA_FAILURE_MARKERS = (
    *DAYTONA_LIFECYCLE_MARKERS,
    "daytona",
    "sandbox",
    *DAYTONA_CONNECTION_MARKERS,
)

RESOURCE_FAILURE_MARKERS = (
    "no space left on device",
    "enospc",
    "disk quota exceeded",
    "cannot allocate memory",
    "out of memory",
    "oom-kill",
    "oom_kill",
    "oomkill",
    "memory limit",
    "resource exhausted",
)

_ACCOUNT_RESOURCE_LIMIT_MARKERS = (
    "total disk limit exceeded",
    "total memory limit exceeded",
    "account storage capacity exceeded",
    "account storage capacity",
)

_ACCOUNT_CAPACITY_MARKERS = (
    *_ACCOUNT_RESOURCE_LIMIT_MARKERS,
    "sandbox capacity exhausted",
    "sandbox capacity exceeded",
    "sandbox quota exceeded",
    "quota exceeded while creating sandbox",
    "capacity exhausted",
)

_DAYTONA_CAPACITY_CONTEXT_MARKERS = (
    "daytona",
    "sandbox",
)

_DAYTONA_MARKERS = DAYTONA_FAILURE_MARKERS
_RESOURCE_MARKERS = RESOURCE_FAILURE_MARKERS

_PROVIDER_AUTH_MARKERS = (
    "authentication failed",
    "invalid api key",
    "invalid_api_key",
    "unauthorized",
    "forbidden",
    "http 401",
    "http 403",
    "api key expired",
    "invalid credentials",
    "key limit",
    "key-limit",
    "budget",
    "credits",
)

_PROVIDER_RATE_LIMIT_MARKERS = (
    "rate limit",
    "rate_limit",
    "ratelimit",
    "too many requests",
    "429",
    "quota exceeded",
    "capacity",
    "overloaded",
)

_PROVIDER_ERROR_MARKERS = (
    "openrouter",
    "anthropic",
    "openai",
    "provider",
    "model error",
    "model_error",
    "bad gateway",
    "gateway timeout",
    "service unavailable",
    "temporarily unavailable",
    "max retries exceeded",
    "500 internal server error",
    "502",
    "503",
    "504",
)

_VERIFIER_ERROR_MARKERS = (
    "verifier crashed",
    "verifier error",
    "reward.json",
    "reward.txt",
    "no reward file",
    "verifier_timeout",
    "submission snapshot export failed",
    "submission snapshot import failed",
    "submission snapshot too large",
    "clean verifier runtime layering failed",
)

_HARDENING_PREFLIGHT_MARKERS = (
    "agentsh",
    "preflight",
    "policy validate",
    "policy validation",
    "harness start blocked",
)

_HARDENING_RUNTIME_MARKERS = (
    "policy hardening",
    "ld_preload",
    "interceptor",
    "hardening install",
    "hardening_runtime",
)

_ARTIFACT_MISSING_MARKERS = (
    "missing expected artifact",
    "no eval logs",
    "artifact missing",
    "artifact_missing",
    "log not found",
    "eval file not found",
)
