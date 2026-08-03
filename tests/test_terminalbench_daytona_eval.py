from __future__ import annotations

import asyncio
import dataclasses
import json
import math
import sys

import pytest
from inspect_ai._eval.task.results import ScorerInfo, scorer_for_metrics
from inspect_ai.scorer import SampleScore, Score, mean
from inspect_ai.solver import TaskState

import boundarybench.terminalbench.pricing as pricing
import boundarybench.terminalbench.daytona_eval as daytona_eval_module
from boundarybench.terminalbench import task_applicability as ta
import boundarybench.task_runtime.sandbox as task_runtime_sandbox_module
from boundarybench.daytona.hardening_config import DEFAULT_DAYTONA_HARDENING_CONFIG
from boundarybench.daytona.runtime_policy_probes import (
    DAYTONA_HARDENING_RUNTIME_TARGET,
    RUNTIME_POLICY_PROBE_WORKSPACE,
    DaytonaRuntimeProbeSuiteError,
    RuntimePolicyProbeReport,
    RuntimePolicyProbeResult,
)
from boundarybench.terminalbench.daytona import (
    DaytonaVerifierResult,
    TerminalBenchTaskBundle,
)
from boundarybench.terminalbench.daytona_constants import DAYTONA_MAX_PARALLEL
from boundarybench.terminalbench.daytona_eval import (
    _is_resource_task_error,
    _is_transient_infra_task_error,
    _with_harness_health_domains,
    hardened_daytona_scorer,
    hardened_daytona_solver,
    hardened_terminalbench_daytona,
    max_concurrent,
    run_one_hardened_task,
)
from boundarybench.terminalbench.daytona_preflight import (
    PREFLIGHT_SCHEMA,
    PreflightFailedError,
    PreflightResult,
    build_policy_proof_plan,
)
from boundarybench.terminalbench.daytona_run import (
    AGENT_LISTENER_PROBE_COMMAND,
    TerminalBenchAgentRunResult,
    TerminalBenchRunResult,
)
from boundarybench.terminalbench.task_config import (
    resolve_agent_session_lifecycle,
)
from boundarybench.terminalbench.policies import (
    HardeningPolicy,
)


@pytest.fixture(autouse=True)
def _static_pricing(monkeypatch):
    monkeypatch.setattr(
        pricing, "openrouter_pricing", lambda: pricing.STATIC_OPENROUTER_PRICING
    )


@pytest.fixture(autouse=True)
def _fake_daytona_sdk_for_non_live_fakes(monkeypatch):
    try:
        __import__("daytona_sdk")
    except ModuleNotFoundError:
        monkeypatch.setitem(
            sys.modules,
            "daytona_sdk",
            type("FakeDaytonaSdkModule", (), {"Daytona": object}),
        )


def test_max_concurrent_clamps_to_daytona_cap(monkeypatch):
    assert DAYTONA_MAX_PARALLEL == 100
    monkeypatch.setenv("BOUNDARYBENCH_MAX_CONCURRENT", "250")
    assert max_concurrent() == 100
    monkeypatch.setenv("BOUNDARYBENCH_MAX_CONCURRENT", "89")
    assert max_concurrent() == 89
    monkeypatch.delenv("BOUNDARYBENCH_MAX_CONCURRENT", raising=False)
    assert max_concurrent() == 5


def test_run_one_task_rejects_invalid_verifier_attempts_before_daytona_work(
    monkeypatch,
):
    class UnexpectedDaytona:
        def __init__(self):
            raise AssertionError("Daytona work started before config validation")

    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "0")
    monkeypatch.setattr("daytona_sdk.Daytona", UnexpectedDaytona)

    with pytest.raises(
        ValueError,
        match=(
            "BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS must be an integer "
            "between 1 and 10"
        ),
    ):
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )


def test_resource_error_detection_avoids_substring_false_positives():
    assert _is_resource_task_error(RuntimeError("No space left on device"))
    assert _is_resource_task_error(RuntimeError("container OOM-kill event"))
    assert not _is_resource_task_error(
        RuntimeError(
            "failed to create sandbox from image alexgshaw/make-doom-for-mips:20251031"
        )
    )
    assert not _is_resource_task_error(RuntimeError("process killed due to timeout"))


def test_transient_infra_error_detection_blocks_resource_retry():
    assert _is_transient_infra_task_error(
        RuntimeError(
            "DaytonaValidationError: no IP address found. Is the Sandbox started?"
        )
    )


def test_retry_markers_reuse_shared_daytona_status_taxonomy():
    import boundarybench.terminalbench.daytona_eval as daytona_eval
    from boundarybench.benchmarks.common.status_taxonomy import (
        DAYTONA_CONNECTION_MARKERS,
        DAYTONA_LIFECYCLE_MARKERS,
        RESOURCE_FAILURE_MARKERS,
    )

    assert daytona_eval.DAYTONA_LIFECYCLE_MARKERS is DAYTONA_LIFECYCLE_MARKERS
    assert daytona_eval.DAYTONA_CONNECTION_MARKERS is DAYTONA_CONNECTION_MARKERS
    assert daytona_eval.RESOURCE_FAILURE_MARKERS is RESOURCE_FAILURE_MARKERS
    assert set(DAYTONA_LIFECYCLE_MARKERS).issubset(
        set(daytona_eval._TRANSIENT_ERROR_MARKERS)
    )
    assert set(DAYTONA_LIFECYCLE_MARKERS).issubset(
        set(daytona_eval._TRANSIENT_INFRA_RESOURCE_RETRY_BLOCKERS)
    )
    assert set(DAYTONA_CONNECTION_MARKERS).issubset(
        set(daytona_eval._TRANSIENT_ERROR_MARKERS)
    )
    assert set(daytona_eval._RESOURCE_ERROR_MARKERS) == set(RESOURCE_FAILURE_MARKERS)


_STREAM = (
    '{"type":"assistant","message":{"content":[{"type":"text","text":"working"},'
    '{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}],"model":"m"}}\n'
    '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"file.txt"}]}}\n'
    '{"type":"result","subtype":"success","result":"done","total_cost_usd":0.12,'
    '"usage":{"input_tokens":100,"output_tokens":20}}'
)


def _fake_result(
    task_id: str,
    reward: float,
    *,
    agent_stdout: str = _STREAM,
    agent_stderr: str = "",
    agent_exit_code: int = 0,
    policy_events: list[dict] | None = None,
    preflight: dict | None = None,
    task_net_runtime_ms: int | None = None,
    openrouter_accounting: dict | None = None,
    harness_session_artifacts: dict | None = None,
    harness: str = "claude_code",
) -> TerminalBenchRunResult:
    answer = "PASS" if reward > 0 else "FAIL"
    return TerminalBenchRunResult(
        sample_id=task_id,
        task_name=f"terminal-bench/{task_id}",
        prompt="solve the task",
        reward=reward,
        answer=answer,
        agent_exit_code=agent_exit_code,
        agent_stdout=agent_stdout,
        agent_stderr=agent_stderr,
        verifier=DaytonaVerifierResult(
            value=reward, answer=answer, exit_code=0, stdout="", stderr=""
        ),
        policy_events=policy_events or [],
        preflight=preflight,
        task_net_runtime_ms=task_net_runtime_ms,
        openrouter_accounting=openrouter_accounting,
        harness_session_artifacts=harness_session_artifacts,
        harness=harness,
        effort_level="high",
        effort_level_source="harness_default",
        effort_level_applied=True,
    )


def _failing_probe_report() -> RuntimePolicyProbeReport:
    return RuntimePolicyProbeReport(
        policy_id="nist-linux-80053-low",
        policy_name="nist-linux-80053-low",
        runtime_target=DAYTONA_HARDENING_RUNTIME_TARGET,
        hardening_config={"name": "nist-linux-80053-low"},
        overlays=("blocked-surfaces",),
        agent_user="daytona",
        workspace=RUNTIME_POLICY_PROBE_WORKSPACE,
        results=(
            RuntimePolicyProbeResult(
                policy_id="nist-linux-80053-low",
                policy_name="nist-linux-80053-low",
                runtime_target=DAYTONA_HARDENING_RUNTIME_TARGET,
                probe_id="nist-linux-80053-low.command_name.sudo",
                surface="command_name_denial",
                expected_outcome="blocked",
                actual_outcome="allowed",
                status="fail",
                classification="policy_miss",
                required=True,
                target="sudo",
                command="sudo -n true",
                configured_by="denied_command_names",
                enforcement_source="path_shim",
                claim_level="runtime_helper",
                execution_context="daytona_sdk",
                runner="daytona_policy_hardening",
                message="expected blocked, observed allowed",
                evidence={"exit_code": 0},
            ),
        ),
    )


def _state(task_id: str) -> TaskState:
    return TaskState(
        model="mockllm/model",
        sample_id=task_id,
        epoch=0,
        input=task_id,
        messages=[],
        metadata={"terminal_bench_task_id": task_id},
    )


def test_task_builds_one_sample_per_task_id():
    t = hardened_terminalbench_daytona(task_ids="a,b,c")
    ids = [s.id for s in (t.dataset or [])]
    assert ids == ["a", "b", "c"]
    assert t.sandbox is None
    sample = list(t.dataset)[0]
    assert sample.metadata["hardened_execution"] is False
    assert sample.metadata["enforcement"] == "daytona_baseline"
    assert sample.metadata["harness"] == "terminus_2"


def test_all_tasks_expands_to_the_frozen_universe():
    t = hardened_terminalbench_daytona(all_tasks=True, policy="high-nist")
    ids = [s.id for s in (t.dataset or [])]
    assert len(ids) == 89
    assert set(ta.POLICY_INAPPLICABLE_TASKS) <= set(ids)

    by_id = {s.id: s for s in t.dataset}
    assert by_id["mailman"].metadata["policy_applicability"] == "not_applicable"


def test_all_tasks_exclude_not_applicable_drops_the_seven():
    t = hardened_terminalbench_daytona(
        all_tasks=True, policy="high-nist", exclude_not_applicable=True
    )
    ids = {s.id for s in t.dataset}
    assert len(ids) == 82
    assert not (set(ta.POLICY_INAPPLICABLE_TASKS) & ids)


def test_all_tasks_exclude_not_applicable_is_a_noop_under_control():
    t = hardened_terminalbench_daytona(
        all_tasks=True, policy="control", exclude_not_applicable=True
    )
    assert len(list(t.dataset)) == 89


def test_include_and_exclude_not_applicable_are_mutually_exclusive():
    with pytest.raises(ValueError, match="mutually exclusive"):
        hardened_terminalbench_daytona(
            task_ids="a",
            include_not_applicable=True,
            exclude_not_applicable=True,
        )


def test_exclude_not_applicable_refuses_an_empty_selection():
    with pytest.raises(ValueError, match="no tasks left"):
        hardened_terminalbench_daytona(
            task_ids="mailman", policy="high-nist", exclude_not_applicable=True
        )


def test_task_applies_native_low_nist_policy_on_demand():
    t = hardened_terminalbench_daytona(task_ids="a", policy="low-nist")
    sample = list(t.dataset)[0]

    assert sample.metadata["policy"] == "low-nist"
    assert sample.metadata["agent_user"] == "daytona"
    assert sample.metadata["policy_overlays"] == []
    assert sample.metadata["hardened_execution"] is True
    assert sample.metadata["enforcement"] == "daytona_policy_hardening"
    hc = sample.metadata["hardening_config"]
    assert hc["native_egress_reject"] is True
    assert hc["egress_domain_default_action"] == "deny"
    assert hc["lock_root_password"] is True
    assert hc["filesystem_scope"] == "workspace"
    assert hc["strip_env_vars"] == []
    assert hc["denied_command_names"] == []
    assert hc["denied_exec_paths"] == []


def test_task_rejects_unknown_harness():
    with pytest.raises(ValueError, match="unknown harness"):
        hardened_terminalbench_daytona(task_ids="a", harness="not-a-harness")


def test_solver_rejects_unknown_harness_before_runner_can_pass(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def passing_runner(*args, **kwargs):
        return _fake_result("x", 1.0)

    with pytest.raises(ValueError, match="unknown harness"):
        hardened_daytona_solver(harness="not-a-harness", runner=passing_runner)


def test_task_records_cli_block_message_override():
    t = hardened_terminalbench_daytona(
        task_ids="a",
        policy="low-nist",
        block_message="Operation not permitted",
    )
    sample = list(t.dataset)[0]

    assert sample.metadata["block_message"] == "Operation not permitted"
    assert (
        sample.metadata["hardening_config"]["block_message"]
        == "Operation not permitted"
    )


def test_task_records_runner_image_provenance(monkeypatch):
    monkeypatch.setattr(
        daytona_eval_module,
        "runtime_provenance",
        lambda: {
            "image_digest": "manager@sha256:abc",
            "image_source_sha": "source-sha",
            "branch_sha": "branch-sha",
            "base_main_sha": "base-sha",
            "branch_name": "feature/fix",
            "dirty": False,
            "build_time": "2026-06-28T09:00:00Z",
            "runner_fingerprint": "f" * 64,
        },
    )

    t = hardened_terminalbench_daytona(task_ids="a")
    sample = list(t.dataset)[0]

    assert sample.metadata["runner_provenance"]["image_digest"] == "manager@sha256:abc"
    assert sample.metadata["runner_provenance"]["image_source_sha"] == "source-sha"
    assert sample.metadata["runner_provenance"]["branch_sha"] == "branch-sha"
    assert sample.metadata["runner_provenance"]["base_main_sha"] == "base-sha"
    assert sample.metadata["runner_provenance"]["runner_fingerprint"] == "f" * 64


def test_solver_runs_runner_and_records_reward(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    captured = {}

    def fake_runner(
        task_id,
        *,
        ref,
        model,
        openrouter_api_key,
        agent_timeout_sec,
        policy="control",
        block_message=None,
        harness="claude_code",
        effort=None,
        policy_prompt="off",
        recovery_bundle="off",
    ):
        captured.update(
            task_id=task_id,
            model=model,
            key=openrouter_api_key,
            timeout=agent_timeout_sec,
            effort=effort,
        )
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(model="minimax/minimax-m3", runner=fake_runner, harness="claude_code")
    state = asyncio.run(solver(_state("log-summary-date-ranges"), None))

    assert captured["task_id"] == "log-summary-date-ranges"
    assert captured["model"] == "minimax/minimax-m3"
    assert captured["key"] == "sk-or-test"
    assert captured["timeout"] == 3600
    assert captured["effort"] == "high"
    assert state.metadata["reward"] == 1.0
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PASS"
    assert meta["harness"] == "claude_code"
    assert meta["effort_level"] == "high"
    assert meta["effort_level_source"] == "harness_default"
    assert meta["effort_level_applied"] is True
    assert meta["hardened_execution"] is False
    assert meta["enforcement"] == "daytona_baseline"
    roles = [m.role for m in state.messages]
    assert roles == ["user", "assistant", "tool"]
    assert state.messages[1].tool_calls[0].function == "Bash"
    assert state.output.model == "mockllm/model"
    assert state.output.usage.input_tokens == 100
    assert state.output.usage.total_cost == pytest.approx(0.000054)
    trace = state.metadata["terminalbench_daytona"]["full_trace"]
    assert trace["schema_version"] == "1"
    assert trace["harness"] == "claude_code"
    assert trace["policy_events"] == []
    assert trace["events"]


def test_solver_passes_and_records_explicit_effort(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    captured = {}

    def fake_runner(
        task_id,
        *,
        ref,
        model,
        openrouter_api_key,
        agent_timeout_sec,
        policy="control",
        block_message=None,
        harness="claude_code",
        effort=None,
        policy_prompt="off",
        recovery_bundle="off",
    ):
        captured["effort"] = effort
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(effort="low", runner=fake_runner)
    state = asyncio.run(solver(_state("log-summary-date-ranges"), None))

    assert captured["effort"] == "low"
    meta = state.metadata["terminalbench_daytona"]
    assert meta["effort_level"] == "low"
    assert meta["effort_level_source"] == "task_arg"
    assert meta["effort_level_applied"] is True
    assert "- **Effort level:** low (task_arg)" in state.metadata["transcript_markdown"]


def test_solver_passes_and_records_block_message(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    captured = {}

    def fake_runner(
        task_id,
        *,
        ref,
        model,
        openrouter_api_key,
        agent_timeout_sec,
        policy="control",
        block_message=None,
        harness="claude_code",
        effort=None,
        policy_prompt="off",
        recovery_bundle="off",
    ):
        captured["block_message"] = block_message
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(
        block_message="Operation not permitted", runner=fake_runner
    )
    state = asyncio.run(solver(_state("x"), None))

    assert captured["block_message"] == "Operation not permitted"
    assert (
        state.metadata["terminalbench_daytona"]["block_message"]
        == "Operation not permitted"
    )


def test_solver_records_usage_into_inspect_accounting(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    recorded = {}

    def fake_record(model, usage, role=None):
        recorded["model"] = model
        recorded["input"] = usage.input_tokens
        recorded["output"] = usage.output_tokens
        recorded["cost"] = usage.total_cost

    monkeypatch.setattr(
        "inspect_ai.model._model.record_and_check_model_usage", fake_record
    )
    solver = hardened_daytona_solver(runner=lambda *a, **k: _fake_result("x", 1.0), harness="claude_code")
    asyncio.run(solver(_state("x"), None))

    assert recorded["input"] == 100
    assert recorded["output"] == 20
    assert recorded["cost"] == pytest.approx(0.0000126)


def test_solver_selects_policy_per_sample_then_env(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_POLICY", "low-nist")
    seen = {}

    def fake_runner(
        task_id,
        *,
        ref,
        model,
        openrouter_api_key,
        agent_timeout_sec,
        policy,
        block_message=None,
        harness="claude_code",
        effort=None,
        policy_prompt="off",
        recovery_bundle="off",
    ):
        seen["policy"] = policy
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner)

    state = _state("x")
    state.metadata["policy"] = "control"
    asyncio.run(solver(state, None))
    assert seen["policy"] == "control"
    assert state.metadata["terminalbench_daytona"]["policy"] == "control"

    asyncio.run(solver(_state("y"), None))
    assert seen["policy"] == "low-nist"


def test_solver_reads_agent_timeout_from_env(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_AGENT_TIMEOUT_SEC", "600")
    captured = {}

    def fake_runner(
        task_id,
        *,
        ref,
        model,
        openrouter_api_key,
        agent_timeout_sec,
        policy="control",
        block_message=None,
        harness="claude_code",
        effort=None,
        policy_prompt="off",
        recovery_bundle="off",
    ):
        captured["timeout"] = agent_timeout_sec
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner)
    asyncio.run(solver(_state("x"), None))
    assert captured["timeout"] == 600


def test_effective_agent_timeout_uses_task_config_exactly():
    from boundarybench.terminalbench.daytona_eval import (
        _effective_agent_timeout_sec,
    )

    assert _effective_agent_timeout_sec(3600, 900) == 900
    assert _effective_agent_timeout_sec(600, 900) == 900
    assert _effective_agent_timeout_sec(3600, 12000) == 12000
    assert _effective_agent_timeout_sec(3600, None) == 3600


def test_solver_isolates_per_task_failure(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    attempts = 0

    def boom(*a, **k):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("provision failed")

    solver = hardened_daytona_solver(runner=boom, harness="claude_code")
    state = asyncio.run(solver(_state("bad-task"), None))

    assert attempts == 1
    assert state.metadata["reward"] == 0.0
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert "provision failed" in meta["error"]
    assert meta["policy_overlays"] == []
    assert meta["agent_user"] == "root"
    assert meta["enforcement"] == "daytona_baseline"
    assert meta["hardened_execution"] is False
    assert meta["harness"] == "claude_code"
    assert meta["benchmark_status"]["task_outcome"] == "ERROR"
    assert meta["benchmark_status"]["failure_class"] == "unknown"
    assert meta["benchmark_status"]["valid_for_analysis"] is False
    assert meta["agent_entity"]["name"] == "claude_code_openrouter"
    assert meta["agent_entity"]["benchmark_status"] == meta["benchmark_status"]


def test_solver_preserves_session_artifacts_from_failed_attempt(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def boom(*a, **k):
        exc = RuntimeError("agent process died")
        exc.harness_session_artifacts = {
            "harness": "codex",
            "file_count": 1,
            "exported_file_count": 1,
            "truncated": False,
            "files": [
                {
                    "path": "/home/daytona/.codex/sessions/rollout.jsonl",
                    "size_bytes": 8,
                    "content": '{"a": 1}',
                    "truncated": False,
                }
            ],
        }
        raise exc

    solver = hardened_daytona_solver(runner=boom)
    state = asyncio.run(solver(_state("dead-task"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["harness_session_artifacts"]["harness"] == "codex"
    assert meta["harness_session_artifacts"]["files"][0]["content"] == '{"a": 1}'


def test_solver_isolates_invalid_per_sample_policy(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    solver = hardened_daytona_solver(runner=lambda *a, **k: _fake_result("x", 1.0))
    state = _state("bad-task")
    state.metadata["policy"] = "does-not-exist"

    state = asyncio.run(solver(state, None))

    assert state.metadata["reward"] == 0.0
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["policy"] == "does-not-exist"
    assert meta["policy_overlays"] == []
    assert meta["agent_user"] is None
    assert "unknown hardening policy" in meta["error"]


def test_solver_retries_transient_infra_errors(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    attempts = 0

    def flaky(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("DaytonaError: RemoteDisconnected")
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=flaky)
    state = asyncio.run(solver(_state("infra-flake"), None))

    assert attempts == 2
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PASS"
    assert meta["attempt"] == 2
    assert meta["retry_errors"]
    assert meta["benchmark_status"]["task_outcome"] == "PASS"
    assert meta["benchmark_status"]["failure_class"] == "none"
    assert meta["benchmark_status"]["valid_for_analysis"] is True
    assert meta["agent_entity"]["benchmark_status"] == meta["benchmark_status"]


def test_solver_accumulates_native_accounting_from_charged_transient_attempts(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    attempts = 0

    def flaky(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return _fake_result(
                task_id,
                0.0,
                agent_stdout="",
                openrouter_accounting={
                    "records": 1,
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cache_read_tokens": 4,
                    "cache_write_tokens": 1,
                    "total_tokens": 12,
                    "cost": 0.01,
                    "cost_complete": False,
                },
            )
        return _fake_result(
            task_id,
            1.0,
            openrouter_accounting={
                "records": 1,
                "input_tokens": 20,
                "output_tokens": 3,
                "cache_read_tokens": 5,
                "cache_write_tokens": 0,
                "total_tokens": 23,
                "cost": 0.02,
                "cost_complete": True,
            },
        )

    state = asyncio.run(
        hardened_daytona_solver(runner=flaky)(_state("billed-retry"), None)
    )

    meta = state.metadata["terminalbench_daytona"]
    accounting = meta["openrouter_accounting"]
    assert attempts == 2
    assert accounting["records"] == 2
    assert accounting["input_tokens"] == 30
    assert accounting["output_tokens"] == 5
    assert accounting["cache_read_tokens"] == 9
    assert accounting["cache_write_tokens"] == 1
    assert accounting["total_tokens"] == 35
    assert accounting["cost"] == pytest.approx(0.03)
    assert accounting["cost_complete"] is False
    assert state.output.usage.input_tokens == 30
    assert state.output.usage.output_tokens == 5
    assert state.output.usage.total_cost is None
    assert meta["agent_model_cost_available"] is False


def test_solver_terminal_transient_failure_keeps_native_usage_and_transcript(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    accounting = {
        "records": 1,
        "input_tokens": 14,
        "output_tokens": 4,
        "cache_read_tokens": 6,
        "cache_write_tokens": 0,
        "total_tokens": 18,
        "cost": 0.005,
        "cost_complete": True,
    }

    state = asyncio.run(
        hardened_daytona_solver(
            runner=lambda task_id, **kwargs: _fake_result(
                task_id,
                0.0,
                agent_stdout="",
                openrouter_accounting=accounting,
            )
        )(_state("terminal-billed-transient"), None)
    )

    meta = state.metadata["terminalbench_daytona"]
    assert meta["transient_error"] is True
    assert meta["agent_model_usage_available"] is True
    assert meta["agent_model_usage_present"] is True
    assert meta["agent_model_usage_source"] == "openrouter_accounting_proxy"
    assert meta["agent_model_usage_recovered"] is True
    assert meta["agent_model_cost_available"] is True
    assert state.output.usage.input_tokens == 14
    assert state.output.usage.output_tokens == 4
    assert state.output.usage.total_cost == pytest.approx(0.005)
    assert (
        "- **Usage:** in=14 out=4 cache_read=6 cache_write=0 cost=$0.005"
        in state.metadata["transcript_markdown"]
    )


def test_solver_terminal_transient_preserves_stdout_usage_recovery_semantics(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    stdout_with_usage_but_no_assistant_turn = (
        '{"type":"result","subtype":"success","result":"done",'
        '"usage":{"input_tokens":7,"output_tokens":2}}'
    )

    state = asyncio.run(
        hardened_daytona_solver(
            harness="claude_code",
            runner=lambda task_id, **kwargs: _fake_result(
                task_id,
                0.0,
                agent_stdout=stdout_with_usage_but_no_assistant_turn,
                openrouter_accounting={
                    "records": 1,
                    "input_tokens": 7,
                    "output_tokens": 2,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "total_tokens": 9,
                    "cost": 0.002,
                    "cost_complete": True,
                },
            )
        )(_state("terminal-billed-with-stdout-usage"), None)
    )

    meta = state.metadata["terminalbench_daytona"]
    assert meta["transient_error"] is True
    assert meta["agent_model_usage_present"] is True
    assert meta["agent_model_usage_source"] == "openrouter_accounting_proxy"
    assert meta["agent_model_usage_recovered"] is False
    assert state.output.usage.input_tokens == 7
    assert state.output.usage.output_tokens == 2


def test_solver_retries_daytona_container_disappeared(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    attempts = 0

    def flaky(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError(
                "DaytonaNotFoundError: Failed to get session command: "
                "sandbox container not found: no such container"
            )
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=flaky)
    state = asyncio.run(solver(_state("daytona-container-gone"), None))

    assert attempts == 2
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PASS"
    assert meta["attempt"] == 2
    assert "sandbox container not found" in meta["retry_errors"][0]


def test_policy_prompt_knob_rejects_invalid_value():
    with pytest.raises(ValueError, match="policy_prompt"):
        hardened_daytona_solver(policy_prompt="sometimes")


def test_solver_threads_policy_prompt_to_runner(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    captured: dict = {}

    def fake_runner(task_id, **kwargs):
        captured.update(kwargs)
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner, policy_prompt="on")
    asyncio.run(solver(_state("thread-knob"), None))

    assert captured["policy_prompt"] == "on"


def _capture_agent_kwargs_for_run_one(monkeypatch, task_id, **run_kwargs):
    """Drive ``run_one_hardened_task`` with provisioning and the agent call
    stubbed, returning the kwargs the (aliased) agent-only twin was invoked with.

    Mirrors the stub set used by the workspace-image tests; the resolved-config
    merges and ``render_policy_prompt`` still run for real before the stub.
    """

    agent_kwargs: dict = {}

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeBundle:
        input = "Solve it."
        task_name = f"terminal-bench/{task_id}"
        verifier_environment_mode = "shared"
        verifier_environment_mode_source = "harbor_default"

    def fake_agent_run(sandbox, loaded_bundle, **kwargs):
        agent_kwargs.update(kwargs)
        return _fake_result(task_id, 1.0)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: FakeBundle(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda bundle: "example/task:latest",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (object(), None),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )

    result = run_one_hardened_task(
        task_id,
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        **run_kwargs,
    )
    assert result.reward == 1.0
    return agent_kwargs


def test_policy_prompt_off_injects_nothing_even_under_hardening(monkeypatch):
    agent_kwargs = _capture_agent_kwargs_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="moderate-nist",
        harness="claude_code",
        policy_prompt="off",
    )
    assert agent_kwargs["policy_prompt_fragment"] is None
    assert agent_kwargs["allowlist_file_content"] is None


def test_policy_prompt_on_threads_resolved_fragment_and_allowlist(monkeypatch):
    agent_kwargs = _capture_agent_kwargs_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="moderate-nist",
        harness="claude_code",
        policy_prompt="on",
    )
    fragment = agent_kwargs["policy_prompt_fragment"]
    assert fragment is not None
    assert fragment.startswith("<environment_policy>")
    assert "## Network: allowlist-only egress" in fragment
    assert "openrouter.ai" not in fragment
    assert "api.anthropic.com" not in fragment
    assert (
        agent_kwargs["allowlist_file_content"]
        == "files.pythonhosted.org\ngithub.com\npypi.org\n"
    )


def test_policy_prompt_on_control_injects_nothing(monkeypatch):
    agent_kwargs = _capture_agent_kwargs_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="control",
        harness="claude_code",
        policy_prompt="on",
    )
    assert agent_kwargs["policy_prompt_fragment"] is None
    assert agent_kwargs["allowlist_file_content"] is None


def _capture_provision_and_result_for_run_one(monkeypatch, task_id, **run_kwargs):
    """Drive ``run_one_hardened_task`` with provisioning and the agent call
    stubbed, returning ``(provision_kwargs, result)``.

    Mirrors ``_capture_agent_kwargs_for_run_one`` but captures the kwargs handed
    to ``provision_hardened_task_sandbox`` (where the recovery files flow) and the
    run result (where the recovery provenance is recorded); ``render_recovery_bundle``
    still runs for real before the stub.
    """

    provision_kwargs: dict = {}

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeBundle:
        input = "Solve it."
        task_name = f"terminal-bench/{task_id}"
        verifier_environment_mode = "shared"
        verifier_environment_mode_source = "harbor_default"

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return (object(), None)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: FakeBundle(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda bundle: "example/task:latest",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda sandbox, loaded_bundle, **kwargs: _fake_result(task_id, 1.0),
    )

    result = run_one_hardened_task(
        task_id,
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        **run_kwargs,
    )
    assert result.reward == 1.0
    return provision_kwargs, result


def test_recovery_bundle_on_renders_files_and_records_provenance(monkeypatch):
    provision_kwargs, result = _capture_provision_and_result_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="high-nist",
        harness="claude_code",
        recovery_bundle="on",
    )
    files = provision_kwargs["recovery_bundle_files"]
    assert files
    assert any(
        ".claude/skills/" in remote_path and remote_path.endswith("SKILL.md")
        for remote_path, _content, _chmod in files
    )
    assert result.recovery_bundle_provenance["mode"] == "on"


def test_recovery_bundle_off_renders_no_files(monkeypatch):
    provision_kwargs, result = _capture_provision_and_result_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="high-nist",
        harness="claude_code",
        recovery_bundle="off",
    )
    assert provision_kwargs["recovery_bundle_files"] == []
    assert result.recovery_bundle_provenance["mode"] == "off"


def test_recovery_bundle_on_control_renders_nothing(monkeypatch):
    provision_kwargs, result = _capture_provision_and_result_for_run_one(
        monkeypatch,
        "build-cython-ext",
        policy="control",
        harness="claude_code",
        recovery_bundle="on",
    )
    assert provision_kwargs["recovery_bundle_files"] == []
    assert result.recovery_bundle_provenance["mode"] == "off"
    assert result.recovery_bundle_provenance["knob"] == "on"


def test_solver_records_policy_prompt_into_benchmark_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def fake_runner(task_id, **kwargs):
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner, policy_prompt="on")
    state = asyncio.run(solver(_state("record-knob"), None))

    assert state.metadata["terminalbench_daytona"]["policy_prompt"] == "on"


def test_solver_defaults_policy_prompt_off_in_benchmark_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def fake_runner(task_id, **kwargs):
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner)
    state = asyncio.run(solver(_state("default-knob"), None))

    assert state.metadata["terminalbench_daytona"]["policy_prompt"] == "off"


def test_task_threads_policy_prompt_to_solver_and_samples(monkeypatch):
    captured: dict = {}
    real_solver = daytona_eval_module.hardened_daytona_solver

    def capturing_solver(**kwargs):
        captured.update(kwargs)
        return real_solver(**kwargs)

    monkeypatch.setattr(
        daytona_eval_module, "hardened_daytona_solver", capturing_solver
    )

    t = hardened_terminalbench_daytona(task_ids="fix-git", policy_prompt="on")
    sample = list(t.dataset)[0]

    assert sample.metadata["policy_prompt"] == "on"
    assert captured["policy_prompt"] == "on"


def test_task_rejects_invalid_policy_prompt():
    with pytest.raises(ValueError, match="policy_prompt"):
        hardened_terminalbench_daytona(task_ids="fix-git", policy_prompt="sometimes")


def test_task_coerces_yaml_boolean_policy_prompt():
    t = hardened_terminalbench_daytona(task_ids="fix-git", policy_prompt=True)
    assert list(t.dataset)[0].metadata["policy_prompt"] == "on"
    off = hardened_terminalbench_daytona(task_ids="fix-git", policy_prompt=False)
    assert list(off.dataset)[0].metadata["policy_prompt"] == "off"


def test_recovery_bundle_knob_rejects_invalid_value():
    with pytest.raises(ValueError, match="recovery_bundle"):
        hardened_daytona_solver(recovery_bundle="sometimes")


def test_solver_threads_recovery_bundle_to_runner(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    captured: dict = {}

    def fake_runner(task_id, **kwargs):
        captured.update(kwargs)
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner, recovery_bundle="on")
    asyncio.run(solver(_state("thread-recovery-knob"), None))

    assert captured["recovery_bundle"] == "on"


def test_solver_records_recovery_bundle_into_benchmark_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def fake_runner(task_id, **kwargs):
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner, recovery_bundle="on")
    state = asyncio.run(solver(_state("record-recovery-knob"), None))

    assert state.metadata["terminalbench_daytona"]["recovery_bundle"] == "on"


def test_solver_defaults_recovery_bundle_off_in_benchmark_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def fake_runner(task_id, **kwargs):
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=fake_runner)
    state = asyncio.run(solver(_state("default-recovery-knob"), None))

    assert state.metadata["terminalbench_daytona"]["recovery_bundle"] == "off"


def test_task_threads_recovery_bundle_to_solver_and_samples(monkeypatch):
    captured: dict = {}
    real_solver = daytona_eval_module.hardened_daytona_solver

    def capturing_solver(**kwargs):
        captured.update(kwargs)
        return real_solver(**kwargs)

    monkeypatch.setattr(
        daytona_eval_module, "hardened_daytona_solver", capturing_solver
    )

    t = hardened_terminalbench_daytona(task_ids="fix-git", recovery_bundle="on")
    sample = list(t.dataset)[0]

    assert sample.metadata["recovery_bundle"] == "on"
    assert captured["recovery_bundle"] == "on"


def test_task_rejects_invalid_recovery_bundle():
    with pytest.raises(ValueError, match="recovery_bundle"):
        hardened_terminalbench_daytona(task_ids="fix-git", recovery_bundle="sometimes")


def test_task_coerces_yaml_boolean_recovery_bundle():
    t = hardened_terminalbench_daytona(task_ids="fix-git", recovery_bundle=True)
    assert list(t.dataset)[0].metadata["recovery_bundle"] == "on"
    off = hardened_terminalbench_daytona(task_ids="fix-git", recovery_bundle=False)
    assert list(off.dataset)[0].metadata["recovery_bundle"] == "off"


def test_run_one_task_prepares_and_uses_workspace_image_workdir(monkeypatch, tmp_path):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    env_dir = tmp_path / "environment"
    env_dir.mkdir()
    (env_dir / "Dockerfile").write_text("WORKDIR /workspace\n")

    class FakeBundle:
        input = "Solve it."
        task_dir = tmp_path
        task_name = "terminal-bench/prove-plus-comm"
        verifier_environment_mode = "shared"
        verifier_environment_mode_source = "harbor_default"

    provision_kwargs: dict = {}
    agent_kwargs: dict = {}

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return object(), None

    def fake_agent_run(sandbox, loaded_bundle, **kwargs):
        agent_kwargs.update(kwargs)
        return _fake_result("prove-plus-comm", 1.0)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: FakeBundle(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda bundle: "example/task:latest",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )

    result = run_one_hardened_task(
        "prove-plus-comm",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="control",
    )

    assert result.reward == 1.0
    assert provision_kwargs["workdir"] == "/workspace"
    assert agent_kwargs["agent_workdir"] == "/workspace"
    assert agent_kwargs["workspace_root"] == "/workspace"


def test_run_one_task_delete_race_does_not_override_result(monkeypatch, capsys):
    class NotFound(Exception):
        pass

    class FakeDaytona:
        def create(
            self, *args, **kwargs
        ):  # pragma: no cover - patched provision owns create
            raise AssertionError("create should be patched through provision")

        def delete(self, sandbox):
            raise NotFound("Sandbox with ID or name gone not found")

    fake_sandbox = object()
    fake_bundle = type(
        "FakeBundle",
        (),
        {
            "input": "Solve it.",
            "verifier_environment_mode": "shared",
            "verifier_environment_mode_source": "harbor_default",
        },
    )()
    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: fake_bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda bundle: "example/task:latest",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (fake_sandbox, None),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: _fake_result("cleanup-race", 1.0),
    )

    result = run_one_hardened_task(
        "cleanup-race",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="control",
    )

    assert result.answer == "PASS"
    assert result.reward == 1.0
    metadata = result.to_metadata()
    assert metadata["phase_timings_ms"]["task_execute_and_verify_ms"] >= 0
    assert metadata["phase_timings_ms"]["sandbox_delete_ms"] >= 0
    assert metadata["phase_timings_ms"]["hardened_task_total_ms"] >= 0
    assert (
        metadata["task_net_runtime_ms"]
        == metadata["phase_timings_ms"]["task_execute_and_verify_ms"]
    )
    captured = capsys.readouterr()
    assert "phase_timing component=terminalbench_daytona" in captured.out
    assert "phase=harbor_task_load" in captured.out
    assert "phase=sandbox_provision_attempt" in captured.out
    assert "phase=task_execute_and_verify" in captured.out
    assert "phase=sandbox_delete" in captured.out
    assert "phase=hardened_task_total" in captured.out


@pytest.mark.parametrize(
    ("task_id", "dockerfile", "expected_workdir", "expected_workdir_source"),
    [
        (
            "fix-git",
            "WORKDIR /app\nWORKDIR /app/personal-site\n",
            "/app/personal-site",
            "task_image",
        ),
        (
            "sanitize-git-repo",
            "WORKDIR /app\nWORKDIR /app/dclm\n",
            "/app/dclm",
            "task_image",
        ),
        ("pypi-server", "WORKDIR /app\n", "/app", "default"),
    ],
)
@pytest.mark.parametrize(
    ("policy", "hardened"),
    [("control", False), ("low-nist", True)],
)
def test_run_one_task_verifies_in_same_live_sandbox_after_agent(
    monkeypatch,
    tmp_path,
    task_id,
    dockerfile,
    expected_workdir,
    expected_workdir_source,
    policy,
    hardened,
):
    events: list[str] = []
    hardening_lift_calls: list[object] = []
    verifier_kwargs: dict = {}
    probe_listeners = "tcp LISTEN 0.0.0.0:8000 users:(uvicorn)"
    expected_preserve = (
        resolve_agent_session_lifecycle(
            task_id=task_id, harbor_ref="terminal-bench==2.1"
        ).lifecycle
        == "preserve_until_verified"
    )

    async def record_hardening_lift(state):
        hardening_lift_calls.append(state)
        return {"status": "unexpected"}

    class FakeDaytona:
        def delete(self, sandbox):
            events.append(f"delete:{sandbox.name}")

    class _VersionResult:
        exit_code = 0
        result = "1.0.61 (Claude Code)\n"

    class _VersionProcess:
        def __init__(self):
            self.commands: list[str] = []

        def exec(self, command, *, timeout, env=None):
            self.commands.append(command)
            if "--version" in command:
                return _VersionResult()
            if command == AGENT_LISTENER_PROBE_COMMAND:
                return type(
                    "Result", (), {"exit_code": 0, "result": probe_listeners}
                )()
            if "__BOUNDARYBENCH_VERIFIER_IDENTITY__" in command:
                events.append("verify:agent")
                return type(
                    "Result",
                    (),
                    {
                        "exit_code": 0,
                        "result": (
                            "__BOUNDARYBENCH_VERIFIER_IDENTITY__ "
                            "effective_uid=0 effective_user=root\n"
                        ),
                    },
                )()
            if command.startswith("cat "):
                return type("Result", (), {"exit_code": 0, "result": "1.0\n"})()
            return type("Result", (), {"exit_code": 0, "result": ""})()

    class FakeSandbox:
        def __init__(self, name: str):
            self.name = name
            self.id = name
            self.process = _VersionProcess()
            self.fs = type("Fs", (), {"upload_file": lambda *args: None})()

    agent_sandbox = FakeSandbox("agent")
    fake_hardening = object()
    env_dir = tmp_path / "environment"
    env_dir.mkdir()
    (env_dir / "Dockerfile").write_text(dockerfile)
    bundle = TerminalBenchTaskBundle(
        sample_id=f"terminal-bench/{task_id}",
        input="Solve it.",
        task_name=f"terminal-bench/{task_id}",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="verifier.environment_mode",
    )

    def fake_agent_run(sandbox, loaded_bundle, **kwargs):
        events.append(f"agent:{sandbox.name}")
        assert loaded_bundle is bundle
        assert kwargs["agent_workdir"] == expected_workdir
        assert kwargs["workspace_root"] == "/app"
        assert kwargs["isolate_agent_pid_namespace"] is False
        assert kwargs["preserve_agent_session"] is expected_preserve
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_workdir=kwargs["agent_workdir"],
            workspace_root=kwargs["workspace_root"],
            agent_pid_namespace_isolation_observed=False,
            agent_session_id="ia-model-agent-test",
            agent_session_preserved=expected_preserve,
            post_agent_listeners="tcp LISTEN :8080",
            harness_session_artifacts={
                "harness": "claude_code",
                "file_count": 1,
                "exported_file_count": 1,
                "truncated": False,
                "files": [
                    {
                        "path": "/home/daytona/.codex/sessions/rollout.jsonl",
                        "size_bytes": 8,
                        "content": '{"a": 1}',
                        "truncated": False,
                    }
                ],
            },
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {"preflight_passed": True, "probe_count": 0, "failed_count": 0}

    class FakeProbeReport:
        passed = True

        def to_metadata(self):
            return {"passed": True, "results": []}

    real_verifier = daytona_eval_module.run_daytona_harbor_verifier

    def capture_verifier_kwargs(sandbox, loaded_bundle, **kwargs):
        verifier_kwargs.update(kwargs)
        return dataclasses.replace(
            real_verifier(sandbox, loaded_bundle, **kwargs),
            session_id="ia-verifier-test",
        )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    provision_kwargs: dict = {}

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return agent_sandbox, fake_hardening if hardened else None

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        lambda *args, **kwargs: FakePreflightResult(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        lambda *args, **kwargs: FakeProbeReport(),
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "run_daytona_harbor_verifier",
        capture_verifier_kwargs,
    )
    assert not hasattr(daytona_eval_module, "export_submission_snapshot")
    assert hasattr(daytona_eval_module, "provision_clean_verifier_sandbox")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona.upload_tests_dir_to_daytona",
        lambda sandbox, loaded_bundle, **kwargs: events.append(
            f"upload_tests:{sandbox.name}"
        ),
    )
    monkeypatch.setattr(
        task_runtime_sandbox_module,
        "_lift_hardening_for_verifier",
        record_hardening_lift,
    )

    result = run_one_hardened_task(
        task_id,
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy=policy,
    )

    assert result.answer == "PASS"
    assert result.postflight_verification == {
        "enabled": True,
        "mode": "harbor_shared_same_daytona",
        "clean_verifier_vm": False,
        "clean_verifier_process": True,
        "handoff_exported": False,
        "agent_vm_deleted": False,
        "verifier_vm_provisioned": False,
        "verifier_started": True,
        "verifier_process_started": True,
        "verifier_completed": True,
        "cleanup_outcome": {
            "status": "complete",
            "shared_sandbox_delete_attempted": True,
            "shared_sandbox_deleted": True,
            "verifier_vm_delete_attempted": False,
            "verifier_vm_deleted": None,
            "handoff_snapshot_cleanup_attempted": False,
            "handoff_snapshot_cleaned": None,
        },
        "verifier_hardening": False,
        "agent_hardening_lifted": False,
        "global_hardening_lifted": False,
        "agent_completed_before_verifier": True,
        "agent_process_disposition": "preserve",
        "agent_process_disposition_source": "safe_default",
        "agent_process_disposition_reason": "unlisted_tasks_preserve_harbor_semantics",
        "agent_pid_namespace_isolation_requested": False,
        "agent_pid_namespace_isolation_observed": False,
        "agent_pid_namespace_isolated": False,
        "tests_uploaded_after_agent": True,
        "live_state_preserved": True,
        "agent_session_lifecycle": "delete_on_agent_exit",
        "agent_session_lifecycle_source": "safe_default",
        "agent_session_lifecycle_reason": (
            "unlisted_tasks_delete_agent_session_after_exit"
        ),
        "agent_session_lifecycle_evidence": None,
        "agent_session_preserved": False,
        "agent_session_id": "ia-model-agent-test",
        "verifier_session_id": "ia-verifier-test",
        "verifier_fresh_session": True,
        "post_agent_listeners": "tcp LISTEN :8080",
        "pre_verifier_listeners": probe_listeners,
        "agent_sandbox_id": "agent",
        "verifier_sandbox_id": "agent",
        "verifier_image": "registry/example:1",
        "verifier_workspace": expected_workdir,
        "workspace_root": "/app",
        "verifier_user": None,
        "verifier_identity": {"effective_uid": 0, "effective_user": "root"},
        "handoff_transport": "none",
        "handoff_paths": [],
        "harbor_ref": "terminal-bench==2.1",
        "harbor_verifier_environment_mode": "shared",
        "harbor_verifier_environment_mode_source": "verifier.environment_mode",
        "effective_verifier_environment_mode": "shared",
        "effective_verifier_environment_mode_source": "verifier.environment_mode",
        "verifier_lifecycle_override_reason": None,
        "agent_session_cleanup": "not_preserved",
    }
    assert result.postflight_verification["agent_sandbox_id"] == "agent"
    assert result.postflight_verification["verifier_sandbox_id"] == "agent"
    assert result.submission_snapshot is None
    assert result.agent_version == "1.0.61 (Claude Code)"
    assert result.to_metadata()["agent_version"] == "1.0.61 (Claude Code)"
    assert provision_kwargs["workdir"] == "/app"
    assert result.agent_workdir == expected_workdir
    assert result.workspace_root == "/app"
    assert result.to_metadata()["agent_workdir"] == expected_workdir
    assert result.to_metadata()["workspace_root"] == "/app"
    assert result.to_metadata()["agent_workdir_source"] == expected_workdir_source
    assert "include_daytona_user_site" not in verifier_kwargs
    session_meta = result.to_metadata()["harness_session_artifacts"]
    assert session_meta["exported_file_count"] == 1
    assert session_meta["files"][0]["content"] == '{"a": 1}'
    assert events == [
        "agent:agent",
        "upload_tests:agent",
        "verify:agent",
        "delete:agent",
    ]
    verifier_event_index = events.index("verify:agent")
    assert verifier_event_index > events.index("agent:agent")
    assert hardening_lift_calls == []
    assert not hasattr(daytona_eval_module, "_lift_hardening_for_verifier")
    verifier_command = next(
        command
        for command in agent_sandbox.process.commands
        if "__BOUNDARYBENCH_VERIFIER_IDENTITY__" in command
    )
    assert f"cd {expected_workdir} && " in verifier_command


def test_run_one_task_fails_closed_for_non_root_verifier_before_provision(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        pass

    provisioned = False
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_user="daytona",
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )

    def fake_provision(*args, **kwargs):
        nonlocal provisioned
        provisioned = True
        return object(), None

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )

    with pytest.raises(RuntimeError, match="root verifier.*daytona"):
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert provisioned is False


def test_run_one_task_fails_closed_for_missing_verifier_mode_before_provision(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        pass

    provisioned = False
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )

    def fake_provision(*args, **kwargs):
        nonlocal provisioned
        provisioned = True
        raise RuntimeError("provision reached")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )

    with pytest.raises(RuntimeError, match="verifier environment mode.*missing"):
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert provisioned is False


@pytest.mark.parametrize("pid_isolation_observed", [False, True])
def test_pinned_pytorch_reaps_agent_in_shared_sandbox_without_handoff(
    monkeypatch, tmp_path, pid_isolation_observed
):
    events: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            events.append(f"delete:{sandbox.id}")

    class _ReapProcess:
        def exec(self, command, *, timeout, env=None):
            return type(
                "Result", (), {"exit_code": 0, "result": "tcp LISTEN 0.0.0.0:9999"}
            )()

    class FakeSandbox:
        def __init__(self, sandbox_id):
            self.id = sandbox_id
            self.process = _ReapProcess()

    agent_sandbox = FakeSandbox("agent-sandbox")
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/pytorch-model-recovery",
        input="Solve it.",
        task_name="terminal-bench/pytorch-model-recovery",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    monkeypatch.setattr(
        "daytona_sdk.Daytona",
        FakeDaytona,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: ["task-resources"],
    )

    def fake_provision(*args, **kwargs):
        events.append("provision:agent-sandbox")
        return agent_sandbox, None

    def fake_agent(sandbox, *args, **kwargs):
        events.append(f"agent:{sandbox.id}")
        assert kwargs["isolate_agent_pid_namespace"] is True
        assert kwargs["preserve_agent_session"] is False
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_workdir="/app",
            workspace_root="/app",
            agent_pid_namespace_isolation_observed=pid_isolation_observed,
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    def fake_verify(sandbox, loaded_bundle, **kwargs):
        events.append(f"verify:{sandbox.id}:{kwargs['remote_workdir']}")
        assert sandbox is agent_sandbox
        assert loaded_bundle is bundle
        assert "include_daytona_user_site" not in kwargs
        kwargs["observation_callback"]("tests_uploaded_after_agent")
        kwargs["observation_callback"]("verifier_process_started")
        return DaytonaVerifierResult(
            value=1.0,
            answer="PASS",
            exit_code=0,
            stdout="ok",
            stderr="",
            verifier_identity={"effective_uid": 0, "effective_user": "root"},
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent,
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_clean_verifier_sandbox",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared verification provisioned a clean sandbox")
        ),
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "export_verifier_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared verification exported a handoff")
        ),
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "import_verifier_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared verification imported a handoff")
        ),
    )
    monkeypatch.setattr(daytona_eval_module, "run_daytona_harbor_verifier", fake_verify)

    result = run_one_hardened_task(
        "pytorch-model-recovery",
        ref="sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="control",
    )

    assert result.reward == 1.0
    assert result.postflight_verification == {
        "enabled": True,
        "mode": "harbor_shared_same_daytona",
        "clean_verifier_vm": False,
        "clean_verifier_process": True,
        "handoff_exported": False,
        "agent_vm_deleted": False,
        "verifier_vm_provisioned": False,
        "verifier_started": True,
        "verifier_process_started": True,
        "verifier_completed": True,
        "cleanup_outcome": {
            "status": "complete",
            "shared_sandbox_delete_attempted": True,
            "shared_sandbox_deleted": True,
            "verifier_vm_delete_attempted": False,
            "verifier_vm_deleted": None,
            "handoff_snapshot_cleanup_attempted": False,
            "handoff_snapshot_cleaned": None,
        },
        "verifier_hardening": False,
        "agent_hardening_lifted": False,
        "global_hardening_lifted": False,
        "agent_completed_before_verifier": True,
        "agent_process_disposition": "reap",
        "agent_process_disposition_source": "boundarybench_ref_task_policy",
        "agent_process_disposition_reason": "reap_conflicting_agent_process",
        "agent_pid_namespace_isolation_requested": True,
        "agent_pid_namespace_isolation_observed": pid_isolation_observed,
        "agent_pid_namespace_isolated": pid_isolation_observed,
        "tests_uploaded_after_agent": True,
        "live_state_preserved": True,
        "agent_session_lifecycle": "delete_on_agent_exit",
        "agent_session_lifecycle_source": "safe_default",
        "agent_session_lifecycle_reason": (
            "unlisted_tasks_delete_agent_session_after_exit"
        ),
        "agent_session_lifecycle_evidence": None,
        "agent_session_preserved": False,
        "agent_session_id": None,
        "verifier_session_id": None,
        "verifier_fresh_session": False,
        "post_agent_listeners": None,
        "pre_verifier_listeners": "tcp LISTEN 0.0.0.0:9999",
        "agent_sandbox_id": "agent-sandbox",
        "verifier_sandbox_id": "agent-sandbox",
        "verifier_image": "registry/example:1",
        "verifier_workspace": "/app",
        "workspace_root": "/app",
        "verifier_user": None,
        "verifier_identity": {"effective_uid": 0, "effective_user": "root"},
        "handoff_transport": "none",
        "handoff_paths": [],
        "harbor_ref": "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a",
        "harbor_verifier_environment_mode": "shared",
        "harbor_verifier_environment_mode_source": "harbor_default",
        "effective_verifier_environment_mode": "shared",
        "effective_verifier_environment_mode_source": "harbor_default",
        "verifier_lifecycle_override_reason": None,
        "agent_session_cleanup": "not_preserved",
    }
    assert events == [
        "provision:agent-sandbox",
        "agent:agent-sandbox",
        "verify:agent-sandbox:/app",
        "delete:agent-sandbox",
    ]


@pytest.mark.parametrize("delete_succeeds", [False, True])
@pytest.mark.parametrize("verifier_succeeds", [False, True])
def test_pinned_pypi_preserves_live_service_in_shared_sandbox_without_pid_isolation(
    monkeypatch, tmp_path, delete_succeeds, verifier_succeeds
):
    events: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            events.append(f"delete:{sandbox.id}")
            if not delete_succeeds:
                raise RuntimeError("delete failed")

    class _PypiProcess:
        def __init__(self):
            self.deleted_sessions: list[str] = []

        def exec(self, command, *, timeout, env=None):
            return type(
                "Result", (), {"exit_code": 0, "result": "tcp LISTEN 0.0.0.0:8080"}
            )()

        def delete_session(self, session_id):
            self.deleted_sessions.append(session_id)

    class FakeSandbox:
        def __init__(self, sandbox_id):
            self.id = sandbox_id
            self.service_running = False
            self.process = _PypiProcess()

    agent_sandbox = FakeSandbox("pypi-sandbox")
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/pypi-server",
        input="Serve the package index.",
        task_name="terminal-bench/pypi-server",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/pypi:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: ["task-resources"],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (agent_sandbox, None),
    )

    def fake_agent(sandbox, *args, **kwargs):
        events.append(f"agent:{sandbox.id}")
        assert sandbox is agent_sandbox
        assert kwargs["isolate_agent_pid_namespace"] is False
        assert kwargs["preserve_agent_session"] is True
        sandbox.service_running = True
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_workdir="/app",
            workspace_root="/app",
            agent_session_id="ia-model-agent-test",
            agent_session_preserved=True,
            post_agent_listeners="tcp LISTEN :8080",
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    def fake_verify(sandbox, loaded_bundle, **kwargs):
        events.append(f"verify:{sandbox.id}")
        assert sandbox is agent_sandbox
        assert loaded_bundle is bundle
        assert sandbox.service_running is True
        kwargs["observation_callback"]("tests_uploaded_after_agent")
        kwargs["observation_callback"]("verifier_process_started")
        if not verifier_succeeds:
            raise RuntimeError("verifier launch failed")
        return DaytonaVerifierResult(
            value=1.0,
            answer="PASS",
            exit_code=0,
            stdout="live service reachable",
            stderr="",
            verifier_identity={"effective_uid": 0, "effective_user": "root"},
            session_id="ia-verifier-test",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent,
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_clean_verifier_sandbox",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared PyPI verification provisioned a clean sandbox")
        ),
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "export_verifier_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("shared PyPI verification exported a handoff")
        ),
    )
    monkeypatch.setattr(daytona_eval_module, "run_daytona_harbor_verifier", fake_verify)

    run_kwargs = {
        "task_id": "pypi-server",
        "ref": "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a",
        "model": "minimax/minimax-m3",
        "openrouter_api_key": "sk-or-test",
        "policy": "control",
    }
    if verifier_succeeds:
        result = run_one_hardened_task(**run_kwargs)
        postflight = result.postflight_verification
    else:
        with pytest.raises(daytona_eval_module._PostAgentVerifierError) as exc_info:
            run_one_hardened_task(**run_kwargs)
        postflight = exc_info.value.postflight_verification
    assert postflight["agent_sandbox_id"] == "pypi-sandbox"
    assert postflight["verifier_sandbox_id"] == "pypi-sandbox"
    assert postflight["harbor_ref"] == (
        "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
    )
    assert postflight["live_state_preserved"] is True
    assert postflight["agent_process_disposition"] == "preserve"
    assert (
        postflight["agent_process_disposition_source"]
        == "boundarybench_ref_task_policy"
    )
    assert (
        postflight["agent_process_disposition_reason"]
        == "verifier_requires_live_service"
    )
    assert postflight["agent_pid_namespace_isolation_requested"] is False
    assert postflight["agent_pid_namespace_isolation_observed"] is False
    assert postflight["agent_pid_namespace_isolated"] is False
    assert postflight["cleanup_outcome"]["shared_sandbox_delete_attempted"] is True
    assert (
        postflight["cleanup_outcome"]["shared_sandbox_deleted"] is delete_succeeds
    )
    assert postflight["cleanup_outcome"]["status"] == (
        "complete" if delete_succeeds else "failed"
    )
    assert postflight["agent_session_lifecycle"] == "preserve_until_verified"
    assert (
        postflight["agent_session_lifecycle_source"]
        == "boundarybench_ref_task_policy"
    )
    assert (
        postflight["agent_session_lifecycle_reason"] == "verifier_requires_live_service"
    )
    assert postflight["agent_session_lifecycle_evidence"]
    assert postflight["agent_session_preserved"] is True
    assert postflight["agent_session_id"] == "ia-model-agent-test"
    assert postflight["pre_verifier_listeners"] == "tcp LISTEN 0.0.0.0:8080"
    if verifier_succeeds:
        assert postflight["verifier_session_id"] == "ia-verifier-test"
        assert postflight["verifier_fresh_session"] is True
    else:
        assert postflight["verifier_session_id"] is None
        assert postflight["verifier_fresh_session"] is False
    assert agent_sandbox.process.deleted_sessions == ["ia-model-agent-test"]
    assert postflight["agent_session_cleanup"] == "deleted"
    assert events == [
        "agent:pypi-sandbox",
        "verify:pypi-sandbox",
        "delete:pypi-sandbox",
    ]


def test_declared_separate_post_agent_failure_does_not_rerun_agent(
    monkeypatch, tmp_path
):
    agent_runs: list[str] = []
    deleted: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            deleted.append(sandbox.id)

    class FakeSandbox:
        id = "agent"

    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/clean-verifier",
        input="Solve it.",
        task_name="terminal-bench/clean-verifier",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="separate",
        verifier_environment_mode_source="verifier.environment_mode",
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        daytona_eval_module,
        "load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(daytona_eval_module, "task_docker_image", lambda bundle: "img")
    monkeypatch.setattr(
        daytona_eval_module, "daytona_task_resource_attempts", lambda bundle: [1, 2]
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_hardened_task_sandbox",
        lambda *args, **kwargs: (FakeSandbox(), None),
    )

    def fake_agent(*args, **kwargs):
        agent_runs.append("agent")
        assert kwargs["isolate_agent_pid_namespace"] is False
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_pid_namespace_isolation_observed=False,
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    snapshot = type("Snapshot", (), {"to_metadata": lambda self: {}})()
    monkeypatch.setattr(
        daytona_eval_module, "run_terminalbench_task_in_daytona", fake_agent
    )
    monkeypatch.setattr(
        daytona_eval_module, "export_verifier_artifacts", lambda *a, **k: snapshot
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_clean_verifier_sandbox",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no space left on device")),
    )
    cleaned: list[object] = []
    monkeypatch.setattr(
        daytona_eval_module, "cleanup_verifier_artifacts", cleaned.append
    )

    with pytest.raises(RuntimeError, match="no space left on device") as exc_info:
        run_one_hardened_task(
            "clean-verifier",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert agent_runs == ["agent"]
    assert deleted == ["agent"]
    assert cleaned == [snapshot]
    assert exc_info.value.postflight_verification["agent_sandbox_id"] == "agent"
    assert exc_info.value.postflight_verification["verifier_sandbox_id"] is None
    assert exc_info.value.postflight_verification["handoff_exported"] is True
    assert exc_info.value.postflight_verification["agent_vm_deleted"] is True
    assert exc_info.value.postflight_verification["verifier_vm_provisioned"] is False
    assert exc_info.value.postflight_verification["clean_verifier_vm"] is False
    assert exc_info.value.postflight_verification["verifier_started"] is False
    assert exc_info.value.postflight_verification["verifier_process_started"] is False
    assert exc_info.value.postflight_verification["clean_verifier_process"] is False
    assert (
        exc_info.value.postflight_verification["agent_pid_namespace_isolated"] is False
    )
    assert exc_info.value.postflight_verification["tests_uploaded_after_agent"] is False
    assert exc_info.value.postflight_verification["verifier_completed"] is False
    assert exc_info.value.postflight_verification["cleanup_outcome"] == {
        "status": "complete",
        "verifier_vm_delete_attempted": False,
        "verifier_vm_deleted": None,
        "handoff_snapshot_cleanup_attempted": True,
        "handoff_snapshot_cleaned": True,
    }


@pytest.mark.parametrize(
    ("bundle_kwargs", "task_id", "ref", "message"),
    [
        (
            {
                "verifier_environment_mode": "separate",
                "verifier_environment_mode_source": "verifier.environment",
            },
            "custom-verifier",
            "terminal-bench==2.1",
            "distinct Harbor verifier environment",
        ),
        (
            {
                "verifier_environment_mode": "separate",
                "verifier_environment_mode_source": "verifier.environment_mode",
                "metadata": {
                    "harbor_config": {
                        "verifier": {
                            "environment_mode": "separate",
                            "environment": {"docker_image": "verifier:latest"},
                        }
                    }
                },
            },
            "custom-verifier-explicit-mode",
            "terminal-bench==2.1",
            "distinct Harbor verifier environment",
        ),
        (
            {
                "verifier_environment_mode": "separate",
                "verifier_environment_mode_source": "verifier.environment_mode",
                "metadata": {
                    "harbor_config": {
                        "artifacts": [{"source": "/app/output"}],
                    }
                },
            },
            "custom-artifact-verifier",
            "terminal-bench==2.1",
            "Harbor artifact handoff",
        ),
    ],
)
def test_unsupported_separate_lifecycle_features_fail_before_provision(
    monkeypatch, tmp_path, bundle_kwargs, task_id, ref, message
):
    class FakeDaytona:
        pass

    bundle = TerminalBenchTaskBundle(
        sample_id=f"terminal-bench/{task_id}",
        input="Solve it.",
        task_name=f"terminal-bench/{task_id}",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        **bundle_kwargs,
    )
    provisioned = False

    def fake_provision(*args, **kwargs):
        nonlocal provisioned
        provisioned = True
        raise AssertionError("unsupported verifier lifecycle reached provisioning")

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        daytona_eval_module,
        "load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        daytona_eval_module, "provision_hardened_task_sandbox", fake_provision
    )

    with pytest.raises(RuntimeError, match=message):
        run_one_hardened_task(
            task_id,
            ref=ref,
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert provisioned is False


def test_declared_same_image_separate_lifecycle_is_supported_without_artifacts(
    tmp_path,
):
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/clean-verifier",
        input="Solve it.",
        task_name="terminal-bench/clean-verifier",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="separate",
        verifier_environment_mode_source="verifier.environment_mode",
    )

    lifecycle = daytona_eval_module._resolve_verifier_lifecycle(
        bundle,
        task_id="clean-verifier",
        harbor_ref="terminal-bench==2.1",
    )

    assert lifecycle.effective_mode == "separate"
    assert lifecycle.handoff_paths == ()


@pytest.mark.parametrize("cleanup_failure", ["verifier_delete", "snapshot_cleanup"])
def test_failed_separate_cleanup_preserves_root_identity_and_lifecycle_evidence(
    monkeypatch, tmp_path, cleanup_failure
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "2")
    agent_runs: list[str] = []
    deleted: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            deleted.append(sandbox.id)
            if sandbox is verifier_sandbox and cleanup_failure == "verifier_delete":
                raise RuntimeError("verifier sandbox cleanup failed")

    class FakeSandbox:
        def __init__(self, sandbox_id):
            self.id = sandbox_id

    agent_sandbox = FakeSandbox("agent-failure-id")
    verifier_sandbox = FakeSandbox("verifier-failure-id")
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/clean-verifier",
        input="Solve it.",
        task_name="terminal-bench/clean-verifier",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="separate",
        verifier_environment_mode_source="verifier.environment_mode",
    )
    snapshot = type(
        "Snapshot",
        (),
        {
            "to_metadata": lambda self: {
                "transport": "explicit_regular_files",
                "workspace_root": "/app",
                "artifacts": [],
            }
        },
    )()

    def fake_agent(*args, **kwargs):
        agent_runs.append("agent")
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_pid_namespace_isolation_observed=False,
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        daytona_eval_module,
        "load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(daytona_eval_module, "task_docker_image", lambda bundle: "img")
    monkeypatch.setattr(
        daytona_eval_module, "daytona_task_resource_attempts", lambda bundle: [None]
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_hardened_task_sandbox",
        lambda *args, **kwargs: (agent_sandbox, None),
    )
    monkeypatch.setattr(
        daytona_eval_module, "run_terminalbench_task_in_daytona", fake_agent
    )
    monkeypatch.setattr(
        daytona_eval_module, "export_verifier_artifacts", lambda *a, **k: snapshot
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_clean_verifier_sandbox",
        lambda *a, **k: verifier_sandbox,
    )
    monkeypatch.setattr(
        daytona_eval_module, "import_verifier_artifacts", lambda *a, **k: None
    )

    def successful_verifier(*args, observation_callback, **kwargs):
        observation_callback("tests_uploaded_after_agent")
        observation_callback("verifier_process_started")
        return DaytonaVerifierResult(
            value=1.0,
            answer="PASS",
            exit_code=0,
            stdout="ok",
            stderr="",
            verifier_identity={"effective_uid": 0, "effective_user": "root"},
        )

    monkeypatch.setattr(
        daytona_eval_module,
        "run_daytona_harbor_verifier",
        successful_verifier,
    )
    cleaned: list[object] = []

    def fail_snapshot_cleanup(cleaned_snapshot):
        cleaned.append(cleaned_snapshot)
        if cleanup_failure == "snapshot_cleanup":
            raise RuntimeError("snapshot cleanup failed")

    monkeypatch.setattr(
        daytona_eval_module, "cleanup_verifier_artifacts", fail_snapshot_cleanup
    )

    state = asyncio.run(
        hardened_daytona_solver(runner=run_one_hardened_task)(
            _state("clean-verifier"), None
        )
    )
    metadata = state.metadata["terminalbench_daytona"]
    postflight = metadata["postflight_verification"]

    assert metadata["answer"] == "ERROR"
    assert metadata["reward"] == 0.0
    assert metadata["post_agent_verifier_error"] is True
    assert metadata["verifier"] == {
        "value": 1.0,
        "answer": "PASS",
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "reward_payload": None,
        "verifier_identity": {"effective_uid": 0, "effective_user": "root"},
        "session_id": None,
        "timed_out": False,
    }
    assert postflight["agent_sandbox_id"] == "agent-failure-id"
    assert postflight["verifier_sandbox_id"] == "verifier-failure-id"
    assert postflight["harbor_verifier_environment_mode"] == "separate"
    assert postflight["harbor_verifier_environment_mode_source"] == (
        "verifier.environment_mode"
    )
    assert postflight["effective_verifier_environment_mode"] == "separate"
    assert postflight["effective_verifier_environment_mode_source"] == (
        "verifier.environment_mode"
    )
    assert postflight["verifier_lifecycle_override_reason"] is None
    assert postflight["handoff_paths"] == []
    assert postflight["handoff_transport"] == "explicit_regular_files"
    assert postflight["handoff_exported"] is True
    assert postflight["agent_vm_deleted"] is True
    assert postflight["verifier_vm_provisioned"] is True
    assert postflight["clean_verifier_vm"] is True
    assert postflight["verifier_started"] is True
    assert postflight["verifier_process_started"] is True
    assert postflight["clean_verifier_process"] is True
    assert postflight["verifier_completed"] is True
    assert postflight["cleanup_outcome"] == {
        "status": "failed",
        "verifier_vm_delete_attempted": True,
        "verifier_vm_deleted": cleanup_failure != "verifier_delete",
        "handoff_snapshot_cleanup_attempted": True,
        "handoff_snapshot_cleaned": cleanup_failure != "snapshot_cleanup",
    }
    assert postflight["verifier_identity"] == {
        "effective_uid": 0,
        "effective_user": "root",
    }
    assert metadata["submission_snapshot"]["workspace_root"] == "/app"
    assert agent_runs == ["agent"]
    assert deleted == ["agent-failure-id", "verifier-failure-id"]
    assert cleaned == [snapshot]


@pytest.mark.parametrize(
    ("failure_phase", "observations", "tests_uploaded", "process_started"),
    [
        ("staging", [], False, False),
        ("upload", [], False, False),
        ("reset", ["tests_uploaded_after_agent"], True, False),
        ("pre_command", ["tests_uploaded_after_agent"], True, False),
        (
            "command",
            ["tests_uploaded_after_agent", "verifier_process_started"],
            True,
            True,
        ),
    ],
)
def test_failed_verifier_reports_only_observed_upload_and_process_phases(
    monkeypatch,
    tmp_path,
    failure_phase,
    observations,
    tests_uploaded,
    process_started,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "2")
    agent_runs: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeSandbox:
        id = "shared-phase-sandbox"

    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/phase-observation",
        input="Solve it.",
        task_name="terminal-bench/phase-observation",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    def fake_agent(*args, **kwargs):
        agent_runs.append("agent")
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    def fake_verifier(*args, observation_callback, **kwargs):
        for observation in observations:
            observation_callback(observation)
        raise RuntimeError(f"{failure_phase} failed")

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        daytona_eval_module,
        "load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(daytona_eval_module, "task_docker_image", lambda bundle: "img")
    monkeypatch.setattr(
        daytona_eval_module, "daytona_task_resource_attempts", lambda bundle: [None]
    )
    monkeypatch.setattr(
        daytona_eval_module,
        "provision_hardened_task_sandbox",
        lambda *args, **kwargs: (FakeSandbox(), None),
    )
    monkeypatch.setattr(
        daytona_eval_module, "run_terminalbench_task_in_daytona", fake_agent
    )
    monkeypatch.setattr(
        daytona_eval_module, "run_daytona_harbor_verifier", fake_verifier
    )

    state = asyncio.run(
        hardened_daytona_solver(runner=run_one_hardened_task)(
            _state("phase-observation"), None
        )
    )
    postflight = state.metadata["terminalbench_daytona"]["postflight_verification"]

    assert state.metadata["terminalbench_daytona"]["answer"] == "ERROR"
    assert postflight["tests_uploaded_after_agent"] is tests_uploaded
    assert postflight["verifier_process_started"] is process_started
    assert postflight["clean_verifier_process"] is process_started
    assert postflight["verifier_completed"] is False
    assert agent_runs == ["agent"]


def test_postflight_resource_error_does_not_rerun_agent(monkeypatch, tmp_path):
    agent_runs: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeSandbox:
        def __init__(self, name: str):
            self.name = name
            self.id = name

    agent_sandbox = FakeSandbox("agent")
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    def fake_agent_run(sandbox, loaded_bundle, **kwargs):
        agent_runs.append(sandbox.name)
        assert kwargs["isolate_agent_pid_namespace"] is False
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            hardening_config={"name": "none"},
            agent_pid_namespace_isolation_observed=False,
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    def fake_verifier(
        sandbox,
        loaded_bundle,
        *,
        remote_workdir,
        observation_callback=None,
        **kwargs,
    ):
        assert remote_workdir == "/app"
        assert "include_daytona_user_site" not in kwargs
        raise RuntimeError("verifier failed: no space left on device")

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None, None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (agent_sandbox, None),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_daytona_harbor_verifier",
        fake_verifier,
    )

    with pytest.raises(RuntimeError, match="no space left on device") as exc_info:
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert agent_runs == ["agent"]
    assert (
        exc_info.value.postflight_verification["agent_pid_namespace_isolated"] is False
    )


def _patch_post_agent_verifier_failure(monkeypatch, tmp_path, *, message):
    agent_runs: list[str] = []

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeSandbox:
        id = "shared-sandbox"

    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        agent_timeout_sec=600,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    accounting = {
        "records": 1,
        "input_tokens": 11,
        "output_tokens": 3,
        "cache_read_tokens": 2,
        "cache_write_tokens": 0,
        "total_tokens": 14,
        "cost": 0.004,
        "cost_complete": True,
    }
    artifacts = {
        "harness": "claude_code",
        "file_count": 1,
        "exported_file_count": 1,
        "truncated": False,
        "files": [
            {
                "path": "/home/daytona/.claude/session.jsonl",
                "size_bytes": 8,
                "content": '{"a": 1}',
                "truncated": False,
            }
        ],
    }
    policy_events = [{"surface": "command", "target": "sudo"}]

    def fake_agent_run(sandbox, loaded_bundle, **kwargs):
        agent_runs.append(str(sandbox.id))
        return TerminalBenchAgentRunResult(
            sample_id=bundle.sample_id,
            task_name=bundle.task_name,
            prompt=bundle.input,
            agent_exit_code=0,
            agent_stdout=_STREAM,
            agent_timed_out=True,
            hardening_config={"name": "none"},
            policy_events=policy_events,
            openrouter_accounting=accounting,
            harness_session_artifacts=artifacts,
            effort_level="high",
            effort_level_source="harness_default",
            effort_level_applied=True,
        )

    def fake_verifier(
        sandbox,
        loaded_bundle,
        *,
        remote_workdir,
        observation_callback=None,
        **kwargs,
    ):
        assert "include_daytona_user_site" not in kwargs
        raise RuntimeError(message)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (FakeSandbox(), None),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_daytona_harbor_verifier",
        fake_verifier,
    )
    return agent_runs, accounting, artifacts, policy_events


def test_solver_does_not_rerun_agent_for_transient_marker_from_verifier(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    agent_runs, _accounting, _artifacts, _policy_events = (
        _patch_post_agent_verifier_failure(
            monkeypatch,
            tmp_path,
            message="DaytonaValidationError: Total disk limit exceeded",
        )
    )

    solver = hardened_daytona_solver(runner=run_one_hardened_task)
    state = asyncio.run(solver(_state("verifier-transient-marker"), None))

    assert agent_runs == ["shared-sandbox"]
    assert (
        state.metadata["terminalbench_daytona"]["benchmark_status"]["failure_class"]
        == "verifier_error"
    )


def test_solver_preserves_sealed_agent_result_when_verifier_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    agent_runs, accounting, artifacts, policy_events = (
        _patch_post_agent_verifier_failure(
            monkeypatch,
            tmp_path,
            message="verifier process failed",
        )
    )

    solver = hardened_daytona_solver(runner=run_one_hardened_task)
    state = asyncio.run(solver(_state("verifier-sealed-result"), None))
    meta = state.metadata["terminalbench_daytona"]

    assert agent_runs == ["shared-sandbox"]
    assert meta["benchmark_status"]["failure_class"] == "verifier_error"
    assert {
        "agent_stdout": meta.get("agent_stdout"),
        "policy_events": meta.get("policy_events"),
        "openrouter_accounting": meta.get("openrouter_accounting"),
        "harness_session_artifacts": meta.get("harness_session_artifacts"),
        "usage_input_tokens": getattr(state.output.usage, "input_tokens", None),
        "usage_total_cost": getattr(state.output.usage, "total_cost", None),
    } == {
        "agent_stdout": _STREAM,
        "policy_events": policy_events,
        "openrouter_accounting": accounting,
        "harness_session_artifacts": artifacts,
        "usage_input_tokens": 11,
        "usage_total_cost": pytest.approx(0.004),
    }
    assert meta.get("full_trace") is not None


def test_run_one_task_provisions_for_longer_verifier_timeout(monkeypatch, tmp_path):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=7200,
        agent_timeout_sec=600,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    provision_kwargs: dict = {}

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return object(), None

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: _fake_result("example", 1.0),
    )

    run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        agent_timeout_sec=600,
        policy="control",
    )

    assert provision_kwargs["command_timeout_sec"] == 7200


def test_run_one_task_passes_terminalbench_resources_to_daytona(monkeypatch, tmp_path):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    fake_resources = object()
    provision_kwargs = {}
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/caffe-cifar-10",
        input="Train caffe.",
        task_name="terminal-bench/caffe-cifar-10",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=1200,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return fake_sandbox, None

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "alexgshaw/caffe-cifar-10:20260403",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [fake_resources],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: _fake_result("caffe-cifar-10", 1.0),
    )

    result = run_one_hardened_task(
        "caffe-cifar-10",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="control",
    )

    assert result.answer == "PASS"
    assert provision_kwargs["resources"] is fake_resources


def test_run_one_task_runs_runtime_policy_probes_before_agent(
    monkeypatch, tmp_path, capsys
):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class FakeSandbox:
        id = "sandbox-success"

    fake_sandbox = FakeSandbox()
    fake_hardening = object()
    captured = {}
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    class FakeProbeReport:
        passed = True

        def to_metadata(self):
            return {
                "schema_version": 1,
                "policy_id": "nist-linux-80053-low",
                "passed": True,
                "results": [
                    {
                        "probe_id": "nist-linux-80053-low.command_name.sudo",
                        "status": "pass",
                    }
                ],
            }

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {
                "schema_version": PREFLIGHT_SCHEMA,
                "preflight_passed": True,
                "policy": "nist-linux-80053-low",
                "probe_count": 1,
                "failed_count": 0,
                "all_probes": [
                    {
                        "probe_id": "command-name:curl:probe",
                        "rule_id": "command-name:curl",
                        "surface": "command",
                        "status": "pass",
                        "policy_evidence_seen": True,
                    }
                ],
            }

    class FakeAgentSHSession:
        session_id = "session-managed-low"

        def to_metadata(self):
            return {
                "session_id": self.session_id,
                "policy_name": "boundarybench-nist-linux-80053-low",
                "config_id": "nist-linux-80053-low-agentsh-policy-v1",
            }

    def fake_probe_suite(*args, **kwargs):
        captured["probe_before_agent"] = "agent_called" not in captured
        captured["probe_kwargs"] = kwargs
        return FakeProbeReport()

    def fake_preflight(*args, **kwargs):
        captured["preflight_before_runtime_probe"] = "probe_kwargs" not in captured
        return FakePreflightResult()

    def fake_agent_run(*args, **kwargs):
        captured["agent_called"] = True
        captured["preflight"] = kwargs["preflight"]
        captured["runtime_policy_probe_report"] = kwargs["runtime_policy_probe_report"]
        return _fake_result("example", 1.0, preflight=kwargs["preflight"])

    def fake_agentsh_session(*args, **kwargs):
        captured["agentsh_before_agent"] = "agent_called" not in captured
        return FakeAgentSHSession()

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (fake_sandbox, fake_hardening),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        fake_preflight,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        fake_probe_suite,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.prepare_daytona_agentsh_session",
        fake_agentsh_session,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )

    result = run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="low-nist",
    )

    assert result.answer == "PASS"
    assert result.sandbox_id == "sandbox-success"
    assert result.to_metadata()["sandbox_id"] == "sandbox-success"
    assert result.preflight["preflight_passed"] is True
    assert captured["preflight_before_runtime_probe"] is True
    assert captured["preflight"]["all_probes"][0]["policy_evidence_seen"] is True
    assert captured["probe_before_agent"] is True
    assert "agentsh_before_agent" not in captured
    assert captured["probe_kwargs"]["policy_id"] == "low-nist"
    assert captured["probe_kwargs"]["agent_user"] == "daytona"
    assert captured["probe_kwargs"]["workspace"] == RUNTIME_POLICY_PROBE_WORKSPACE
    assert captured["probe_kwargs"]["unsupported_surfaces"] == ()
    assert captured["runtime_policy_probe_report"]["results"][0]["status"] == "pass"
    captured_output = capsys.readouterr()
    assert "phase=policy_preflight" in captured_output.out
    assert "phase=runtime_policy_probes" in captured_output.out


def test_run_one_task_does_not_create_agentsh_session_for_nist_policy(
    monkeypatch, tmp_path, capsys
):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    fake_hardening = object()
    captured = {}
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    class FakeProbeReport:
        passed = True

        def to_metadata(self):
            return {
                "schema_version": 1,
                "policy_id": "nist-linux-80053-high",
                "passed": True,
                "results": [],
            }

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {"preflight_passed": True, "probe_count": 0, "failed_count": 0}

    class FakeAgentSHSession:
        session_id = "session-managed-example"

        def to_metadata(self):
            return {
                "session_id": self.session_id,
                "policy_name": "boundarybench-nist-linux-80053-high",
                "config_id": "nist-linux-80053-high-agentsh-policy-v1",
            }

    def fake_agentsh_session(sandbox, *, config, run_id):
        raise AssertionError(
            "NIST runtime gate presets should not create AgentSH sessions"
        )
        return FakeAgentSHSession()

    def fake_agent_run(*args, **kwargs):
        captured["agentsh_session_id"] = kwargs["agentsh_session_id"]
        captured["agentsh_policy_session"] = kwargs["agentsh_policy_session"]
        return _fake_result("example", 1.0)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (fake_sandbox, fake_hardening),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        lambda *args, **kwargs: FakePreflightResult(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        lambda *args, **kwargs: FakeProbeReport(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.prepare_daytona_agentsh_session",
        fake_agentsh_session,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )

    result = run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="high-nist",
    )

    assert result.answer == "PASS"
    assert captured["agentsh_session_id"] is None
    assert captured["agentsh_policy_session"] is None
    captured_output = capsys.readouterr()
    assert "phase=agentsh_policy_session" not in captured_output.out


def test_run_one_task_records_opt_in_apparmor_capability_probe(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARYBENCH_APPARMOR_CAPABILITY_PROBE", "1")

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    fake_hardening = object()
    captured = {}
    apparmor_metadata = {
        "engine": "apparmor",
        "status": "unsupported",
        "supported": False,
        "unsupported_reason": "apparmor_parser unavailable",
    }
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    class FakeAppArmorReport:
        status = "unsupported"
        supported = False

        def to_metadata(self):
            return apparmor_metadata

    class FakeProbeReport:
        passed = True

        def __init__(self, mac_capability_probe):
            self.mac_capability_probe = mac_capability_probe

        def to_metadata(self):
            return {
                "schema_version": 2,
                "policy_id": "nist-linux-80053-low",
                "passed": True,
                "mac_capability_probe": self.mac_capability_probe,
                "results": [
                    {
                        "probe_id": "nist-linux-80053-low.command_name.sudo",
                        "status": "pass",
                    }
                ],
            }

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {
                "schema_version": PREFLIGHT_SCHEMA,
                "preflight_passed": True,
                "policy": "nist-linux-80053-low",
                "probe_count": 0,
                "failed_count": 0,
                "all_probes": [],
            }

    class FakeAgentSHSession:
        session_id = "session-managed-low"

        def to_metadata(self):
            return {
                "session_id": self.session_id,
                "policy_name": "boundarybench-nist-linux-80053-low",
                "config_id": "nist-linux-80053-low-agentsh-policy-v1",
            }

    def fake_app_armor_probe(*args, **kwargs):
        captured["apparmor_before_runtime_probe"] = "probe_kwargs" not in captured
        captured["apparmor_before_agent"] = "agent_called" not in captured
        return FakeAppArmorReport()

    def fake_probe_suite(*args, **kwargs):
        captured["probe_kwargs"] = kwargs
        return FakeProbeReport(kwargs["mac_capability_probe"])

    def fake_agent_run(*args, **kwargs):
        captured["agent_called"] = True
        captured["runtime_policy_probe_report"] = kwargs["runtime_policy_probe_report"]
        return _fake_result(
            "example",
            1.0,
            preflight=kwargs["preflight"],
        )

    def fake_agentsh_session(*args, **kwargs):
        captured["agentsh_before_agent"] = "agent_called" not in captured
        return FakeAgentSHSession()

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (fake_sandbox, fake_hardening),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        lambda *args, **kwargs: FakePreflightResult(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_apparmor_capability_probe",
        fake_app_armor_probe,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        fake_probe_suite,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.prepare_daytona_agentsh_session",
        fake_agentsh_session,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_agent_run,
    )

    result = run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="low-nist",
    )

    assert result.answer == "PASS"
    assert captured["apparmor_before_runtime_probe"] is True
    assert captured["apparmor_before_agent"] is True
    assert "agentsh_before_agent" not in captured
    assert captured["probe_kwargs"]["mac_capability_probe"] == apparmor_metadata
    assert (
        captured["runtime_policy_probe_report"]["mac_capability_probe"]
        == apparmor_metadata
    )


def test_solver_records_compact_preflight_metadata_on_success(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    compact_preflight = {
        "schema_version": PREFLIGHT_SCHEMA,
        "preflight_passed": True,
        "policy": "nist-linux-80053-high",
        "probe_count": 1,
        "failed_count": 0,
        "all_probes": [
            {
                "probe_id": "command-name:curl:probe",
                "rule_id": "command-name:curl",
                "surface": "command",
                "status": "pass",
                "policy_evidence_seen": True,
            }
        ],
    }

    def passing_runner(*args, **kwargs):
        return _fake_result("preflight-pass", 1.0, preflight=compact_preflight)

    solver = hardened_daytona_solver(runner=passing_runner)
    state = asyncio.run(solver(_state("preflight-pass"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["preflight"] == compact_preflight
    assert "stdout" not in meta["preflight"]["all_probes"][0]


def test_run_one_task_failing_runtime_policy_probe_prevents_agent(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    fake_hardening = object()
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (fake_sandbox, fake_hardening),
    )

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {"preflight_passed": True, "probe_count": 1}

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        lambda *args, **kwargs: FakePreflightResult(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        lambda *args, **kwargs: _failing_probe_report(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("agent must not run after failed runtime probe")
        ),
    )

    with pytest.raises(DaytonaRuntimeProbeSuiteError) as exc_info:
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="high-nist",
        )
    assert exc_info.value.phase_timings_ms["policy_preflight_ms"] >= 0
    assert exc_info.value.phase_timings_ms["runtime_policy_probes_ms"] >= 0


def test_run_one_task_attaches_sandbox_id_to_bare_probe_exception(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    class BareDaytonaError(RuntimeError):
        pass

    class FakeSandbox:
        id = "sandbox-bare-probe-error"

    class FakePreflightResult:
        def to_compact_metadata(self):
            return {"preflight_passed": True, "probe_count": 1}

    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [None],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        lambda *args, **kwargs: (FakeSandbox(), object()),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_preflight",
        lambda *args, **kwargs: FakePreflightResult(),
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_runtime_policy_probe_suite_in_sandbox",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            BareDaytonaError("Failed to execute command: ")
        ),
    )

    with pytest.raises(BareDaytonaError) as exc_info:
        run_one_hardened_task(
            "example",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="high-nist",
        )

    assert exc_info.value.sandbox_id == "sandbox-bare-probe-error"


def test_solver_records_runtime_policy_probe_failure_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def failing_runner(*args, **kwargs):
        exc = DaytonaRuntimeProbeSuiteError(_failing_probe_report())
        exc.phase_timings_ms = {
            "policy_preflight_ms": 10,
            "runtime_policy_probes_ms": 25,
        }
        exc.phase_timing_details = [
            {
                "component": "terminalbench_daytona",
                "id": "probe-fail",
                "phase": "runtime_policy_probes",
                "elapsed_ms": 25,
                "status": "error",
            }
        ]
        raise exc

    solver = hardened_daytona_solver(runner=failing_runner)
    state = asyncio.run(solver(_state("probe-fail"), None))

    meta = state.metadata["terminalbench_daytona"]
    report = meta["runtime_policy_probe_report"]
    assert meta["answer"] == "ERROR"
    assert "runtime probe suite failed" in meta["error"]
    assert report["passed"] is False
    assert report["required_failed_count"] == 1
    assert report["results"][0]["classification"] == "policy_miss"
    assert meta["preflight_failed"] is False
    assert meta["runtime_probe_failed"] is True
    assert meta["phase_timings_ms"]["runtime_policy_probes_ms"] == 25
    assert meta["phase_timing_details"][0]["phase"] == "runtime_policy_probes"
    assert meta["benchmark_status"]["failure_class"] == "hardening_preflight"


def test_solver_exports_sandbox_id_from_bare_exception(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def failing_runner(*args, **kwargs):
        exc = RuntimeError("Failed to execute command: ")
        exc.sandbox_id = "sandbox-from-exception"
        raise exc

    solver = hardened_daytona_solver(runner=failing_runner)
    state = asyncio.run(solver(_state("bare-error"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["sandbox_id"] == "sandbox-from-exception"
    assert meta["error_message"] == "Failed to execute command: "


def test_solver_records_raw_exception_traceback_metadata(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

    def failing_runner(*args, **kwargs):
        raise ExceptionGroup(
            "unhandled errors in a TaskGroup",
            [FileNotFoundError(2, "No such file or directory")],
        )

    solver = hardened_daytona_solver(runner=failing_runner)
    state = asyncio.run(solver(_state("raw-error"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["error_type"] == "ExceptionGroup"
    assert "unhandled errors in a TaskGroup" in meta["error_message"]
    assert "FileNotFoundError" in meta["error_traceback"]
    assert "No such file or directory" in meta["error_traceback"]
    assert meta["preflight_failed"] is False
    assert meta["runtime_probe_failed"] is False


def test_run_one_task_does_not_retry_resource_failure_with_larger_profile(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        def delete(self, sandbox):
            deleted.append(sandbox)

    class FakeResources:
        def __init__(self, cpu, memory, disk, gpu=None):
            self.cpu = cpu
            self.memory = memory
            self.disk = disk
            self.gpu = gpu

    deleted = []
    sandboxes = [object(), object()]
    provisioned = []
    attempts = 0
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/make-doom-for-mips",
        input="Build it.",
        task_name="terminal-bench/make-doom-for-mips",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=1200,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    profiles = [
        FakeResources(cpu=1, memory=2, disk=3),
        FakeResources(cpu=1, memory=2, disk=10),
    ]

    def fake_provision(*args, **kwargs):
        provisioned.append(kwargs["resources"])
        return sandboxes[len(provisioned) - 1], None

    def fail_resource_error(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("tar: test_outputs.py: Cannot open: No space left on device")

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "alexgshaw/make-doom-for-mips:20251031",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: profiles,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fail_resource_error,
    )

    with pytest.raises(RuntimeError, match="No space left on device"):
        run_one_hardened_task(
            "make-doom-for-mips",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert attempts == 1
    assert [(r.cpu, r.memory, r.disk, r.gpu) for r in provisioned] == [(1, 2, 3, None)]
    assert deleted == [sandboxes[0]]


def test_run_one_task_does_not_resource_retry_transient_infra_error(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        def delete(self, sandbox):
            deleted.append(sandbox)

    class FakeResources:
        def __init__(self, cpu, memory, disk, gpu=None):
            self.cpu = cpu
            self.memory = memory
            self.disk = disk
            self.gpu = gpu

    deleted = []
    fake_sandbox = object()
    provisioned = []
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/caffe-cifar-10",
        input="Train it.",
        task_name="terminal-bench/caffe-cifar-10",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=1200,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    profiles = [
        FakeResources(cpu=1, memory=2, disk=3),
        FakeResources(cpu=1, memory=2, disk=10),
    ]

    def fake_provision(*args, **kwargs):
        provisioned.append(kwargs["resources"])
        return fake_sandbox, None

    def fail_with_transient_infra(*args, **kwargs):
        raise RuntimeError(
            "DaytonaValidationError: no IP address found. "
            "Is the Sandbox started? resource exhausted"
        )

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "alexgshaw/caffe-cifar-10:20260403",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: profiles,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fail_with_transient_infra,
    )

    with pytest.raises(RuntimeError, match="no IP address found"):
        run_one_hardened_task(
            "caffe-cifar-10",
            ref="terminal-bench==2.1",
            model="minimax/minimax-m3",
            openrouter_api_key="sk-or-test",
            policy="control",
        )

    assert [(r.cpu, r.memory, r.disk, r.gpu) for r in provisioned] == [
        (1, 2, 3, None),
    ]
    assert deleted == [fake_sandbox]


def test_solver_retries_zero_turn_start(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    zero_turn_stream = (
        '{"type":"result","subtype":"success","result":"done",'
        '"usage":{"input_tokens":1,"output_tokens":0}}'
    )
    attempts = 0

    def zero_then_ok(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return _fake_result(task_id, 0.0, agent_stdout=zero_turn_stream)
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=zero_then_ok, harness="claude_code")
    state = asyncio.run(solver(_state("zero-turn"), None))

    assert attempts == 2
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PASS"
    assert meta["attempt"] == 2
    assert "zero assistant turns" in meta["retry_errors"][0]


def test_solver_preserves_verifier_result_when_trace_proves_terminus_activity(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "3")
    attempts = 0
    cancelled_stdout = (
        'TERMINUS2_RESULT {"error":"","error_type":"CancelledError",'
        '"status":"error","type":"terminus_2.result"}'
    )
    trajectory = {
        "steps": [
            {
                "source": "agent",
                "message": "working",
                "tool_calls": [
                    {
                        "tool_call_id": "call-1",
                        "function_name": "bash_command",
                        "arguments": {"keystrokes": "touch /app/done\n"},
                    }
                ],
                "observation": {
                    "results": [{"source_call_id": "call-1", "content": ""}]
                },
            }
        ]
    }
    session_artifacts = {
        "truncated": False,
        "files": [
            {
                "path": "/root/.terminus-2/sessions/current/trajectory.json",
                "content": json.dumps(trajectory),
                "truncated": False,
            }
        ],
    }

    def cancelled_after_work(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        return _fake_result(
            task_id,
            1.0,
            agent_stdout=cancelled_stdout,
            agent_exit_code=1,
            harness="terminus_2",
            harness_session_artifacts=session_artifacts,
        )

    state = asyncio.run(
        hardened_daytona_solver(
            runner=cancelled_after_work,
            harness="terminus_2",
        )(_state("terminus-cancelled-after-work"), None)
    )

    meta = state.metadata["terminalbench_daytona"]
    assert attempts == 1
    assert meta["answer"] == "PASS"
    assert meta["attempt"] == 1
    assert meta["activity"] == {"assistant_turns": 1, "tool_calls": 1}
    assert meta["full_trace"]["assistant_message_count"] == 1
    assert meta["full_trace"]["tool_call_count"] == 1


def test_solver_final_terminus_error_keeps_verbose_trace_and_activity(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    cancelled_stdout = (
        'TERMINUS2_RESULT {"error":"","error_type":"CancelledError",'
        '"status":"error","type":"terminus_2.result"}'
    )
    trajectory = {
        "steps": [
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:00Z",
                "reasoning_content": "I should inspect the workspace.",
                "message": "working",
                "tool_calls": [
                    {
                        "tool_call_id": "call-1",
                        "function_name": "bash_command",
                        "arguments": {"keystrokes": "ls -la\n"},
                    }
                ],
                "observation": {
                    "results": [{"source_call_id": "call-1", "content": "file.txt"}]
                },
            }
        ]
    }
    artifacts = {
        "harness": "terminus_2",
        "truncated": False,
        "files": [
            {
                "path": "/root/.terminus-2/sessions/current/trajectory.json",
                "content": json.dumps(trajectory),
                "truncated": False,
            }
        ],
    }
    failed_result = _fake_result(
        "terminus-final-error",
        0.0,
        agent_stdout=cancelled_stdout,
        agent_exit_code=1,
        harness="terminus_2",
        harness_session_artifacts=artifacts,
    )

    def fail_after_work(*args, **kwargs):
        raise daytona_eval_module._TransientTaskAttempt(
            "agent produced zero assistant turns", result=failed_result
        )

    state = asyncio.run(
        hardened_daytona_solver(runner=fail_after_work, harness="terminus_2")(
            _state("terminus-final-error"), None
        )
    )

    meta = state.metadata["terminalbench_daytona"]
    transcript = state.metadata["transcript_markdown"]
    assert meta["answer"] == "ERROR"
    assert meta["activity"] == {"assistant_turns": 1, "tool_calls": 1}
    assert meta["full_trace"]["assistant_message_count"] == 1
    assert meta["full_trace"]["tool_call_count"] == 1
    assert meta["full_trace"]["events"][-1]["type"] == "error"
    assert meta["full_trace"]["events"][-1]["message"] == "CancelledError"
    assert "I should inspect the workspace." in transcript
    assert "**🔧 tool call → `bash_command`**" in transcript
    assert "file.txt" in transcript
    assert "**⚠️ harness error**" in transcript


def test_solver_preserves_zero_turn_stdout_on_final_failure(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    zero_turn_stream = (
        '{"type":"system","subtype":"init","model":"minimax/minimax-m3"}\n'
        "Permission denied\n"
        '{"type":"result","subtype":"error","result":"api failed",'
        '"usage":{"input_tokens":1,"output_tokens":0}}'
    )

    solver = hardened_daytona_solver(
        harness="claude_code",
        runner=lambda task_id, **kwargs: _fake_result(
            task_id, 0.0, agent_stdout=zero_turn_stream
        )
    )
    state = asyncio.run(solver(_state("zero-turn-final"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["agent_stdout"] == zero_turn_stream
    assert meta["activity"]["assistant_turns"] == 0
    assert "zero assistant turns" in meta["error"]
    assert "api failed" in state.metadata["transcript_markdown"]


def test_solver_preserves_agent_stderr_and_stream_diagnostics(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    malformed_stream = (
        '{"type":"assistant","message":{"content":[{"type":"text","text":"working"}]}}\n'
        '{"type":"assistant","message":{"content":[{"type":"redacted_thinking","data":"cut'
    )

    solver = hardened_daytona_solver(
        runner=lambda task_id, **kwargs: _fake_result(
            task_id,
            0.0,
            agent_stdout=malformed_stream,
            agent_stderr="provider stream ended unexpectedly",
            agent_exit_code=1,
        )
    )
    state = asyncio.run(solver(_state("malformed-stream"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["agent_exit_code"] == 1
    assert meta["agent_stderr"] == "provider stream ended unexpectedly"
    assert meta["agent_stdout_parse_error_count"] == 1
    assert meta["agent_stdout_last_complete_event_type"] == "assistant"
    assert meta["agent_stdout_truncated_or_malformed"] is True


def test_solver_preserves_usage_and_cost_when_final_result_event_missing(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    no_result_stream = (
        '{"type":"system","subtype":"init","model":"minimax/minimax-m3"}\n'
        '{"type":"assistant","usage":{"input_tokens":5,"output_tokens":1},'
        '"message":{"content":[{"type":"text","text":"working"}]}}\n'
        '{"type":"assistant","usage":{"input_tokens":7,"output_tokens":2},'
        '"message":{"content":[{"type":"text","text":"still working"}]}}\n'
    )

    solver = hardened_daytona_solver(
        harness="claude_code",
        model="minimax/minimax-m3",
        runner=lambda task_id, **kwargs: _fake_result(
            task_id, 0.0, agent_stdout=no_result_stream
        ),
    )
    state = asyncio.run(solver(_state("no-final-result"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["agent_stdout_truncated_or_malformed"] is False
    assert meta["agent_stdout_result_event_missing"] is True
    assert meta["agent_stdout_final_result_event_present"] is False
    assert meta["agent_model_usage_present"] is True
    assert meta["agent_model_usage_source"] == "partial_events"
    assert meta["agent_model_usage_recovered"] is True
    assert meta["agent_model_cost_available"] is True
    assert state.output.usage.input_tokens == 12
    assert state.output.usage.output_tokens == 3


def test_solver_native_accounting_recovers_grok_usage_and_renders_transcript(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    accounting = {
        "records": 4,
        "input_tokens": 43817,
        "output_tokens": 361,
        "cache_read_tokens": 22400,
        "cache_write_tokens": 0,
        "total_tokens": 44178,
        "cost": 0.03215375,
        "cost_complete": True,
    }
    grok_stdout = '{"text":"I inspected the repository."}'

    solver = hardened_daytona_solver(
        harness="grok",
        runner=lambda task_id, **kwargs: _fake_result(
            task_id,
            0.0,
            agent_stdout=grok_stdout,
            openrouter_accounting=accounting,
            harness="grok",
        ),
    )
    state = asyncio.run(solver(_state("grok-native-accounting"), None))

    meta = state.metadata["terminalbench_daytona"]
    transcript = state.metadata["transcript_markdown"]
    assert meta["agent_model_usage_available"] is True
    assert meta["agent_model_usage_present"] is True
    assert meta["agent_model_usage_source"] == "openrouter_accounting_proxy"
    assert meta["agent_model_usage_recovered"] is True
    assert meta["agent_model_cost_available"] is True
    assert (
        "- **Usage:** in=43817 out=361 cache_read=22400 cache_write=0 cost=$0.03215375"
    ) in transcript


def test_solver_proxy_usage_does_not_mark_complete_claude_usage_recovered(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    accounting = {
        "records": 1,
        "input_tokens": 110,
        "output_tokens": 22,
        "cache_read_tokens": 10,
        "cache_write_tokens": 0,
        "total_tokens": 132,
        "cost": 0.04,
        "cost_complete": True,
    }

    solver = hardened_daytona_solver(
        runner=lambda task_id, **kwargs: _fake_result(
            task_id,
            1.0,
            openrouter_accounting=accounting,
        )
    )
    state = asyncio.run(solver(_state("claude-proxy-usage"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["agent_model_usage_present"] is True
    assert meta["agent_model_usage_source"] == "openrouter_accounting_proxy"
    assert meta["agent_model_usage_recovered"] is False


def test_solver_counts_structured_policy_events(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    agent_stdout = (
        '{"type":"assistant","timestamp":"2026-07-06T00:00:01Z",'
        '"message":{"content":[{"type":"tool_use","id":"pre","name":"Bash",'
        '"input":{"command":"before"}}],"model":"m"}}\n'
        '{"type":"assistant","timestamp":"2026-07-06T00:00:05Z",'
        '"message":{"content":[{"type":"tool_use","id":"post","name":"Bash",'
        '"input":{"command":"after"}}],"model":"m"}}\n'
        '{"type":"result","subtype":"success","result":"done",'
        '"usage":{"input_tokens":100,"output_tokens":20}}'
    )
    events = [
        {"event_type": "policy_enforce", "surface": "full_mac_enforcement"},
        {
            "event_type": "policy_block",
            "surface": "command",
            "command": "bash",
            "timestamp": "2026-07-06T00:00:03Z",
            "comm": "bash",
            "cmdline": "bash blocked.sh",
        },
    ]

    solver = hardened_daytona_solver(
        harness="claude_code",
        runner=lambda task_id, **kwargs: _fake_result(
            task_id,
            1.0,
            agent_stdout=agent_stdout,
            policy_events=events,
            task_net_runtime_ms=60_000,
        )
    )
    state = asyncio.run(solver(_state("policy-event"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["policy_events"] == events
    assert meta["policy_event_count"] == 2
    assert meta["policy_block_count"] == 1
    assert meta["blocked_surface_count"] == 1
    assert meta["unique_blocked_target_count"] == 1
    assert meta["top_blocked_target_share"] == 1.0
    assert meta["blocks_per_minute"] == 1.0
    assert meta["post_first_block_tool_calls"] == 1
    assert meta["policy_block_process_counts"] == {"bash": 1}
    assert meta["policy_block_cmdline_counts"] == {"bash blocked.sh": 1}
    assert meta["agent_model_usage_available"] is True


def test_solver_requires_openrouter_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    solver = hardened_daytona_solver(runner=lambda *a, **k: _fake_result("x", 1.0))
    with pytest.raises(RuntimeError, match="Cloud Run Secret Manager environment"):
        asyncio.run(solver(_state("x"), None))


def test_scorer_surfaces_official_reward():
    state = _state("x")
    state.metadata["terminalbench_daytona"] = {"reward": 0.0, "answer": "FAIL"}
    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert score.value == 0.0
    assert score.answer == "FAIL"


def test_solver_classifies_preflight_failure_as_invalid_hardening_error(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "5")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    attempts = 0
    policy = HardeningPolicy(
        name="preflight-test",
        config=DEFAULT_DAYTONA_HARDENING_CONFIG,
        overlays=("blocked-surfaces",),
        agent_user="daytona",
    )
    proof_plan = build_policy_proof_plan(policy)
    failed_probe = proof_plan.probes[0].to_probe_result(
        observed="allowed",
        status="fail",
        exit_code=0,
        stdout="allowed",
        stderr="",
        message="expected blocked, observed allowed",
    )
    preflight = PreflightResult(
        passed=False,
        proof_plan=proof_plan,
        results=(failed_probe,),
        failed_probes=(failed_probe,),
    )

    def boom(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        raise PreflightFailedError("policy preflight failed", result=preflight)

    solver = hardened_daytona_solver(runner=boom)
    state = asyncio.run(solver(_state("preflight-fail"), None))

    assert attempts == 1
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "INVALID"
    assert meta["preflight_rejected"] is True
    assert meta["preflight"]["preflight_passed"] is False
    assert meta["benchmark_status"]["task_outcome"] == "INVALID"
    assert meta["benchmark_status"]["failure_class"] == "hardening_preflight"
    assert meta["benchmark_status"]["valid_for_analysis"] is False
    assert "## Policy Preflight" in state.metadata["transcript_markdown"]
    assert "command-name:curl" in state.metadata["transcript_markdown"]


def test_scorer_preserves_preflight_failure_as_unscored():
    state = _state("x")
    state.metadata["terminalbench_daytona"] = {
        "reward": 0.0,
        "answer": "INVALID",
        "preflight_rejected": True,
        "benchmark_status": {
            "task_outcome": "INVALID",
            "failure_class": "hardening_preflight",
            "valid_for_analysis": False,
        },
    }

    score = asyncio.run(hardened_daytona_scorer()(state, None))

    assert math.isnan(score.value)
    assert score.answer == "INVALID"
    assert score.metadata["preflight_rejected"] is True
    assert "hardening preflight" in score.explanation.lower()


_PROVIDER_ERROR_STREAM = (
    '{"type":"system","subtype":"init","model":"minimax/minimax-m3"}\n'
    "Error: HTTP 403 key-limit reached for this OpenRouter key\n"
    '{"type":"result","subtype":"error","result":"api error",'
    '"usage":{"input_tokens":0,"output_tokens":0}}'
)


def test_solver_classifies_provider_error_as_provider_error(monkeypatch):
    """A provider/auth failure with zero turns should be PROVIDER_ERROR, not FAIL."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )

    solver = hardened_daytona_solver(
        harness="claude_code",
        runner=lambda task_id, **kwargs: _fake_result(
            task_id, 0.0, agent_stdout=_PROVIDER_ERROR_STREAM
        )
    )
    state = asyncio.run(solver(_state("provider-fail"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PROVIDER_ERROR"
    assert meta["provider_error"] is True
    assert meta["provider_error_detail"] is not None
    assert meta["provider_error_detail"]["marker"] == "key-limit"
    assert state.metadata["reward"] == 0.0


def test_solver_retries_provider_errors_before_classifying(monkeypatch):
    """Provider errors are transient — the solver should retry before giving up."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.TRANSIENT_RETRY_BACKOFF_SEC",
        0,
    )
    attempts = 0

    def provider_then_ok(task_id, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return _fake_result(task_id, 0.0, agent_stdout=_PROVIDER_ERROR_STREAM)
        return _fake_result(task_id, 1.0)

    solver = hardened_daytona_solver(runner=provider_then_ok, harness="claude_code")
    state = asyncio.run(solver(_state("provider-retry"), None))

    assert attempts == 3
    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "PASS"
    assert meta["attempt"] == 3
    assert len(meta["retry_errors"]) == 2


def test_scorer_preserves_provider_error_answer_as_unscored():
    """Provider/auth failures keep their label but do not affect metrics."""
    state = _state("x")
    state.metadata["terminalbench_daytona"] = {
        "reward": 0.0,
        "answer": "PROVIDER_ERROR",
        "provider_error": True,
    }
    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert math.isnan(score.value)
    assert score.answer == "PROVIDER_ERROR"
    assert score.metadata["provider_error"] is True
    assert "PROVIDER_ERROR" in score.explanation
    assert "not a benchmark FAIL" in score.explanation


def test_provider_errors_are_excluded_from_final_mean_metric():
    """Inspect should count provider errors as unscored, not zero-reward samples."""
    provider_state = _state("provider-error")
    provider_state.metadata["terminalbench_daytona"] = {
        "reward": 0.0,
        "answer": "PROVIDER_ERROR",
        "provider_error": True,
    }
    provider_score = asyncio.run(hardened_daytona_scorer()(provider_state, None))
    pass_score = Score(value=1.0, answer="PASS")

    eval_scores = scorer_for_metrics(
        scorer_name="hardened_daytona_scorer",
        scorer_info=ScorerInfo(name="hardened_daytona_scorer", metrics=[mean()]),
        sample_scores=[
            SampleScore(score=provider_score, sample_id="provider-error"),
            SampleScore(score=pass_score, sample_id="passing-task"),
        ],
        metrics=[mean()],
    )

    assert len(eval_scores) == 1
    result = eval_scores[0]
    assert result.scored_samples == 1
    assert result.unscored_samples == 1
    assert result.metrics["mean"].value == 1.0


def test_daytona_infra_errors_are_excluded_from_final_mean_metric():
    """Daytona lifecycle failures stay visible but do not lower model metrics."""
    infra_state = _state("daytona-error")
    infra_state.metadata["terminalbench_daytona"] = {
        "reward": 0.0,
        "answer": "ERROR",
        "error": (
            "DaytonaNotFoundError: Failed to get session command: "
            "sandbox container not found"
        ),
        "benchmark_status": {
            "task_outcome": "ERROR",
            "failure_class": "infra_daytona",
            "valid_for_analysis": False,
        },
    }
    infra_score = asyncio.run(hardened_daytona_scorer()(infra_state, None))
    pass_score = Score(value=1.0, answer="PASS")

    eval_scores = scorer_for_metrics(
        scorer_name="hardened_daytona_scorer",
        scorer_info=ScorerInfo(name="hardened_daytona_scorer", metrics=[mean()]),
        sample_scores=[
            SampleScore(score=infra_score, sample_id="daytona-error"),
            SampleScore(score=pass_score, sample_id="passing-task"),
        ],
        metrics=[mean()],
    )

    assert math.isnan(infra_score.value)
    assert infra_score.answer == "ERROR"
    assert "infra_daytona" in infra_score.explanation
    assert len(eval_scores) == 1
    result = eval_scores[0]
    assert result.scored_samples == 1
    assert result.unscored_samples == 1
    assert result.metrics["mean"].value == 1.0


def test_verifier_harness_failures_are_excluded_from_final_mean_metric():
    """A verifier timeout/crash is a harness failure, not a model FAIL.

    It must stay visible (unscored ERROR) but not deflate the success-rate mean.
    """
    for failure_class in ("verifier_timeout", "verifier_error"):
        verifier_state = _state(f"verifier-{failure_class}")
        verifier_state.metadata["terminalbench_daytona"] = {
            "reward": 0.0,
            "answer": "ERROR",
            "benchmark_status": {
                "task_outcome": "ERROR",
                "failure_class": failure_class,
                "valid_for_analysis": False,
            },
        }
        verifier_score = asyncio.run(hardened_daytona_scorer()(verifier_state, None))
        pass_score = Score(value=1.0, answer="PASS")

        eval_scores = scorer_for_metrics(
            scorer_name="hardened_daytona_scorer",
            scorer_info=ScorerInfo(name="hardened_daytona_scorer", metrics=[mean()]),
            sample_scores=[
                SampleScore(
                    score=verifier_score, sample_id=f"verifier-{failure_class}"
                ),
                SampleScore(score=pass_score, sample_id="passing-task"),
            ],
            metrics=[mean()],
        )

        assert math.isnan(verifier_score.value)
        assert verifier_score.answer == "ERROR"
        assert failure_class in verifier_score.explanation
        result = eval_scores[0]
        assert result.scored_samples == 1
        assert result.unscored_samples == 1
        assert result.metrics["mean"].value == 1.0


def test_solver_classifies_daytona_account_capacity_as_unscored_infra_resource(
    monkeypatch,
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")

    def daytona_capacity_error(*args, **kwargs):
        raise RuntimeError("DaytonaValidationError: Total disk limit exceeded")

    solver = hardened_daytona_solver(runner=daytona_capacity_error)
    state = asyncio.run(solver(_state("capacity-error"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert "Total disk limit exceeded" in meta["error"]
    assert meta["benchmark_status"]["task_outcome"] == "ERROR"
    assert meta["benchmark_status"]["failure_class"] == "infra_resource"
    assert meta["benchmark_status"]["valid_for_analysis"] is False

    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert math.isnan(score.value)
    assert score.answer == "ERROR"
    assert "infra_resource" in score.explanation


def test_solver_classifies_missing_reward_as_unscored_verifier_error(monkeypatch):
    """A verifier crash (no reward file) is a verifier/harness failure.

    Exercises the real classification path end-to-end (not a hand-set status):
    the runner raises the same FileNotFoundError run_daytona_harbor_verifier
    raises when no reward file is produced, and the sample must land on
    verifier_error and be excluded from the mean.
    """
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")

    def missing_reward(*args, **kwargs):
        raise FileNotFoundError("No reward file found under /logs/verifier")

    solver = hardened_daytona_solver(runner=missing_reward)
    state = asyncio.run(solver(_state("verifier-crash"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["benchmark_status"]["failure_class"] == "verifier_error"
    assert meta["benchmark_status"]["valid_for_analysis"] is False

    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert math.isnan(score.value)
    assert score.answer == "ERROR"
    assert "verifier_error" in score.explanation


def test_solver_excludes_post_agent_verifier_failure_from_mean(monkeypatch):
    """A post-agent verifier failure is a pipeline/harness failure.

    A verifier failure after a successful agent run must not be scored 0.0 as a
    model FAIL; it is excluded from the mean.
    """
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("BOUNDARYBENCH_TASK_MAX_ATTEMPTS", "1")

    def verifier_failure(*args, **kwargs):
        raise RuntimeError("verifier error: failed to launch verifier process")

    solver = hardened_daytona_solver(runner=verifier_failure)
    state = asyncio.run(solver(_state("verifier-launch-failure"), None))

    meta = state.metadata["terminalbench_daytona"]
    assert meta["answer"] == "ERROR"
    assert meta["benchmark_status"]["failure_class"] == "verifier_error"
    assert meta["benchmark_status"]["valid_for_analysis"] is False

    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert math.isnan(score.value)


def test_scorer_does_not_flag_normal_fail_as_provider_error():
    """A legitimate FAIL should not be affected by provider error logic."""
    state = _state("x")
    state.metadata["terminalbench_daytona"] = {"reward": 0.0, "answer": "FAIL"}
    score = asyncio.run(hardened_daytona_scorer()(state, None))
    assert score.answer == "FAIL"
    assert "PROVIDER_ERROR" not in score.explanation


def test_run_one_task_native_empty_overlays_still_installs_and_threads_mode(
    monkeypatch, tmp_path
):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    provision_kwargs: dict = {}
    run_kwargs: dict = {}
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    native_empty_policy = HardeningPolicy(
        name="native-empty",
        config=DEFAULT_DAYTONA_HARDENING_CONFIG,
        overlays=(),
        enforcement_mode="native",
    )

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return fake_sandbox, None

    def fake_run(*args, **kwargs):
        run_kwargs.update(kwargs)
        return _fake_result("example", 1.0)

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.resolve_policy_for_run",
        lambda policy: native_empty_policy,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [object()],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        fake_run,
    )

    result = run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="native-empty",
    )

    assert result.answer == "PASS"
    assert provision_kwargs["install_policy_hardening"] is True
    assert provision_kwargs["enforcement_mode"] == "native"
    assert run_kwargs["enforcement_mode"] == "native"


def test_run_one_task_legacy_empty_overlays_skips_install(monkeypatch, tmp_path):
    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    provision_kwargs: dict = {}
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Solve it.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )
    legacy_empty_policy = HardeningPolicy(
        name="legacy-empty",
        config=DEFAULT_DAYTONA_HARDENING_CONFIG,
        overlays=(),
    )

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return fake_sandbox, None

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.resolve_policy_for_run",
        lambda policy: legacy_empty_policy,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [object()],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: _fake_result("example", 1.0),
    )

    result = run_one_hardened_task(
        "example",
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy="legacy-empty",
    )

    assert result.answer == "PASS"
    assert provision_kwargs["install_policy_hardening"] is False
    assert provision_kwargs["enforcement_mode"] == "legacy"


def _bundle_for(tmp_path, task_id: str) -> TerminalBenchTaskBundle:
    return TerminalBenchTaskBundle(
        sample_id=f"terminal-bench/{task_id}",
        input="Solve it.",
        task_name=f"terminal-bench/{task_id}",
        task_dir=tmp_path,
        tests_dir=tmp_path,
        test_path=tmp_path / "test.sh",
        verifier_timeout_sec=120,
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )


def _run_capturing_provision(monkeypatch, tmp_path, *, task_id: str, policy: str):
    """Run one hardened task, capturing the hardening_config passed to provision.

    Everything downstream of config selection is monkeypatched, so this exercises
    the real resolve_policy_for_run + config recompute path without Daytona.
    """

    class FakeDaytona:
        def delete(self, sandbox):
            pass

    fake_sandbox = object()
    provision_kwargs: dict = {}
    bundle = _bundle_for(tmp_path, task_id)

    def fake_provision(*args, **kwargs):
        provision_kwargs.update(kwargs)
        return fake_sandbox, None

    monkeypatch.setattr("daytona_sdk.Daytona", FakeDaytona)
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.load_terminalbench_daytona_bundle",
        lambda task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.task_docker_image",
        lambda loaded_bundle: "registry/example:1",
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.daytona_task_resource_attempts",
        lambda loaded_bundle: [object()],
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.provision_hardened_task_sandbox",
        fake_provision,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.run_terminalbench_task_in_daytona",
        lambda *args, **kwargs: _fake_result(task_id, 1.0),
    )

    result = run_one_hardened_task(
        task_id,
        ref="terminal-bench==2.1",
        model="minimax/minimax-m3",
        openrouter_api_key="sk-or-test",
        policy=policy,
    )
    assert result.answer == "PASS"
    assert provision_kwargs["task_id"] == task_id
    return provision_kwargs["hardening_config"]


@pytest.mark.parametrize("policy", ["low-nist", "moderate-nist"])
def test_run_one_task_threads_task_id_into_native_egress_allowlist(
    monkeypatch, tmp_path, policy
):
    task_domains = {"cloud.r-project.org", "cran.r-project.org"}
    config = _run_capturing_provision(
        monkeypatch, tmp_path, task_id="bn-fit-modify", policy=policy
    )

    assert config.name == policy
    assert task_domains.issubset(set(config.egress_domain_allowlist))


def test_run_one_task_native_config_omits_task_domains_for_unknown_task(
    monkeypatch, tmp_path
):
    from boundarybench.daytona.policy_axes import task_egress_domains

    task_domains = task_egress_domains("bn-fit-modify")

    config = _run_capturing_provision(
        monkeypatch,
        tmp_path,
        task_id="definitely-unknown-terminal-bench-task",
        policy="moderate-nist",
    )

    allowlist = set(config.egress_domain_allowlist)
    assert allowlist.isdisjoint(task_domains)


def test_run_one_task_task_id_is_inert_for_non_parameterized_control_preset(
    monkeypatch, tmp_path
):
    config = _run_capturing_provision(
        monkeypatch, tmp_path, task_id="adaptive-rejection-sampler", policy="control"
    )

    assert config.name == "control"
    assert config.egress_domain_allowlist == ()


def _axis_config(preset: str):
    from boundarybench.daytona.policy_axes import (
        AXIS_PRESETS,
        build_daytona_config_from_axes,
    )

    return build_daytona_config_from_axes(AXIS_PRESETS[preset])


@pytest.mark.parametrize("preset", ["low-nist", "high-nist"])
def test_health_overlay_injects_running_harness_only(preset):
    from boundarybench.harness.claude_code import ClaudeCodeAdapter
    from boundarybench.harness.codex import CodexAdapter

    base = _axis_config(preset)
    base_domains = set(base.egress_domain_allowlist)

    codex = _with_harness_health_domains(base, CodexAdapter())
    claude = _with_harness_health_domains(base, ClaudeCodeAdapter())
    codex_added = set(codex.egress_domain_allowlist) - base_domains
    claude_added = set(claude.egress_domain_allowlist) - base_domains

    assert codex_added == {"chatgpt.com"}
    assert claude_added <= {"api.anthropic.com"}
    assert "api.anthropic.com" not in codex_added
    assert "chatgpt.com" not in claude_added
    assert "chatgpt.com" in codex.egress_domain_allowlist
    assert "api.anthropic.com" in claude.egress_domain_allowlist
    assert "chatgpt.com" not in claude.egress_domain_allowlist


def test_anthropic_shared_on_n1_but_claude_scoped_on_model_plane():
    from boundarybench.harness.codex import CodexAdapter

    n1_codex = _with_harness_health_domains(_axis_config("low-nist"), CodexAdapter())
    assert "api.anthropic.com" in n1_codex.egress_domain_allowlist

    n2_codex = _with_harness_health_domains(
        _axis_config("moderate-nist"), CodexAdapter()
    )
    assert "api.anthropic.com" not in n2_codex.egress_domain_allowlist


def test_high_nist_codex_adds_declared_health_domain():
    from boundarybench.harness.codex import CodexAdapter

    base = _axis_config("high-nist")
    overlaid = _with_harness_health_domains(base, CodexAdapter())

    assert "chatgpt.com" not in base.egress_domain_allowlist
    assert overlaid.egress_domain_allowlist == (
        *base.egress_domain_allowlist,
        "chatgpt.com",
    )
    assert len(overlaid.egress_domain_allowlist) == 206


def test_high_nist_claude_domain_is_already_in_trusted_base():
    from boundarybench.harness.claude_code import ClaudeCodeAdapter

    base = _axis_config("high-nist")
    overlaid = _with_harness_health_domains(base, ClaudeCodeAdapter())

    assert "api.anthropic.com" in base.egress_domain_allowlist
    assert overlaid is base
    assert len(overlaid.egress_domain_allowlist) == 205


def test_high_nist_grok_contributes_no_health_domain():
    from boundarybench.harness.grok import GrokAdapter

    base = _axis_config("high-nist")

    assert _with_harness_health_domains(base, GrokAdapter()) is base
    assert len(base.egress_domain_allowlist) == 205


@pytest.mark.parametrize("preset", ["control", "fslock"])
def test_health_overlay_noop_when_domain_egress_ungated(preset):
    from boundarybench.harness.claude_code import ClaudeCodeAdapter
    from boundarybench.harness.codex import CodexAdapter

    base = _axis_config(preset)
    assert base.domain_egress_enabled is False
    assert _with_harness_health_domains(base, ClaudeCodeAdapter()) is base
    assert _with_harness_health_domains(base, CodexAdapter()) is base


def test_health_overlay_grok_contributes_nothing():
    from boundarybench.harness.grok import GrokAdapter

    base = _axis_config("low-nist")
    assert _with_harness_health_domains(base, GrokAdapter()) is base


def test_health_overlay_does_not_duplicate_present_domain():
    from dataclasses import replace

    from boundarybench.harness.codex import CodexAdapter

    base = _axis_config("high-nist")
    seeded = replace(
        base,
        egress_domain_allowlist=(*base.egress_domain_allowlist, "chatgpt.com"),
    )
    overlaid = _with_harness_health_domains(seeded, CodexAdapter())
    assert overlaid.egress_domain_allowlist == seeded.egress_domain_allowlist
    assert overlaid.egress_domain_allowlist.count("chatgpt.com") == 1


def test_home_carveout_overlay_injects_running_harness_dirs():
    from boundarybench.harness.claude_code import ClaudeCodeAdapter
    from boundarybench.harness.codex import CodexAdapter
    from boundarybench.terminalbench.daytona_eval import (
        _with_harness_home_carveouts,
    )

    from boundarybench.harness.grok import GrokAdapter

    base = _axis_config("high-nist")
    codex = _with_harness_home_carveouts(base, CodexAdapter())
    claude = _with_harness_home_carveouts(base, ClaudeCodeAdapter())
    grok = _with_harness_home_carveouts(base, GrokAdapter())
    assert ".codex" in codex.f3_home_carveout_subdirs
    assert ".grok" in grok.f3_home_carveout_subdirs
    assert codex.f3_home_carveout_subdirs[0] == ".claude"
    assert claude.f3_home_carveout_subdirs == base.f3_home_carveout_subdirs
    assert ".codex" not in claude.f3_home_carveout_subdirs
    assert ".grok" not in codex.f3_home_carveout_subdirs
