import asyncio
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
import inspect_ai.util as inspect_util
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput
from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import TaskState, solver

import boundarybench._registry as registry
import boundarybench.terminalbench.harbor as harbor_module
import boundarybench.task_runtime.loading as hardening_loading
import boundarybench.task_runtime.sandbox as sandbox_runtime
import boundarybench.task_runtime.scorers as hardening_scorers
import boundarybench.task_runtime.solvers as solver_gates
from boundarybench.enforcement import FakeAgentSHBackend, get_enforcement_config
from boundarybench import tasks
from boundarybench.tasks import hardened_agents


def test_registry_exports_hardened_agents():
    assert registry.hardened_agents is hardened_agents


def test_package_metadata_exposes_harbor_extra():
    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text()
    )

    assert pyproject["project"]["optional-dependencies"]["harbor"] == [
        "inspect-harbor>=0.5.7; python_version >= '3.12'",
        "harbor==0.13.1; python_version >= '3.12'",
    ]


def test_hardened_agents_task_builds():
    task = hardened_agents(
        enforcement="local_fake",
        dataset="terminal-bench-2.1",
        task_id="log-summary-date-ranges",
        hardening_config="agentsh_sev1_fixture",
        preflight_only=False,
        max_samples=1,
    )

    assert task.dataset is not None
    assert len(task.dataset) == 1


@pytest.mark.parametrize(
    "enforcement",
    ["daytona_agentsh", "legacy_docker_hardened", "docker_hardened"],
)
def test_hardened_agents_rejects_unsupported_enforcement(enforcement):
    with pytest.raises(ValueError, match="local_fake, none, agentsh"):
        hardened_agents(enforcement=enforcement)


def test_hardened_agents_rejects_non_terminalbench_dataset():
    with pytest.raises(ValueError, match="terminal-bench-2.1"):
        hardened_agents(enforcement="none", dataset="terminal-bench-2.0")


def test_hardening_config_loader_adapter_uses_signature_without_typeerror_probe():
    calls = []

    def one_arg_loader(config_id: str):
        calls.append(config_id)
        raise TypeError("real loader failure")

    def two_arg_loader(config_id: str, task_id: str):
        return {"config_id": config_id, "task_id": task_id}

    with pytest.raises(TypeError, match="real loader failure"):
        hardening_loading._adapt_config_loader(one_arg_loader)(
            "agentsh_sev1_fixture", "task-1"
        )
    assert calls == ["agentsh_sev1_fixture"]

    assert hardening_loading._adapt_config_loader(two_arg_loader)(
        "agentsh_sev1_fixture", "task-1"
    ) == {"config_id": "agentsh_sev1_fixture", "task_id": "task-1"}


def test_hardened_agents_none_builds_with_control_metadata(monkeypatch):
    captured = {}

    def fake_build(config):
        captured["config"] = config
        return Task(
            dataset=MemoryDataset(
                [
                    Sample(
                        id="log-summary-date-ranges",
                        input="real terminal-bench task",
                        metadata={"task_name": "log-summary-date-ranges"},
                    )
                ]
            ),
            solver=_fake_harbor_solver(),
            scorer=_fake_harbor_scorer(),
        )

    monkeypatch.setattr(harbor_module, "_build_terminal_bench_2_1_task", fake_build)

    task = hardened_agents(
        enforcement="none",
        dataset="terminal-bench-2.1",
        task_id="log-summary-date-ranges",
        max_samples=1,
    )

    assert captured["config"].task_id == "log-summary-date-ranges"
    assert captured["config"].max_samples == 1
    assert task.metadata["enforcement"] == "none"
    assert task.metadata["custom_verifier"] is False
    assert task.metadata["boundarybench"]["enforcement"] == "none"
    sample = task.dataset[0]
    assert sample.id == "log-summary-date-ranges"
    assert sample.metadata["dataset_version"] == "terminal-bench-2.1"
    assert sample.metadata["terminal_bench_task_id"] == "log-summary-date-ranges"
    assert sample.metadata["real_terminal_bench_task"] is True


def test_terminalbench_control_scorer_preserves_official_verifier_result():
    async def fake_upstream_scorer(state, target):
        return Score(
            value=1.0,
            answer="PASS",
            explanation="Test exit code: 0\n\nstdout:\nreward ok\n\nstderr:\n",
            metadata={"reward_dict": {"reward": 1.0}},
        )

    config = harbor_module.TerminalBenchControlConfig(
        dataset="terminal-bench-2.1",
        task_id="log-summary-date-ranges",
        max_samples=1,
        ref=harbor_module.DEFAULT_TERMINAL_BENCH_2_1_REF,
        sandbox_env_name="docker",
        overwrite_cache=False,
        override_cpus=None,
        override_memory_mb=None,
        override_gpus=None,
    )
    score_fn = harbor_module.terminalbench_control_scorer(fake_upstream_scorer, config)
    state = SimpleNamespace(
        metadata={"terminal_bench_task_id": "log-summary-date-ranges"},
        sample_id="log-summary-date-ranges",
    )

    score = asyncio.run(score_fn(state, None))

    assert score.value == 1.0
    assert score.answer == "PASS"
    assert score.metadata["official_verifier_result"]["passed"] is True
    assert score.metadata["official_verifier_output"]["exit_code"] == 0
    assert score.metadata["official_verifier_output"]["stdout"] == "reward ok"
    assert score.metadata["fake_result_json_scoring"] is False


def test_terminalbench_adapter_threads_harbor_control_metadata(monkeypatch):
    captured = {}

    def build_package_slice(config, dataset_task_names):
        captured["config"] = config
        captured["dataset_task_names"] = dataset_task_names
        return _fake_harbor_task(
            samples=[
                Sample(
                    id="terminal-bench/log-summary-date-ranges",
                    input="real terminal-bench task",
                    metadata={"task_name": "terminal-bench/log-summary-date-ranges"},
                )
            ]
        )

    monkeypatch.setattr(
        harbor_module,
        "_build_terminal_bench_2_1_package_slice",
        build_package_slice,
    )
    config = harbor_module.TerminalBenchControlConfig(
        dataset="terminal-bench-2.1",
        task_id="log-summary-date-ranges",
        max_samples=1,
        ref="sha256:test-ref",
        sandbox_env_name="docker-custom",
        overwrite_cache=True,
        override_cpus=2,
        override_memory_mb=4096,
        override_gpus=1,
    )

    task = harbor_module._build_terminal_bench_2_1_task(config)

    assert captured["config"] is config
    assert captured["dataset_task_names"] == ["terminal-bench/log-summary-date-ranges"]
    assert task.dataset[0].id == "terminal-bench/log-summary-date-ranges"


def test_terminalbench_adapter_uses_public_task_for_unfiltered_runs(
    monkeypatch,
):
    captured = {}

    def terminal_bench_2_1(**kwargs):
        captured.update(kwargs)
        return _fake_harbor_task(
            samples=[
                Sample(
                    id="terminal-bench/first-task",
                    input="real terminal-bench task",
                    metadata={"task_name": "terminal-bench/first-task"},
                ),
            ]
        )

    monkeypatch.setitem(
        sys.modules,
        "inspect_harbor",
        SimpleNamespace(terminal_bench_2_1=terminal_bench_2_1),
    )
    config = harbor_module.TerminalBenchControlConfig(
        dataset="terminal-bench-2.1",
        task_id=None,
        max_samples=3,
        ref="sha256:test-ref",
        sandbox_env_name="docker",
        overwrite_cache=False,
        override_cpus=None,
        override_memory_mb=None,
        override_gpus=None,
    )

    task = harbor_module._build_terminal_bench_2_1_task(config)

    assert captured["dataset_task_names"] is None
    assert captured["n_tasks"] == 3
    assert captured["ref"] == "sha256:test-ref"
    assert len(task.dataset) == 1
    assert task.dataset[0].id == "terminal-bench/first-task"


def test_hardened_agents_local_fake_eval_smoke(tmp_path):
    logs = inspect_eval(
        hardened_agents(enforcement="local_fake", max_samples=1),
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
    )

    assert logs[0].status == "success"
    assert logs[0].results is not None
    assert logs[0].results.total_samples == 1
    assert logs[0].results.completed_samples == 1
    assert logs[0].samples is not None
    assert logs[0].samples[0].metadata["enforcement"] == "local_fake"
    assert logs[0].samples[0].metadata["local_fake"]["backend"] == "local_fake"
    assert logs[0].samples[0].scores["smoke_scorer"].answer == "success"


def test_hardened_agents_local_fake_delay_smoke(tmp_path):
    logs = inspect_eval(
        hardened_agents(
            enforcement="local_fake",
            max_samples=1,
            local_fake_delay_seconds=0.01,
        ),
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
    )

    assert logs[0].status == "success"
    assert logs[0].samples is not None
    local_fake = logs[0].samples[0].metadata["local_fake"]
    assert local_fake["backend"] == "local_fake"
    assert local_fake["delay_seconds"] == 0.01


def test_hardened_agents_local_fake_delay_rejects_negative():
    with pytest.raises(ValueError, match="local_fake_delay_seconds"):
        hardened_agents(enforcement="local_fake", local_fake_delay_seconds=-1)


def test_hardened_agents_local_fake_delay_rejects_non_local_fake():
    with pytest.raises(ValueError, match="local_fake_delay_seconds"):
        hardened_agents(enforcement="none", local_fake_delay_seconds=1)


def test_hardened_agents_none_fail_fast_when_harbor_missing(monkeypatch):
    def missing_harbor(**kwargs):
        raise RuntimeError("inspect-harbor is required for enforcement=none")

    monkeypatch.setattr(tasks, "build_terminalbench_control_task", missing_harbor)

    with pytest.raises(RuntimeError, match="inspect-harbor"):
        hardened_agents(enforcement="none", task_id="log-summary-date-ranges")


def test_hardened_agents_none_uses_harbor_control_task(monkeypatch):
    harbor_task = _fake_harbor_task()
    seen = {}

    def fake_build_task(**kwargs):
        seen.update(kwargs)
        return harbor_task

    monkeypatch.setattr(tasks, "build_terminalbench_control_task", fake_build_task)

    task = hardened_agents(
        enforcement="none",
        dataset="terminal-bench-2.1",
        task_id="log-summary-date-ranges",
        max_samples=1,
    )

    assert task.dataset is harbor_task.dataset
    assert task.solver is harbor_task.solver
    assert task.scorer is harbor_task.scorer
    assert task.metadata["boundarybench"]["enforcement"] == "none"
    assert seen == {
        "dataset": "terminal-bench-2.1",
        "task_id": "log-summary-date-ranges",
        "max_samples": 1,
        "ref": harbor_module.DEFAULT_TERMINAL_BENCH_2_1_REF,
        "sandbox_env_name": "docker",
        "overwrite_cache": False,
        "override_cpus": None,
        "override_memory_mb": None,
        "override_gpus": None,
    }


def test_connect_docker_bridge_rejects_unexpected_container_identifier(monkeypatch):
    async def unexpected_exec(*args, **kwargs):
        raise AssertionError("subprocess should not be invoked")

    monkeypatch.setattr(
        sandbox_runtime.asyncio, "create_subprocess_exec", unexpected_exec
    )

    with pytest.raises(ValueError, match="unsupported docker container identifier"):
        asyncio.run(
            sandbox_runtime._connect_docker_bridge(
                "container; rm -rf /",
                timeout=1,
            )
        )


def test_connect_docker_bridge_constructs_allowlisted_command(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(
        sandbox_runtime.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    result = asyncio.run(
        sandbox_runtime._connect_docker_bridge(
            "container-1_2.3",
            timeout=1,
        )
    )

    assert captured["args"] == (
        "docker",
        "network",
        "connect",
        "bridge",
        "container-1_2.3",
    )
    assert captured["kwargs"] == {
        "stdout": sandbox_runtime.asyncio.subprocess.PIPE,
        "stderr": sandbox_runtime.asyncio.subprocess.PIPE,
    }
    assert result["cmd"] == [
        "docker",
        "network",
        "connect",
        "bridge",
        "container-1_2.3",
    ]
    assert result["returncode"] == 0


def test_hardened_harbor_scorer_classifies_copy_blocks_without_custom_verifier(
    monkeypatch,
):
    class CopyTestsDirError(Exception):
        pass

    @scorer(metrics=[])
    def copy_blocked_scorer():
        async def score(state: TaskState, target):
            raise CopyTestsDirError("tee: /tests/test_outputs.py: Permission denied")

        return score

    monkeypatch.setattr(
        hardening_scorers, "_lift_hardening_for_verifier", _noop_verifier_lift
    )

    state = _started_hardening_state()
    wrapped = hardening_scorers.hardening_aware_harbor_scorer(
        copy_blocked_scorer()
    )
    score = asyncio.run(wrapped(state, None))

    assert score.answer == "failure"
    assert score.value == 0.0
    assert score.metadata["failure_type"] == "harbor_verifier_copy_blocked"
    assert score.metadata["official_verifier_result"] is None
    assert score.metadata["custom_verifier"] is False
    assert score.metadata["alternate_reward_computed"] is False
    assert score.metadata["upstream_error_type"] == "CopyTestsDirError"


def test_hardened_harbor_scorer_classifies_bootstrap_blocks_without_custom_verifier(
    monkeypatch,
):
    @scorer(metrics=[])
    def bootstrap_blocked_scorer():
        async def score(state: TaskState, target):
            return Score(
                value=0.0,
                answer="FAIL",
                explanation="uvx: command not found\nUnable to locate package curl",
            )

        return score

    monkeypatch.setattr(
        hardening_scorers, "_lift_hardening_for_verifier", _noop_verifier_lift
    )

    state = _started_hardening_state()
    wrapped = hardening_scorers.hardening_aware_harbor_scorer(
        bootstrap_blocked_scorer()
    )
    score = asyncio.run(wrapped(state, None))

    assert score.answer == "failure"
    assert score.value == 0.0
    assert score.metadata["failure_type"] == "harbor_verifier_bootstrap_blocked"
    assert score.metadata["official_verifier_result"] is None
    assert score.metadata["custom_verifier"] is False
    assert score.metadata["alternate_reward_computed"] is False
    assert score.metadata["upstream_harbor_score"]["answer"] == "FAIL"


def test_hardened_harbor_scorer_does_not_classify_mid_sentence_bootstrap_terms(
    monkeypatch,
):
    async def explanatory_failure_scorer(state: TaskState, target):
        return Score(
            value=0.0,
            answer="FAIL",
            explanation=(
                "The verifier explanation mentions setgroups as background "
                "context but did not emit a bootstrap stderr line."
            ),
        )

    monkeypatch.setattr(
        hardening_scorers, "_lift_hardening_for_verifier", _noop_verifier_lift
    )
    state = _task_state()
    state.metadata = {
        "hardening": {
            "enforcement": "agentsh",
            "config": {"config_id": "agentsh_sev1_fixture"},
            "preflight": {"status": "passed"},
            "preflight_only": False,
            "agent_started": True,
        }
    }

    wrapped = hardening_scorers.hardening_aware_harbor_scorer(
        explanatory_failure_scorer
    )
    score = asyncio.run(wrapped(state, None))

    assert score.value == 0.0
    assert score.answer == "FAIL"
    assert score.metadata["harbor_verifier_ran"] is True
    assert "failure_type" not in score.metadata


def test_hardened_harbor_scorer_records_partial_lift_and_continues(monkeypatch):
    class BrokenLiftSandbox:
        async def exec(self, cmd, *, input, user):
            raise ConnectionError("exec channel closed")

        async def connection(self, *, user):
            raise RuntimeError("connection unavailable")

    async def harbor_scorer(state: TaskState, target):
        return Score(value=1.0, answer="PASS", explanation="ok")

    monkeypatch.setattr(inspect_util, "sandbox", lambda: BrokenLiftSandbox())
    state = _task_state()
    state.metadata = {
        "hardening": {
            "enforcement": "agentsh",
            "config": {"config_id": "agentsh_sev1_fixture"},
            "preflight": {"status": "passed"},
            "preflight_only": False,
            "agent_started": True,
        }
    }

    wrapped = hardening_scorers.hardening_aware_harbor_scorer(harbor_scorer)
    score = asyncio.run(wrapped(state, None))

    lift = state.metadata["hardening"]["verifier_hardening_lift"]
    assert lift["status"] == "partial"
    assert [error["operation"] for error in lift["errors"]] == [
        "in_container_lift",
        "sandbox_connection",
    ]
    assert score.value == 1.0
    assert score.metadata["verifier_hardening_lift"]["status"] == "partial"


def test_hardened_harbor_scorer_has_no_direct_verifier_helpers():
    assert not hasattr(tasks, "_score_harbor_direct_test_functions")
    assert not hasattr(tasks, "_score_harbor_with_root_test_copy")


def test_hardened_agents_accepts_agentsh_mode(monkeypatch):
    monkeypatch.setattr(
        tasks, "build_terminalbench_control_task", lambda **kwargs: _fake_harbor_task()
    )

    task = hardened_agents(
        enforcement="agentsh",
        task_id="log-summary-date-ranges",
        hardening_config="agentsh_sev1_fixture",
        max_samples=1,
    )

    assert task.metadata["enforcement"] == "agentsh"
    assert task.metadata["boundarybench"]["enforcement"] == "agentsh"
    assert (
        task.metadata["boundarybench"]["agentsh_policy_hardening"]["backend"]
        == "agentsh"
    )


def test_hardened_agents_agentsh_preflight_only_records_fake_contract_evidence(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "fake")
    monkeypatch.delenv("BOUNDARYBENCH_AGENTSH_FAKE_FAILURE", raising=False)
    monkeypatch.setattr(
        tasks, "build_terminalbench_control_task", lambda **kwargs: _fake_harbor_task()
    )

    logs = inspect_eval(
        hardened_agents(
            enforcement="agentsh",
            task_id="log-summary-date-ranges",
            hardening_config="agentsh_sev1_fixture",
            preflight_only=True,
            max_samples=1,
        ),
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
    )

    sample = logs[0].samples[0]
    hardening = sample.metadata["hardening"]
    assert sample.output.completion == "agentsh_preflight_passed"
    assert sample.metadata["enforcement"] == "agentsh"
    assert hardening["enforcement"] == "agentsh"
    assert hardening["agent_started"] is False
    assert hardening["agentsh_backend"] == "fake"
    assert hardening["evidence_tier"] == "contract_test"
    assert hardening["benchmark_claim"] == "none"
    assert hardening["session"]["backend"] == "fake"
    assert hardening["session"]["metadata"]["test_only"] is True
    assert hardening["preflight"]["status"] == "pass"
    assert (
        hardening["preflight"]["policy_digest"] == hardening["policy"]["policy_digest"]
    )
    assert any(
        result["agentsh_policy_result"] == "fallback_passed"
        for result in hardening["preflight"]["results"]
    )
    score = sample.scores["hardening_preflight_scorer"]
    assert score.answer == "success"
    assert score.metadata["enforcement"] == "agentsh"
    assert score.metadata["score_source"] == "hardening_preflight_sentinel"
    assert score.metadata["harbor_verifier_ran"] is False
    assert score.metadata["terminal_bench_score_eligible"] is False


def test_hardened_agents_agentsh_fake_non_preflight_refuses_harbor(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "fake")
    monkeypatch.delenv("BOUNDARYBENCH_AGENTSH_FAKE_FAILURE", raising=False)
    monkeypatch.setattr(
        tasks, "build_terminalbench_control_task", lambda **kwargs: _fake_harbor_task()
    )

    logs = inspect_eval(
        hardened_agents(
            enforcement="agentsh",
            task_id="log-summary-date-ranges",
            hardening_config="agentsh_sev1_fixture",
            max_samples=1,
        ),
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
    )

    sample = logs[0].samples[0]
    assert sample.output.completion == "agentsh_preflight_failed"
    assert "harbor_result" not in sample.metadata
    assert sample.metadata["enforcement"] == "agentsh"
    hardening = sample.metadata["hardening"]
    assert hardening["agent_started"] is False
    assert hardening["benchmark_claim"] == "none"
    assert hardening["terminal_bench_score_eligible"] is False
    assert hardening["harbor_verifier_ran"] is False
    assert hardening["preflight"]["failure_type"] == (
        "agentsh_agent_wrapping_not_implemented"
    )
    score = sample.scores["_fake_harbor_scorer"]
    assert score.answer == "failure"
    assert score.metadata["enforcement"] == "agentsh"
    assert score.metadata["failure_type"] == "hardening_preflight"
    assert score.metadata["terminal_bench_score_eligible"] is False
    assert score.metadata["harbor_verifier_ran"] is False


def test_hardened_agents_agentsh_preflight_failure_skips_harbor(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "fake")
    monkeypatch.setenv(
        "BOUNDARYBENCH_AGENTSH_FAKE_FAILURE", "omit_supported_event"
    )
    monkeypatch.setattr(
        tasks, "build_terminalbench_control_task", lambda **kwargs: _fake_harbor_task()
    )

    logs = inspect_eval(
        hardened_agents(
            enforcement="agentsh",
            task_id="log-summary-date-ranges",
            hardening_config="agentsh_sev1_fixture",
            max_samples=1,
        ),
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
    )

    sample = logs[0].samples[0]
    assert sample.output.completion == "agentsh_preflight_failed"
    assert "harbor_result" not in sample.metadata
    assert sample.metadata["enforcement"] == "agentsh"
    assert sample.metadata["hardening"]["agent_started"] is False
    score = sample.scores["_fake_harbor_scorer"]
    assert score.answer == "failure"
    assert score.metadata["enforcement"] == "agentsh"
    assert score.metadata["failure_type"] == "hardening_preflight"
    assert score.metadata["harbor_verifier_ran"] is False
    assert score.metadata["terminal_bench_score_eligible"] is False


def test_hardened_agents_agentsh_real_backend_missing_binary_fails_closed(monkeypatch):
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "real")
    monkeypatch.delenv("AGENTSH_BIN", raising=False)
    state = _task_state()

    result = asyncio.run(
        tasks.agentsh_solver(
            upstream_solver=_fake_harbor_solver(),
            hardening_config="agentsh_sev1_fixture",
            task_id="log-summary-date-ranges",
            preflight_only=False,
        )(state, None)
    )

    assert result.completed is True
    assert result.output.completion == "agentsh_preflight_failed"
    assert result.metadata["hardening"]["agent_started"] is False
    assert result.metadata["hardening"]["preflight"]["failure_type"] == (
        "agentsh_setup_or_session_failure"
    )
    assert result.metadata["hardening"]["preflight"]["silent_fallback"] is False


def test_hardened_agents_agentsh_real_backend_version_probe_does_not_create_session(
    monkeypatch,
):
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "real")
    monkeypatch.setenv("AGENTSH_BIN", "/bin/echo")
    state = _task_state()

    result = asyncio.run(
        tasks.agentsh_solver(
            upstream_solver=_fake_harbor_solver(),
            hardening_config="agentsh_sev1_fixture",
            task_id="log-summary-date-ranges",
            preflight_only=False,
        )(state, None)
    )

    assert result.completed is True
    assert result.output.completion == "agentsh_preflight_failed"
    assert "agentsh_session" not in result.metadata
    assert "session" not in result.metadata["hardening"]
    preflight = result.metadata["hardening"]["preflight"]
    assert preflight["failure_type"] == "agentsh_setup_or_session_failure"
    assert "did not look like agentsh output" in preflight["error"]
    assert preflight["silent_fallback"] is False


def test_hardened_agents_agentsh_real_backend_blocks_unwrapped_upstream(monkeypatch):
    called = False

    class PassingRealNoWrapBackend(FakeAgentSHBackend):
        backend_kind = "real"
        evidence_tier = "real_agentsh"
        agentsh_version = "real-test"
        wraps_upstream_solver = False

    @solver
    def upstream():
        async def solve(state: TaskState, generate):
            nonlocal called
            called = True
            state.output = ModelOutput(
                model=str(state.model), completion="upstream-called"
            )
            state.completed = True
            return state

        return solve

    monkeypatch.setattr(
        solver_gates,
        "_load_agentsh_runtime",
        lambda: SimpleNamespace(
            load_config=lambda config_id, task_id: get_enforcement_config(config_id),
            backend=PassingRealNoWrapBackend(),
        ),
    )
    state = _task_state()

    result = asyncio.run(
        tasks.agentsh_solver(
            upstream_solver=upstream(),
            hardening_config="agentsh_sev1_fixture",
            task_id="log-summary-date-ranges",
            preflight_only=False,
        )(state, None)
    )

    assert called is False
    assert result.completed is True
    assert result.output.completion == "agentsh_preflight_failed"
    assert result.metadata["hardening"]["agent_started"] is False
    assert result.metadata["hardening"]["benchmark_claim"] == "none"
    assert result.metadata["hardening"]["preflight"]["failure_type"] == (
        "agentsh_agent_wrapping_not_implemented"
    )


@pytest.mark.parametrize(
    ("evidence_tier", "expected_claim", "expected_eligible"),
    [
        ("real_agentsh", "official_terminal_bench_candidate", True),
        ("real_policy_yaml", "none", False),
    ],
)
def test_hardened_agents_agentsh_benchmark_claim_is_real_agentsh_allowlist(
    monkeypatch,
    evidence_tier,
    expected_claim,
    expected_eligible,
):
    called = False

    class PassingWrappedBackend(FakeAgentSHBackend):
        backend_kind = "real"
        agentsh_version = "real-test"
        wraps_upstream_solver = True

    PassingWrappedBackend.evidence_tier = evidence_tier

    @solver
    def upstream():
        async def solve(state: TaskState, generate):
            nonlocal called
            called = True
            state.output = ModelOutput(
                model=str(state.model), completion="upstream-called"
            )
            state.completed = True
            return state

        return solve

    monkeypatch.setattr(
        solver_gates,
        "_load_agentsh_runtime",
        lambda: SimpleNamespace(
            load_config=lambda config_id, task_id: get_enforcement_config(config_id),
            backend=PassingWrappedBackend(),
        ),
    )
    state = _task_state()

    result = asyncio.run(
        tasks.agentsh_solver(
            upstream_solver=upstream(),
            hardening_config="agentsh_sev1_fixture",
            task_id="log-summary-date-ranges",
            preflight_only=False,
        )(state, None)
    )

    assert called is True
    assert result.output.completion == "upstream-called"
    assert result.metadata["hardening"]["benchmark_claim"] == expected_claim
    assert result.metadata["benchmark_claim"] == expected_claim
    assert (
        result.metadata["hardening"]["terminal_bench_score_eligible"]
        is expected_eligible
    )
    assert result.metadata["terminal_bench_score_eligible"] is expected_eligible


def _fake_harbor_task(samples: list[Sample] | None = None) -> Task:
    return _fake_harbor_task_with_scorer(_fake_harbor_scorer(), samples=samples)


def _fake_harbor_task_with_scorer(
    scorer,
    *,
    samples: list[Sample] | None = None,
) -> Task:
    return Task(
        dataset=MemoryDataset(
            samples
            or [
                Sample(
                    id="log-summary-date-ranges",
                    input="Harbor Terminal-Bench sample",
                    target="harbor-ok",
                    metadata={
                        "enforcement": "none",
                        "severity": "sev0",
                        "control_mode": True,
                        "hardened_execution": False,
                        "harbor_package_ref": "sha256:fake-ref",
                        "harbor": {
                            "dataset": "terminal-bench-2.1",
                            "task_id": "log-summary-date-ranges",
                        },
                    },
                )
            ]
        ),
        solver=_fake_harbor_solver(),
        scorer=scorer,
        sandbox=None,
        metadata={
            "enforcement": "none",
            "severity": "sev0",
            "control_mode": True,
            "hardened_execution": False,
            "harbor_package_ref": "sha256:fake-ref",
            "harbor": {"dataset": "terminal-bench-2.1"},
        },
    )


@solver
def _fake_harbor_solver():
    async def solve(state: TaskState, generate):
        state.metadata["harbor_result"] = {
            "dataset": "terminal-bench-2.1",
            "task_id": "log-summary-date-ranges",
        }
        state.output = ModelOutput(model=str(state.model), completion="harbor-ok")
        state.completed = True
        return state

    return solve


@scorer(metrics=[])
def _fake_harbor_scorer():
    async def score(state: TaskState, target):
        return Score(
            value=1.0,
            answer="success",
            explanation="fake Harbor scorer",
            metadata={
                "enforcement": "none",
                "control_mode": True,
                "hardened_execution": False,
                "official_verifier_result": {
                    "answer": "PASS",
                    "reward": 1.0,
                    "passed": True,
                },
                "harbor_result": state.metadata.get("harbor_result"),
            },
        )

    return score


async def _noop_verifier_lift(state: TaskState):
    return {}


def _started_hardening_state() -> TaskState:
    state = _task_state()
    state.metadata = {
        "hardening": {
            "enforcement": "agentsh",
            "config": {"config_id": "agentsh_sev1_fixture"},
            "preflight": {"status": "passed"},
            "preflight_only": False,
            "agent_started": True,
        }
    }
    return state


def _task_state() -> TaskState:
    return TaskState(
        model="mockllm/model",
        sample_id="log-summary-date-ranges",
        epoch=1,
        input="Harbor Terminal-Bench sample",
        messages=[],
        metadata={},
    )
