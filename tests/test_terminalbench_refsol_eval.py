from __future__ import annotations

import asyncio
import hashlib
import math
import re
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspect_ai.solver import TaskState

import boundarybench.terminalbench.refsol_eval as refsol_eval
from boundarybench.terminalbench.daytona import TerminalBenchTaskBundle
from boundarybench.terminalbench.daytona_constants import (
    SANDBOX_MANAGED_BY_LABEL,
    SANDBOX_MANAGED_BY_VALUE,
    SANDBOX_RUN_ID_LABEL,
)
from boundarybench.terminalbench.refsol_eval import (
    REMOTE_SOLUTION_PATH,
    RefsolRunResult,
    refsol_daytona_scorer,
    refsol_terminalbench_daytona,
    run_one_refsol_task,
)
from boundarybench.terminalbench.daytona_preflight import PreflightFailedError
from boundarybench.terminalbench.daytona_runtime_layer import (
    render_sandbox_base_script,
)
from boundarybench.daytona.runtime_policy_probes import (
    RUNTIME_POLICY_PROBE_WORKSPACE,
)
from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    run_with_daytona_policy_hardening,
)


TASK_TOML = """
[agent]
timeout_sec = 123.0

[verifier]
timeout_sec = 120.0

[environment]
docker_image = "example/refsol-image:1"
cpus = 1
memory_mb = 2048
storage_mb = 10240
gpus = 0

[solution.env]
FOO = "bar"
"""


class _FakeResult:
    def __init__(self, exit_code: int, result: str) -> None:
        self.exit_code = exit_code
        self.result = result


class _FakeProcess:
    """Fake Daytona process API recording a global op log.

    The op log lets tests assert ordering and session lifecycle — most
    importantly that the solution's session is never deleted (the pypi-server
    daemon-reap regression lock) and that the solution never runs through a
    plain blocking exec (unreliable for long commands).
    """

    def __init__(
        self,
        ops: list[tuple[str, str]],
        *,
        solution_exit_code: int = 0,
        solution_stdout: str = "solution output",
        reward_txt: str = "1.0\n",
    ):
        self.ops = ops
        self.solution_exit_code = solution_exit_code
        self.solution_stdout = solution_stdout
        self.reward_txt = reward_txt
        self.commands: list[str] = []
        self.envs: list[dict[str, str] | None] = []
        self.session_commands: dict[str, str] = {}

    def exec(self, command: str, *, timeout: int, env=None):
        self.ops.append(("exec", command))
        self.commands.append(command)
        self.envs.append(env)
        if "reward.txt" in command:
            return _FakeResult(0, self.reward_txt)
        return _FakeResult(0, "ok")

    def create_session(self, session_id: str) -> None:
        self.ops.append(("create_session", session_id))

    def execute_session_command(self, session_id: str, request, *, timeout: int):
        self.ops.append(("execute_session_command", request.command))
        self.session_commands[session_id] = request.command
        return SimpleNamespace(cmd_id="cmd-1")

    def get_session_command(self, session_id: str, cmd_id: str):
        if session_id.startswith("ia-refsol-"):
            return SimpleNamespace(exit_code=self.solution_exit_code)
        return SimpleNamespace(exit_code=0)

    def get_session_command_logs(self, session_id: str, cmd_id: str):
        if session_id.startswith("ia-refsol-"):
            return SimpleNamespace(stdout=self.solution_stdout)
        return SimpleNamespace(stdout="verifier ok")

    def delete_session(self, session_id: str) -> None:
        self.ops.append(("delete_session", session_id))


class _FakeFs:
    def __init__(self) -> None:
        self.uploads: list[tuple[str, str]] = []

    def upload_file(self, local_path: str, remote_path: str) -> None:
        self.uploads.append((local_path, remote_path))


class _FakeSandbox:
    def __init__(
        self,
        ops: list[tuple[str, str]],
        *,
        solution_exit_code: int = 0,
        solution_stdout: str = "solution output",
        reward_txt: str = "1.0\n",
    ):
        self.id = "sandbox-123"
        self.labels: dict[str, str] = {}
        self.process = _FakeProcess(
            ops,
            solution_exit_code=solution_exit_code,
            solution_stdout=solution_stdout,
            reward_txt=reward_txt,
        )
        self.fs = _FakeFs()


class _FakeDaytona:
    def __init__(
        self,
        *,
        solution_exit_code: int = 0,
        solution_stdout: str = "solution output",
        reward_txt: str = "1.0\n",
        listed_after_delete: list[object] | None = None,
        create_errors: list[Exception] | None = None,
        undeletable_ids: set[str] | None = None,
    ) -> None:
        self.ops: list[tuple[str, str]] = []
        self.solution_exit_code = solution_exit_code
        self.solution_stdout = solution_stdout
        self.reward_txt = reward_txt
        self.listed_after_delete = listed_after_delete or []
        self.create_errors = list(create_errors or [])
        self.undeletable_ids = undeletable_ids or set()
        self.created_params: list[object] = []
        self.deleted: list[object] = []
        self.deleted_ids: set[str] = set()
        self.sandboxes: list[_FakeSandbox] = []

    def create(self, params, *, timeout: int):
        if self.create_errors:
            raise self.create_errors.pop(0)
        self.created_params.append(params)
        sandbox = _FakeSandbox(
            self.ops,
            solution_exit_code=self.solution_exit_code,
            solution_stdout=self.solution_stdout,
            reward_txt=self.reward_txt,
        )
        sandbox.labels = dict(getattr(params, "labels", None) or {})
        self.sandboxes.append(sandbox)
        return sandbox

    def delete(self, sandbox) -> None:
        sandbox_id = str(getattr(sandbox, "id", ""))
        if sandbox_id in self.undeletable_ids:
            raise RuntimeError(f"cannot delete {sandbox_id}")
        self.deleted.append(sandbox)
        self.deleted_ids.add(sandbox_id)

    def list(self):
        return [
            s
            for s in self.listed_after_delete
            if str(getattr(s, "id", "")) not in self.deleted_ids
        ]


def _write_task_dir(tmp_path: Path) -> Path:
    (tmp_path / "task.toml").write_text(TASK_TOML)
    solution_dir = tmp_path / "solution"
    solution_dir.mkdir()
    (solution_dir / "solve.sh").write_text("#!/bin/bash\necho solved\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test.sh").write_text("echo verifying\n")
    return tmp_path


def _bundle(tmp_path: Path) -> TerminalBenchTaskBundle:
    task_dir = _write_task_dir(tmp_path)
    tests_dir = task_dir / "tests"
    return TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="example",
        task_name="terminal-bench/example",
        task_dir=task_dir,
        tests_dir=tests_dir,
        test_path=tests_dir / "test.sh",
        verifier_timeout_sec=120,
        verifier_user="root",
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )


def _run(
    tmp_path: Path,
    monkeypatch,
    *,
    daytona: _FakeDaytona | None = None,
    run_id: str | None = "refsol-run-1",
    solution_timeout_sec: int | None = None,
    policy: str = "none",
    task_id: str = "example",
    solution_variant: str | None = None,
) -> tuple[RefsolRunResult, _FakeDaytona]:
    fake = daytona or _FakeDaytona()
    bundle = _bundle(tmp_path)
    monkeypatch.setattr(
        refsol_eval,
        "load_terminalbench_daytona_bundle",
        lambda *, task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr("daytona_sdk.Daytona", lambda: fake)
    monkeypatch.setattr(refsol_eval, "LEFTOVER_CHECK_ATTEMPTS", 2)
    monkeypatch.setattr(refsol_eval, "LEFTOVER_CHECK_SLEEP_SEC", 0)
    if run_id is None:
        monkeypatch.delenv("BOUNDARYBENCH_RUN_ID", raising=False)
    else:
        monkeypatch.setenv("BOUNDARYBENCH_RUN_ID", run_id)
    kwargs = {
        "ref": "sha256:test-ref",
        "solution_timeout_sec": solution_timeout_sec,
        "policy": policy,
    }
    if solution_variant is not None:
        kwargs["solution_variant"] = solution_variant
    result = run_one_refsol_task(task_id, **kwargs)
    return result, fake


def test_harness_free_base_script_contains_no_agent_runtime():
    script = render_sandbox_base_script(
        workdir="/app",
        run_agent_as_root=False,
    )

    assert "SANDBOX_BASE_OK" in script
    assert "ensure_daytona_user" in script
    assert "claude" not in script.lower()
    assert "codex" not in script.lower()
    assert "openrouter" not in script.lower()


def test_policy_runner_can_preserve_refsol_session_until_sandbox_cleanup():
    pytest.importorskip("daytona_sdk")
    ops: list[tuple[str, str]] = []
    sandbox = _FakeSandbox(ops)
    hardening = DaytonaPolicyHardening(
        asset_dir="/tmp/h",
        policy_message_preload_so="/tmp/h/policy.so",
        block_message_command="/tmp/h/deny.sh",
        mount_real_path="/tmp/h/mount.real",
        policy_bin_dir="/tmp/h/bin",
        child_network_block_env="/tmp/h/child-net",
    )

    result = run_with_daytona_policy_hardening(
        sandbox,
        daytona_policy_hardening=hardening,
        command="bash /solution/solve.sh",
        cwd="/app",
        timeout=30,
        isolate_network=False,
        block_network=False,
        preserve_session=True,
        session_id_prefix="ia-refsol-",
    )

    refsol_sessions = [
        payload
        for op, payload in ops
        if op == "create_session" and payload.startswith("ia-refsol-")
    ]
    assert refsol_sessions
    assert ("delete_session", refsol_sessions[0]) not in ops
    assert result.exit_code == 0
    assert result.session_id == refsol_sessions[0]


def test_hardened_solution_identity_is_controller_marker_before_solve():
    command = refsol_eval._hardened_solution_command(
        123,
        {"FOO": "bar"},
        "/app",
    )

    marker = refsol_eval.REFSOL_IDENTITY_MARKER
    assert command.index(marker) < command.index(REMOTE_SOLUTION_PATH)
    assert "$(id -u)" in command
    assert "$(id -un)" in command
    assert "$(pwd -P)" in command
    assert "/tmp/boundarybench-refsol-identity" not in command


@pytest.mark.parametrize(
    "policy",
    ["non-root", "low-nist", "moderate-nist", "high-nist", "high-nist"],
)
def test_task_accepts_native_policy_and_records_task_aware_metadata(policy):
    task = refsol_terminalbench_daytona(
        task_ids="log-summary-date-ranges", policy=policy
    )

    sample = list(task.dataset)[0]
    assert sample.metadata["policy"] == policy
    assert sample.metadata["hardened_execution"] is True
    assert sample.metadata["execution_mode"] == "reference_solution"
    assert sample.metadata["hardening_config"]["enforcement_mode"] == "native"
    if policy == "high-nist":
        allowlist = sample.metadata["hardening_config"]["egress_domain_allowlist"]
        assert len(allowlist) == 205
        assert "deb.debian.org" not in allowlist
    elif policy != "non-root":
        assert "deb.debian.org" in sample.metadata["hardening_config"][
            "egress_domain_allowlist"
        ]


_HARDENED_WITNESS_SCENARIOS = [
    pytest.param({"variant": None, "task_id": "example"}, id="canonical"),
    pytest.param(
        {
            "variant": "solvability-witnesses",
            "task_id": "sqlite-with-gcov",
            "dir_attr": "_ROOTLESS_WITNESSES_DIR",
            "asset_prefix": "refsol_rootless_witnesses",
            "fidelity": "committed_rootless_witness",
            "override_reason": "rootless_witness_variant",
        },
        id="rootless-witness",
    ),
    pytest.param(
        {
            "variant": "static-egress-witnesses",
            "task_id": "build-pmars",
            "dir_attr": "_NETWORK_WITNESSES_DIR",
            "asset_prefix": "refsol_network_witnesses",
            "fidelity": "committed_static_egress_witness",
            "override_reason": "static_egress_witness_variant",
        },
        id="static-egress-witness",
    ),
]


@pytest.mark.parametrize("scenario", _HARDENED_WITNESS_SCENARIOS)
def test_hardened_refsol_uses_base_policy_probes_persistent_session_and_root_verifier(
    tmp_path, monkeypatch, scenario
):
    execution_order = []
    base_calls = []
    install_calls = []
    preflight_calls = []
    probe_calls = []
    hardened_calls = []
    verifier_calls = []
    telemetry_events = [
        {"event_type": "policy_block", "surface": "domain_egress_policy"}
    ]

    class _Metadata:
        def __init__(self, value):
            self.value = value

        def to_compact_metadata(self):
            return self.value

        def to_metadata(self):
            return self.value

    def fake_base(*, workdir, run_agent_as_root):
        base_calls.append((workdir, run_agent_as_root))
        return "BASE_ONLY"

    hardening = SimpleNamespace(
        hardening_config=SimpleNamespace(
            to_metadata=lambda: {"enforcement_mode": "native"}
        )
    )

    def fake_install(sandbox, asset_dir, **kwargs):
        install_calls.append((sandbox, asset_dir, kwargs))
        return hardening

    def fake_preflight(sandbox, *, policy, daytona_policy_hardening):
        preflight_calls.append((sandbox, policy.name, daytona_policy_hardening))
        return _Metadata({"passed": True})

    def fake_probes(sandbox, **kwargs):
        execution_order.append("probes")
        probe_calls.append((sandbox, kwargs))
        return _Metadata({"passed": True, "required_failed_count": 0, "results": []})

    def fake_cleanup(sandbox, *, daytona_policy_hardening, enforcement_mode):
        execution_order.append("cleanup")
        assert daytona_policy_hardening is hardening
        assert enforcement_mode == "native"

    def fake_hardened(sandbox, **kwargs):
        execution_order.append("solution")
        hardened_calls.append((sandbox, kwargs))
        return SimpleNamespace(
            exit_code=0,
            stdout=(
                "__BOUNDARYBENCH_REFSOL_IDENTITY__ "
                "effective_uid=1000 effective_user=daytona pwd=/app/nested\n"
                "solution output"
            ),
            stderr="",
            timed_out=False,
            session_id="ia-refsol-observed",
        )

    def fake_verifier(sandbox, bundle, **kwargs):
        verifier_calls.append((sandbox, bundle, kwargs))
        return refsol_eval.DaytonaVerifierResult(
            value=1.0,
            answer="PASS",
            exit_code=0,
            stdout="ok",
            stderr="",
            verifier_identity={"effective_uid": 0, "effective_user": "root"},
            session_id="ia-verifier-observed",
        )

    monkeypatch.setattr(refsol_eval, "render_sandbox_base_script", fake_base)
    monkeypatch.setattr(refsol_eval, "install_daytona_policy_hardening", fake_install)
    monkeypatch.setattr(refsol_eval, "run_preflight", fake_preflight)
    monkeypatch.setattr(
        refsol_eval, "run_runtime_policy_probe_suite_in_sandbox", fake_probes
    )
    monkeypatch.setattr(
        refsol_eval, "ensure_runtime_policy_probe_suite_passed", lambda report: None
    )
    monkeypatch.setattr(
        refsol_eval,
        "remove_pre_agent_setup_artifacts",
        fake_cleanup,
    )
    monkeypatch.setattr(refsol_eval, "clear_policy_event_log", lambda sandbox: None)
    monkeypatch.setattr(refsol_eval, "run_with_daytona_policy_hardening", fake_hardened)
    monkeypatch.setattr(
        refsol_eval,
        "harvest_passive_telemetry",
        lambda sandbox, *, agent_stdout, hardening_config: telemetry_events,
    )
    monkeypatch.setattr(refsol_eval, "run_daytona_harbor_verifier", fake_verifier)
    dockerfile_dir = tmp_path / "environment"
    dockerfile_dir.mkdir()
    (dockerfile_dir / "Dockerfile").write_text(
        "FROM python:3.13-slim\nWORKDIR /app\nWORKDIR /app/nested\n"
    )
    solution_variant = scenario["variant"]
    config = scenario if solution_variant is not None else None
    task_id = scenario["task_id"]
    witness_body = b"#!/bin/sh\necho committed witness\n"
    if config is not None:
        witness_dir = tmp_path / "witnesses" / task_id
        witness_dir.mkdir(parents=True)
        (witness_dir / "solve.sh").write_bytes(witness_body)
        monkeypatch.setattr(
            refsol_eval,
            config["dir_attr"],
            tmp_path / "witnesses",
        )
    result, fake = _run(
        tmp_path,
        monkeypatch,
        policy="low-nist",
        task_id=task_id,
        solution_variant=solution_variant,
    )

    assert base_calls == [("/app", False)]
    assert install_calls[0][0] is fake.sandboxes[0]
    assert preflight_calls[0][1] == "low-nist"
    assert probe_calls[0][1]["policy_id"] == "low-nist"
    assert probe_calls[0][1]["workspace"] == RUNTIME_POLICY_PROBE_WORKSPACE
    assert execution_order == ["probes", "cleanup", "solution"]
    hardened_kwargs = hardened_calls[0][1]
    assert hardened_kwargs["cwd"] == "/app/nested"
    assert hardened_kwargs["workspace"] == "/app"
    assert hardened_kwargs["preserve_session"] is True
    assert hardened_kwargs["session_id_prefix"] == "ia-refsol-"
    assert "id -u" in hardened_kwargs["command"]
    assert "id -un" in hardened_kwargs["command"]
    assert verifier_calls[0][0] is fake.sandboxes[0]
    assert verifier_calls[0][2]["remote_workdir"] == "/app/nested"
    assert "include_daytona_user_site" not in verifier_calls[0][2]
    assert result.policy == "low-nist"
    assert result.hardened_execution is True
    assert result.preflight == {"passed": True, "policy": "low-nist"}
    assert result.runtime_policy_probe_report["passed"] is True
    assert result.policy_events == telemetry_events
    assert result.solution_identity == {
        "effective_uid": 1000,
        "effective_user": "daytona",
        "observed_workdir": "/app/nested",
        "policy": "low-nist",
    }
    if config is None:
        assert result.solution_fidelity == "canonical_shipped"
        assert result.solution_override == {
            "applied": False,
            "reason": "canonical_shipped",
        }
        assert result.solution_variant is None
        assert result.solution_source == {}
        assert "solution_variant" not in result.to_metadata()
        assert "solution_source" not in result.to_metadata()
        assert not any(
            remote == REMOTE_SOLUTION_PATH
            for _, remote in fake.sandboxes[0].fs.uploads
        )
    else:
        assert result.solution_fidelity == config["fidelity"]
        assert result.solution_variant == solution_variant
        assert result.solution_override == {
            "applied": False,
            "reason": config["override_reason"],
        }
        assert result.solution_source == {
            "name": solution_variant,
            "task_id": task_id,
            "asset_path": f"{config['asset_prefix']}/{task_id}/solve.sh",
            "sha256": hashlib.sha256(witness_body).hexdigest(),
        }
        assert result.to_metadata()["solution_variant"] == solution_variant
        assert result.to_metadata()["solution_source"] == result.solution_source
        uploads = fake.sandboxes[0].fs.uploads
        canonical_index = next(
            index
            for index, (_, remote) in enumerate(uploads)
            if remote == "/tmp/boundarybench-refsol-solution.tar.gz"
        )
        witness_index = next(
            index
            for index, (_, remote) in enumerate(uploads)
            if remote == REMOTE_SOLUTION_PATH
        )
        assert canonical_index < witness_index
    assert result.pip_time_shim == {
        "enabled": False,
        "reason": (
            config["fidelity"] if config is not None else "canonical_shipped"
        ),
    }
    assert result.hardening_config["policy"] == "low-nist"
    assert result.verification_lifecycle == {
        "solution_sandbox_id": "sandbox-123",
        "verifier_sandbox_id": "sandbox-123",
        "solution_session_id": "ia-refsol-observed",
        "verifier_session_id": "ia-verifier-observed",
        "phase_order": ["solution", "verifier"],
        "solution_completed_before_verifier": True,
        "verifier_fresh_session": True,
        "same_sandbox": True,
        "verifier_identity": {"effective_uid": 0, "effective_user": "root"},
    }


@pytest.mark.parametrize(
    "policy",
    ["non-root", "low-nist", "moderate-nist", "high-nist", "high-nist"],
)
def test_requested_refsol_policies_require_observed_non_root_identity(policy):
    with pytest.raises(RuntimeError, match="solution identity is not non-root"):
        refsol_eval._validate_solution_identity(
            policy=policy,
            expected_user="daytona",
            expected_workdir="/app",
            identity={
                "effective_uid": 0,
                "effective_user": "root",
                "observed_workdir": "/app",
                "policy": policy,
            },
        )

    refsol_eval._validate_solution_identity(
        policy=policy,
        expected_user="daytona",
        identity={
            "effective_uid": 1000,
            "effective_user": "daytona",
            "observed_workdir": "/app",
            "policy": policy,
        },
        expected_workdir="/app",
    )


def test_intentional_policy_egress_block_is_a_verifier_fail_not_transient_retry(
    tmp_path, monkeypatch
):
    attempts = []
    events = [{"event_type": "policy_block", "surface": "domain_egress_policy"}]

    def runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        attempts.append(policy)
        return RefsolRunResult(
            task_id=task_id,
            harbor_ref=ref,
            image="example/image:1",
            solution_path="/solution/solve.sh",
            solution_exit_code=1,
            solution_timed_out=False,
            solution_stdout_tail="connection refused",
            verifier=refsol_eval.DaytonaVerifierResult(
                value=0.0,
                answer="FAIL",
                exit_code=1,
                stdout="failed",
                stderr="",
            ),
            sandbox_id="sandbox-1",
            run_id="run-1",
            policy=policy,
            hardened_execution=True,
            policy_events=events,
        )

    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref",
        policy="low-nist",
        runner=runner,
        max_attempts=3,
    )
    state = _state({"terminal_bench_task_id": "example"})

    result_state = asyncio.run(solver_fn(state, None))

    assert attempts == ["low-nist"]
    metadata = result_state.metadata["terminalbench_refsol"]
    assert metadata["answer"] == "FAIL"
    assert metadata["attempt"] == 1
    assert not hasattr(refsol_eval, "_should_retry_egress_failure")


def test_network_gated_egress_failure_without_policy_evidence_is_invalid():
    disposition = refsol_eval._egress_failure_disposition(
        verifier_reward=0.0,
        solution_stdout="curl: (7) failed to connect",
        policy_events=[],
        network_gated=True,
    )

    assert disposition == "invalid"


def test_network_gated_egress_failure_with_inferred_evidence_is_measurement():
    disposition = refsol_eval._egress_failure_disposition(
        verifier_reward=0.0,
        solution_stdout="curl: (7) failed to connect",
        policy_events=[
            {
                "event_type": "policy_block_inferred",
                "axis": "network",
                "surface": "domain_egress_policy",
            }
        ],
        network_gated=True,
    )

    assert disposition == "measurement"


def test_ungated_egress_failure_preserves_legacy_transient_retry():
    disposition = refsol_eval._egress_failure_disposition(
        verifier_reward=0.0,
        solution_stdout="curl: (7) failed to connect",
        policy_events=[],
        network_gated=False,
    )

    assert disposition == "retry"


def test_solution_session_is_never_deleted_and_never_uses_plain_exec(
    tmp_path, monkeypatch
):
    result, fake = _run(tmp_path, monkeypatch)

    process = fake.sandboxes[0].process
    refsol_sessions = [
        session_id
        for session_id in process.session_commands
        if session_id.startswith("ia-refsol-")
    ]
    assert refsol_sessions, "solution was never executed via a session"
    solution_session = refsol_sessions[0]
    assert REMOTE_SOLUTION_PATH in process.session_commands[solution_session]
    deleted_sessions = [payload for op, payload in fake.ops if op == "delete_session"]
    assert solution_session not in deleted_sessions
    assert not any(
        REMOTE_SOLUTION_PATH in command and "timeout -k" in command
        for command in process.commands
    )
    solution_exec_index = next(
        index
        for index, (op, payload) in enumerate(fake.ops)
        if op == "execute_session_command" and REMOTE_SOLUTION_PATH in payload
    )
    verifier_session_creates = [
        index
        for index, (op, payload) in enumerate(fake.ops)
        if op == "create_session" and payload.startswith("ia-verifier-")
    ]
    assert verifier_session_creates
    assert min(verifier_session_creates) > solution_exec_index
    assert result.reward == 1.0
    assert result.answer == "PASS"
    assert result.solution_exit_code == 0
    assert result.solution_timed_out is False
    verifier_session = next(
        session_id
        for session_id in process.session_commands
        if session_id.startswith("ia-verifier-")
    )
    assert result.verification_lifecycle["solution_session_id"] == solution_session
    assert result.verification_lifecycle["verifier_session_id"] == verifier_session
    assert solution_session != verifier_session


def test_solution_command_shape_timeout_and_env(tmp_path, monkeypatch):
    result, fake = _run(tmp_path, monkeypatch)

    process = fake.sandboxes[0].process
    solution_session = next(
        session_id
        for session_id in process.session_commands
        if session_id.startswith("ia-refsol-")
    )
    command = process.session_commands[solution_session]
    assert command == (
        f"export FOO=bar; cd /app && timeout -k 10 123s bash -l "
        f"{REMOTE_SOLUTION_PATH} < /dev/null 2>&1"
    )
    assert result.solution_path.endswith("solution/solve.sh")
    assert result.solution_stdout_tail == "solution output"


def test_whole_solution_directory_is_uploaded(tmp_path, monkeypatch):
    _, fake = _run(tmp_path, monkeypatch)

    uploads = fake.sandboxes[0].fs.uploads
    assert any(
        remote == "/tmp/boundarybench-refsol-solution.tar.gz"
        for _, remote in uploads
    )
    extract_commands = [
        c
        for c in fake.sandboxes[0].process.commands
        if "tar -xzf" in c and "/solution" in c
    ]
    assert extract_commands, "solution tarball was never extracted to /solution"


def test_workdir_comes_from_environment_dockerfile(tmp_path, monkeypatch):
    dockerfile_dir = tmp_path / "environment"
    dockerfile_dir.mkdir()
    (dockerfile_dir / "Dockerfile").write_text(
        "FROM python:3.13-slim\nWORKDIR /app\nWORKDIR /workspace\n"
    )
    _, fake = _run(tmp_path, monkeypatch)

    process = fake.sandboxes[0].process
    solution_command = next(
        command
        for command in process.session_commands.values()
        if REMOTE_SOLUTION_PATH in command
    )
    assert "cd /workspace && " in solution_command
    verifier_command = next(
        command for command in process.session_commands.values() if "/tests/" in command
    )
    assert "cd /workspace && " in verifier_command


def test_explicit_solution_timeout_overrides_task_toml(tmp_path, monkeypatch):
    _, fake = _run(tmp_path, monkeypatch, solution_timeout_sec=45)

    process = fake.sandboxes[0].process
    assert any(
        "timeout -k 10 45s" in command for command in process.session_commands.values()
    )


def test_sandbox_labels_include_run_id(tmp_path, monkeypatch):
    _, fake = _run(tmp_path, monkeypatch, run_id="refsol-run-1")

    params = fake.created_params[0]
    labels = dict(getattr(params, "labels", None) or {})
    assert labels[SANDBOX_RUN_ID_LABEL] == "refsol-run-1"
    assert labels[SANDBOX_MANAGED_BY_LABEL] == (
        f"{SANDBOX_MANAGED_BY_VALUE}-refsol-run-1"
    )


def test_refsol_sandbox_auto_stop_tracks_task_timeout(tmp_path, monkeypatch):
    long_task_toml = TASK_TOML.replace("timeout_sec = 123.0", "timeout_sec = 7200.0")
    _, fake = _run_with_task_toml(
        tmp_path,
        monkeypatch,
        long_task_toml,
        shim_output="ok",
    )

    assert fake.created_params[0].auto_stop_interval == 150


def test_cleanup_is_run_scoped_and_ignores_foreign_sandboxes(tmp_path, monkeypatch):
    foreign = SimpleNamespace(
        id="foreign-1",
        labels={SANDBOX_RUN_ID_LABEL: "other-run"},
        state="STARTED",
    )
    reap_calls = {}

    def fake_reap(daytona, *, run_id, include_running):
        reap_calls["run_id"] = run_id
        reap_calls["include_running"] = include_running
        return (0, 0)

    monkeypatch.setattr(refsol_eval, "reap_stale_terminalbench_sandboxes", fake_reap)
    result, fake = _run(
        tmp_path,
        monkeypatch,
        daytona=_FakeDaytona(listed_after_delete=[foreign]),
    )

    assert reap_calls == {"run_id": "refsol-run-1", "include_running": True}
    assert result.cleanup["status"] == "complete"
    assert result.cleanup["leftover_count"] == 0
    assert result.cleanup["sandbox_deleted"] is True
    assert fake.deleted, "sandbox was not deleted"


def test_cleanup_actively_deletes_transient_leftovers(tmp_path, monkeypatch):
    leftover = SimpleNamespace(
        id="stray-1",
        labels={SANDBOX_RUN_ID_LABEL: "refsol-run-1"},
        state="STARTED",
    )
    monkeypatch.setattr(
        refsol_eval,
        "reap_stale_terminalbench_sandboxes",
        lambda daytona, *, run_id, include_running: (0, 0),
    )
    fake = _FakeDaytona(listed_after_delete=[leftover])
    result, _ = _run(tmp_path, monkeypatch, daytona=fake)

    assert result.cleanup["status"] == "complete"
    assert result.cleanup["leftover_count"] == 0
    assert any(getattr(s, "id", "") == "stray-1" for s in fake.deleted)


def test_cleanup_reports_undeletable_leftovers_as_partial(tmp_path, monkeypatch):
    leftover = SimpleNamespace(
        id="stray-1",
        labels={SANDBOX_RUN_ID_LABEL: "refsol-run-1"},
        state="STARTED",
    )
    monkeypatch.setattr(
        refsol_eval,
        "reap_stale_terminalbench_sandboxes",
        lambda daytona, *, run_id, include_running: (0, 0),
    )
    result, _ = _run(
        tmp_path,
        monkeypatch,
        daytona=_FakeDaytona(
            listed_after_delete=[leftover], undeletable_ids={"stray-1"}
        ),
    )

    assert result.cleanup["status"] == "partial"
    assert result.cleanup["leftover_count"] == 1
    assert result.cleanup["leftover_ids"] == ["stray-1"]


def test_cleanup_skipped_without_run_id(tmp_path, monkeypatch):
    result, _ = _run(tmp_path, monkeypatch, run_id=None)

    assert result.cleanup["status"] == "skipped_no_run_id"
    assert result.run_id is None


def test_solution_timeout_records_exit_124_and_still_verifies(tmp_path, monkeypatch):
    result, fake = _run(
        tmp_path, monkeypatch, daytona=_FakeDaytona(solution_exit_code=124)
    )

    assert result.solution_exit_code == 124
    assert result.solution_timed_out is True
    assert any(op == "create_session" for op, _ in fake.ops)


def test_sandbox_deleted_even_when_verifier_raises(tmp_path, monkeypatch):
    def broken_verifier(sandbox, bundle, **kwargs):
        raise RuntimeError("verifier exploded")

    monkeypatch.setattr(refsol_eval, "run_daytona_harbor_verifier", broken_verifier)
    with pytest.raises(RuntimeError, match="verifier exploded"):
        _run(tmp_path, monkeypatch)


def test_sandbox_delete_happens_on_verifier_failure(tmp_path, monkeypatch):
    fake = _FakeDaytona()
    monkeypatch.setattr(
        refsol_eval,
        "run_daytona_harbor_verifier",
        lambda sandbox, bundle, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with pytest.raises(RuntimeError):
        _run(tmp_path, monkeypatch, daytona=fake)
    assert fake.deleted, "sandbox must be deleted in finally on failure"


def test_provisions_declared_task_resources(tmp_path, monkeypatch):
    _, fake = _run(tmp_path, monkeypatch)

    assert len(fake.created_params) == 1
    res = fake.created_params[0].resources
    assert res.cpu == 1
    assert res.memory == 2
    assert res.disk == 10


def test_high_declared_resources_are_not_capped(tmp_path):
    bundle = _bundle(tmp_path)
    (tmp_path / "task.toml").write_text(
        "[agent]\ntimeout_sec = 123.0\n"
        '[environment]\ndocker_image = "example/refsol-image:1"\n'
        "cpus = 16\nmemory_mb = 65536\nstorage_mb = 1048576\ngpus = 0\n"
    )
    res = refsol_eval._refsol_resources(bundle)
    assert res.cpu == 16
    assert res.memory == 64
    assert res.disk == 1024


def test_modest_declared_resources_are_honored(tmp_path):
    bundle = _bundle(tmp_path)
    (tmp_path / "task.toml").write_text(
        '[environment]\ndocker_image = "x:1"\ncpus = 1\nmemory_mb = 2048\n'
        "storage_mb = 3072\ngpus = 0\n"
    )
    res = refsol_eval._refsol_resources(bundle)
    assert (res.cpu, res.memory, res.disk) == (1, 2, 3)


def test_missing_solve_sh_raises_clear_error(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path)
    (tmp_path / "solution" / "solve.sh").unlink()
    monkeypatch.setattr(
        refsol_eval,
        "load_terminalbench_daytona_bundle",
        lambda *, task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr("daytona_sdk.Daytona", lambda: _FakeDaytona())
    with pytest.raises(FileNotFoundError, match="no shipped reference solution"):
        run_one_refsol_task("example", ref="sha256:test-ref")


def _state(metadata: dict) -> TaskState:
    return TaskState(
        model="mockllm/model",
        sample_id="example",
        epoch=0,
        input="example",
        messages=[],
        metadata=metadata,
    )


def _passing_refsol_metadata(**overrides) -> dict:
    metadata = {
        "task_id": "example",
        "reward": 1.0,
        "answer": "PASS",
        "solution_exit_code": 0,
        "cleanup": {"status": "complete", "leftover_count": 0},
    }
    metadata.update(overrides)
    return metadata


def test_scorer_passes_clean_run():
    state = _state({"terminalbench_refsol": _passing_refsol_metadata()})
    score = asyncio.run(refsol_daytona_scorer()(state, None))
    assert score.value == 1.0
    assert score.answer == "PASS"


@pytest.mark.parametrize(
    "overrides",
    [
        {"cleanup": {"status": "partial", "leftover_count": 0}},
        {"cleanup": {"status": "complete", "leftover_count": 1}},
    ],
)
def test_scorer_does_not_gate_on_cleanup_state(overrides):
    state = _state({"terminalbench_refsol": _passing_refsol_metadata(**overrides)})
    score = asyncio.run(refsol_daytona_scorer()(state, None))
    assert score.value == 1.0
    assert score.answer == "PASS"


def test_scorer_reflects_failing_verifier():
    state = _state(
        {"terminalbench_refsol": _passing_refsol_metadata(reward=0.0, answer="FAIL")}
    )
    score = asyncio.run(refsol_daytona_scorer()(state, None))
    assert score.value == 0.0
    assert score.answer == "FAIL"


@pytest.mark.parametrize("exit_code", [2, 127, None])
def test_scorer_does_not_gate_on_solution_exit_code(exit_code):
    state = _state(
        {"terminalbench_refsol": _passing_refsol_metadata(solution_exit_code=exit_code)}
    )
    score = asyncio.run(refsol_daytona_scorer()(state, None))
    assert score.value == 1.0
    assert f"solution_exit_code={exit_code}" in (score.explanation or "")


def test_task_builds_one_sample_per_task_id():
    t = refsol_terminalbench_daytona(task_ids="a,b,c")
    ids = [s.id for s in (t.dataset or [])]
    assert ids == ["a", "b", "c"]
    assert t.sandbox is None
    sample = list(t.dataset)[0]
    assert sample.metadata["policy"] == "none"
    assert sample.metadata["hardened_execution"] is False
    assert sample.metadata["execution_mode"] == "reference_solution"
    assert "solution_variant" not in sample.metadata


def test_solver_only_forwards_solution_variant_when_explicit():
    calls = []

    def runner(task_id, **kwargs):
        calls.append((task_id, kwargs))
        return RefsolRunResult(
            task_id=task_id,
            harbor_ref=kwargs["ref"],
            image="example/image:1",
            solution_path=REMOTE_SOLUTION_PATH,
            solution_exit_code=0,
            solution_timed_out=False,
            solution_stdout_tail="ok",
            verifier=refsol_eval.DaytonaVerifierResult(
                value=1.0,
                answer="PASS",
                exit_code=0,
                stdout="ok",
                stderr="",
            ),
            sandbox_id="sandbox-1",
            run_id="run-1",
        )

    normal_solver = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref", runner=runner, max_attempts=1
    )
    asyncio.run(normal_solver(_state({"terminal_bench_task_id": "example"}), None))
    assert "solution_variant" not in calls[-1][1]

    witness_solver = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref",
        runner=runner,
        max_attempts=1,
        solution_variant="solvability-witnesses",
    )
    asyncio.run(
        witness_solver(
            _state({"terminal_bench_task_id": "sqlite-with-gcov"}), None
        )
    )
    assert calls[-1][1]["solution_variant"] == "solvability-witnesses"


@pytest.mark.parametrize(
    ("task_id", "policy", "solution_variant", "error"),
    [
        ("sqlite-with-gcov", "low-nist", "unknown", "unknown solution variant"),
        (
            "log-summary-date-ranges",
            "low-nist",
            "solvability-witnesses",
            "not admitted",
        ),
        (
            "sqlite-with-gcov",
            "none",
            "solvability-witnesses",
            "requires a native policy",
        ),
    ],
)
def test_task_rejects_invalid_witness_admission(
    tmp_path, monkeypatch, task_id, policy, solution_variant, error
):
    monkeypatch.setattr(refsol_eval, "_ROOTLESS_WITNESSES_DIR", tmp_path)
    with pytest.raises(ValueError, match=error):
        refsol_terminalbench_daytona(
            task_ids=task_id,
            policy=policy,
            solution_variant=solution_variant,
        )


def test_task_omission_never_resolves_witness_assets(monkeypatch):
    def unexpected(_solution_variant):
        raise AssertionError("normal refsol resolved a witness variant")

    monkeypatch.setattr(refsol_eval, "_witness_variant", unexpected)

    task = refsol_terminalbench_daytona(task_ids="log-summary-date-ranges")

    assert "solution_variant" not in list(task.dataset)[0].metadata


def test_task_rejects_missing_rootless_witness_asset(tmp_path, monkeypatch):
    monkeypatch.setattr(refsol_eval, "_ROOTLESS_WITNESSES_DIR", tmp_path)

    with pytest.raises(FileNotFoundError, match="rootless witness asset"):
        refsol_terminalbench_daytona(
            task_ids="sqlite-with-gcov",
            policy="low-nist",
            solution_variant="solvability-witnesses",
        )


@pytest.mark.parametrize(
    ("task_id", "policy", "solution_variant", "error"),
    [
        ("gcode-to-text", "low-nist", "unknown", "unknown solution variant"),
        (
            "sqlite-with-gcov",
            "low-nist",
            "static-egress-witnesses",
            "not admitted",
        ),
        (
            "gcode-to-text",
            "none",
            "static-egress-witnesses",
            "requires a native policy",
        ),
    ],
)
def test_task_rejects_invalid_static_egress_witness_admission(
    tmp_path, monkeypatch, task_id, policy, solution_variant, error
):
    monkeypatch.setattr(refsol_eval, "_NETWORK_WITNESSES_DIR", tmp_path)
    with pytest.raises(ValueError, match=error):
        refsol_terminalbench_daytona(
            task_ids=task_id,
            policy=policy,
            solution_variant=solution_variant,
        )


def test_task_rejects_missing_static_egress_witness_asset(tmp_path, monkeypatch):
    monkeypatch.setattr(refsol_eval, "_NETWORK_WITNESSES_DIR", tmp_path)

    with pytest.raises(FileNotFoundError, match="static-egress witness asset"):
        refsol_terminalbench_daytona(
            task_ids="gcode-to-text",
            policy="low-nist",
            solution_variant="static-egress-witnesses",
        )


def test_task_accepts_static_egress_witness_and_records_variant(
    tmp_path, monkeypatch
):
    task_id = "gcode-to-text"
    witness_dir = tmp_path / task_id
    witness_dir.mkdir(parents=True)
    (witness_dir / "solve.sh").write_bytes(b"#!/bin/sh\necho committed witness\n")
    monkeypatch.setattr(refsol_eval, "_NETWORK_WITNESSES_DIR", tmp_path)

    task = refsol_terminalbench_daytona(
        task_ids=task_id,
        policy="low-nist",
        solution_variant="static-egress-witnesses",
    )

    sample = list(task.dataset)[0]
    assert sample.metadata["solution_variant"] == "static-egress-witnesses"
    assert sample.metadata["policy"] == "low-nist"
    assert sample.metadata["hardened_execution"] is True


def test_static_egress_witness_source_and_path_use_network_asset_dir(
    tmp_path, monkeypatch
):
    task_id = "gcode-to-text"
    witness_body = b"#!/bin/sh\necho committed witness\n"
    witness_dir = tmp_path / task_id
    witness_dir.mkdir(parents=True)
    (witness_dir / "solve.sh").write_bytes(witness_body)
    monkeypatch.setattr(refsol_eval, "_NETWORK_WITNESSES_DIR", tmp_path)

    variant = refsol_eval._witness_variant("static-egress-witnesses")
    assert refsol_eval._witness_path(variant, task_id) == (
        tmp_path / task_id / "solve.sh"
    )
    assert refsol_eval.witness_source("static-egress-witnesses", task_id) == {
        "name": "static-egress-witnesses",
        "task_id": task_id,
        "asset_path": f"refsol_network_witnesses/{task_id}/solve.sh",
        "sha256": hashlib.sha256(witness_body).hexdigest(),
    }
    assert refsol_eval.witness_solution_fidelity("static-egress-witnesses") == (
        "committed_static_egress_witness"
    )
    assert refsol_eval.witness_solution_override("static-egress-witnesses") == {
        "applied": False,
        "reason": "static_egress_witness_variant",
    }


def _rootless_witness_text(task_id: str) -> str:
    path = (
        Path(refsol_eval.__file__).resolve().parent
        / "refsol_rootless_witnesses"
        / task_id
        / "solve.sh"
    )
    assert path.is_file(), f"missing packaged rootless witness: {path}"
    return path.read_text()


def _assert_apt_get_installs_are_download_only(script: str) -> None:
    logical_script = re.sub(r"\\(?:\r\n|\n)[ \t]*", " ", script)
    shell_commands = re.split(r"(?:\r?\n|;|&&|\|\|)", logical_script)
    install_commands = [
        command.strip()
        for command in shell_commands
        if re.match(r"^\s*apt(?:-get)?(?:\s|$)", command)
        and re.search(r"(?:^|\s)install(?:\s|$)", command)
    ]

    assert install_commands, "witness must contain an apt-get install invocation"
    for command in install_commands:
        install_prefix = re.split(r"(?:^|\s)install(?:\s|$)", command, maxsplit=1)[0]
        assert re.search(
            r"(?:^|\s)--download-only(?:\s|$)", install_prefix
        ), f"apt-get install must use --download-only: {command}"


def test_rootless_witness_asset_check_rejects_mixed_safe_and_root_apt_installs():
    script = """\
apt-get "${opts[@]}" --download-only \\
  install safe-package
apt-get "${opts[@]}" -y \\
  install root-package
"""

    with pytest.raises(AssertionError, match="must use --download-only"):
        _assert_apt_get_installs_are_download_only(script)


@pytest.mark.parametrize(
    "script",
    [
        "apt-get --download-only install safe; apt-get -y install root-package",
        "apt-get --download-only install safe\napt -y install root-package",
    ],
)
def test_rootless_witness_asset_check_rejects_compound_root_apt_installs(script):
    with pytest.raises(AssertionError, match="must use --download-only"):
        _assert_apt_get_installs_are_download_only(script)


@pytest.mark.parametrize(
    "task_id",
    ["sqlite-with-gcov", "build-pmars", "adaptive-rejection-sampler"],
)
def test_rootless_witness_assets_reject_root_only_package_installation(task_id):
    script = _rootless_witness_text(task_id)

    assert "set -euo pipefail" in script
    assert "sudo" not in script
    _assert_apt_get_installs_are_download_only(script)
    assert "apt install" not in script
    assert "dpkg-deb -x" in script


@pytest.mark.parametrize("task_id", ["make-doom-for-mips", "caffe-cifar-10"])
def test_eng_3309_rootless_witnesses_use_private_apt_sysroots(task_id):
    import subprocess

    path = Path(refsol_eval._ROOTLESS_WITNESSES_DIR) / task_id / "solve.sh"
    script = path.read_text()
    syntax = subprocess.run(
        ["bash", "-n", str(path)], capture_output=True, text=True, check=False
    )

    assert syntax.returncode == 0, syntax.stderr
    assert path.stat().st_mode & 0o111
    assert "set -euo pipefail" in script
    assert "export APT_CONFIG=/app/rootless-apt/apt.conf" in script
    assert 'Dir::State=/app/rootless-apt/state' in script
    assert 'Dir::Cache=/app/rootless-apt/cache' in script
    assert 'apt-get "${APT_OPTIONS[@]}" update' in script
    assert 'apt-cache "${APT_OPTIONS[@]}" depends --recurse' in script
    assert 'apt-get "${APT_OPTIONS[@]}" download "$package"' in script
    assert 'dpkg -x "$archive" "$SYSROOT"' in script
    assert "SYSROOT=/app/sysroot" in script
    assert "sudo" not in script
    assert "apt-get install" not in script
    assert "dpkg -i" not in script
    assert "proot" not in script.lower()


def test_make_doom_rootless_witness_builds_and_validates_mips_output():
    script = _rootless_witness_text("make-doom-for-mips")

    assert "cat <<'QQEOF' > /app/mips.patch" in script
    assert "commit 4da9b5d989cda19f1a07f045c73aac66bf0d6f97" in script
    for package in (
        "clang",
        "llvm",
        "lld",
        "binutils-mips-linux-gnu",
        "gcc-mips-linux-gnu",
        "g++-mips-linux-gnu",
        "libbinutils",
    ):
        assert package in script
    assert "git apply /app/mips.patch" in script
    assert "make all && cp doomgeneric_mips /app/doomgeneric_mips" in script
    assert "test -s /app/doomgeneric_mips" in script
    assert "readelf" in script and "Machine:.*MIPS" in script


def test_caffe_rootless_witness_builds_cpu_only_verifier_artifacts_in_budget():
    script = _rootless_witness_text("caffe-cifar-10")

    for package in (
        "build-essential",
        "libprotobuf-dev",
        "libleveldb-dev",
        "libsnappy-dev",
        "libhdf5-dev",
        "libopenblas-pthread-dev",
        "libboost-filesystem-dev",
        "libboost-system-dev",
        "libboost-thread-dev",
        "libgflags-dev",
        "libgoogle-glog-dev",
        "liblmdb-dev",
        "patchelf",
    ):
        assert package in script
    assert "libopenblas-dev" not in script
    assert "libboost-all-dev" not in script
    assert "libopencv-dev" not in script
    assert "git checkout 9b89154" in script
    assert "CPU_ONLY := 1" in script
    assert "USE_OPENCV := 0" in script
    assert "make all -j4" in script
    assert "patchelf --force-rpath --set-rpath" in script
    assert "https://data.brainchip.com/dataset-mirror/cifar10/" in script
    assert "c4a38c50a1bc5f3a1c5537f2155ab9d68f9f25eb1ed8d9ddda3db29a59bca1dd" in script
    assert "sha256sum -c" in script
    assert "get_cifar10.sh" not in script
    assert "create_cifar10.sh" in script
    assert "max_iter: 500" in script
    assert "test_iter: 10" in script
    assert "0,/batch_size: 100/s//batch_size: 64/" in script
    assert ".build_release/tools/caffe.bin train" in script
    assert "--solver=examples/cifar10/cifar10_quick_solver.prototxt" in script
    assert "training_output.txt" in script
    assert "cifar10_quick_iter_500.caffemodel" in script


def test_sqlite_rootless_witness_builds_and_executes_gcov_binary():
    script = _rootless_witness_text("sqlite-with-gcov")

    assert "/app/vendor/sqlite-fossil-release.tar.gz" in script
    assert "/app/sqlite" in script
    assert "-ftest-coverage" in script
    assert "-fprofile-arcs" in script
    assert "--enable-fts3" in script
    assert "--enable-session" in script
    assert "/app/sqlite/sqlite3" in script
    assert "/usr/local/bin/sqlite3" not in script
    assert '"*.gcno"' in script
    assert '"*.gcda"' in script


def test_pmars_rootless_witness_uses_private_apt_source_and_copies_libc_binary():
    script = _rootless_witness_text("build-pmars")

    assert "Dir::State=" in script
    assert "Dir::Cache::archives=" in script
    assert 'apt-get "${opts[@]}" source pmars' in script
    assert 'if [ -f "$ROOT/usr/lib/x86_64-linux-gnu/libc.so" ]; then' in script
    assert "-Wl,-Bstatic -lncurses -ltinfo -Wl,-Bdynamic" in script
    assert "cp pmars /app/pmars" in script
    assert "ldd /app/pmars" in script
    assert "ENG3310_PMARS_LDD_BEGIN" in script
    assert "ENG3310_PMARS_LDD_END" in script
    assert 'printf \'%s\\n\' "$ldd_output"' in script
    assert "libc.so.6" in script
    assert "install -m" not in script
    assert "/usr/local/bin/pmars" not in script


def test_r_rootless_witness_installs_prefix_and_proves_symlinked_r_home():
    script = _rootless_witness_text("adaptive-rejection-sampler")

    assert "ROOT=/app/R/root" in script
    assert "ln -s root/usr/lib/R /app/R/lib" in script
    assert "/app/R/bin/Rscript.real" in script
    assert "LD_LIBRARY_PATH=/app/R/root/" in script
    assert "/app/R/bin/Rscript" in script
    assert "/usr/local/bin/Rscript" not in script
    assert "R.home()" in script
    assert 'ENG3310_R_HOME=%s\\n' in script
    assert 'test "$r_home" = /app/R/lib' in script
    assert "adaptive-rejection-sampler-2024" in script
    assert 'source("ars.R")' in script
    assert "normal_samples.txt" in script


def test_r_rootless_witness_rejects_non_log_concave_density_before_sampling():
    script = _rootless_witness_text("adaptive-rejection-sampler")

    assert "eng3310_assert_log_concave" in script
    assert "diff(slopes)" in script
    assert "Density is not log-concave" in script


def test_r_rootless_witness_tolerates_optional_exponential_sample_failure():
    script = _rootless_witness_text("adaptive-rejection-sampler")

    assert "Exponential sample generation skipped" in script


def test_r_rootless_witness_resolves_openssl_from_private_root_or_image():
    script = _rootless_witness_text("adaptive-rejection-sampler")
    logical_script = re.sub(r"\\(?:\r\n|\n)[ \t]*", " ", script)

    assert 'openssl_bin="$ROOT/usr/bin/openssl"' in script
    assert 'if [ ! -x "$openssl_bin" ]; then' in script
    assert 'openssl_bin="$(command -v openssl || true)"' in script
    assert 'test -n "$openssl_bin"' in script
    assert 'test -x "$openssl_bin"' in script
    assert re.search(r'"\$openssl_bin"\s+enc -aes-256-cbc', logical_script)


@pytest.mark.parametrize(
    ("task_id", "policy", "solution_variant", "error_type", "error"),
    [
        (
            "sqlite-with-gcov",
            "low-nist",
            "unknown",
            ValueError,
            "unknown solution variant",
        ),
        (
            "log-summary-date-ranges",
            "low-nist",
            "solvability-witnesses",
            ValueError,
            "not admitted",
        ),
        (
            "sqlite-with-gcov",
            "none",
            "solvability-witnesses",
            ValueError,
            "requires a native policy",
        ),
        (
            "sqlite-with-gcov",
            "low-nist",
            "solvability-witnesses",
            FileNotFoundError,
            "rootless witness asset",
        ),
    ],
)
def test_runner_rejects_invalid_witness_before_bundle_load_or_daytona(
    tmp_path,
    monkeypatch,
    task_id,
    policy,
    solution_variant,
    error_type,
    error,
):
    calls = []
    monkeypatch.setattr(refsol_eval, "_ROOTLESS_WITNESSES_DIR", tmp_path)
    monkeypatch.setattr(
        refsol_eval,
        "load_terminalbench_daytona_bundle",
        lambda **kwargs: calls.append("bundle"),
    )
    monkeypatch.setattr(
        "daytona_sdk.Daytona", lambda: calls.append("daytona")
    )

    with pytest.raises(error_type, match=error):
        run_one_refsol_task(
            task_id,
            ref="sha256:test-ref",
            policy=policy,
            solution_variant=solution_variant,
        )

    assert calls == []


def test_none_run_is_labeled_compatibility_baseline_and_records_remote_solution_path(
    tmp_path, monkeypatch
):
    result, _ = _run(tmp_path, monkeypatch, policy="none")

    assert result.solution_fidelity == "compatibility_baseline"
    assert result.solution_path == REMOTE_SOLUTION_PATH


def test_default_task_ids_are_the_regression_slice():
    t = refsol_terminalbench_daytona()
    ids = [s.id for s in (t.dataset or [])]
    assert ids == [
        "log-summary-date-ranges",
        "openssl-selfsigned-cert",
        "pypi-server",
    ]


def test_solver_records_error_metadata_instead_of_raising(monkeypatch):
    def failing_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        raise RuntimeError("provisioning exploded")

    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref", runner=failing_runner, max_attempts=1
    )
    state = _state({"terminal_bench_task_id": "example"})
    result_state = asyncio.run(solver_fn(state, None))

    metadata = result_state.metadata["terminalbench_refsol"]
    assert metadata["answer"] == "ERROR"
    assert metadata["reward"] == 0.0
    assert "provisioning exploded" in metadata["error"]
    assert result_state.completed is True
    score = asyncio.run(refsol_daytona_scorer()(result_state, None))
    assert math.isnan(score.value)
    assert score.answer == "ERROR"
    assert metadata["benchmark_status"]["task_outcome"] == "ERROR"
    assert metadata["benchmark_status"]["valid_for_analysis"] is False


def test_solver_preserves_actual_runtime_probe_failure_for_manager_retry():
    report_metadata = {
        "passed": False,
        "required_failed_count": 1,
        "results": [
            {
                "required": True,
                "status": "fail",
                "classification": "runtime_error",
                "message": "container disappeared",
            }
        ],
    }
    report = SimpleNamespace(
        required_failed_count=1,
        to_metadata=lambda: report_metadata,
    )

    def failing_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        raise refsol_eval.DaytonaRuntimeProbeSuiteError(report)

    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref",
        runner=failing_runner,
        max_attempts=1,
        policy="low-nist",
    )
    state = _state({"terminal_bench_task_id": "example"})
    result_state = asyncio.run(solver_fn(state, None))

    metadata = result_state.metadata["terminalbench_refsol"]
    assert metadata["runtime_policy_probe_report"] == report_metadata
    assert metadata["benchmark_status"]["failure_class"] == "hardening_preflight"
    assert metadata["answer"] == "ERROR"
    assert metadata["hardening_preflight_infra_retry_eligible"] is True
    score = asyncio.run(refsol_daytona_scorer()(result_state, None))
    assert math.isnan(score.value)


@pytest.mark.parametrize(
    "exception",
    [
        refsol_eval._MissingPolicyEvidenceError("missing policy event"),
        PreflightFailedError("policy assertion failed", result=None),
    ],
)
def test_solver_records_policy_contract_failures_as_invalid(exception):
    def failing_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        raise exception

    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref",
        runner=failing_runner,
        max_attempts=1,
        policy="low-nist",
    )
    result_state = asyncio.run(
        solver_fn(_state({"terminal_bench_task_id": "example"}), None)
    )

    metadata = result_state.metadata["terminalbench_refsol"]
    assert metadata["answer"] == "INVALID"
    assert metadata["benchmark_status"] == {
        "schema_version": "boundarybench.benchmark-status.v1",
        "job_status": "completed",
        "eval_artifact_status": "complete",
        "task_outcome": "INVALID",
        "failure_class": "hardening_preflight",
        "valid_for_analysis": False,
    }
    score = asyncio.run(refsol_daytona_scorer()(result_state, None))
    assert math.isnan(score.value)
    assert score.answer == "INVALID"


def test_solver_records_policy_assertion_probe_failure_as_invalid():
    report_metadata = {
        "passed": False,
        "required_failed_count": 1,
        "results": [
            {
                "required": True,
                "status": "fail",
                "classification": "policy_assertion",
                "message": "curl unexpectedly succeeded",
            }
        ],
    }
    report = SimpleNamespace(
        required_failed_count=1,
        to_metadata=lambda: report_metadata,
    )

    def failing_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        raise refsol_eval.DaytonaRuntimeProbeSuiteError(report)

    result_state = asyncio.run(
        refsol_eval.refsol_daytona_solver(
            ref="sha256:test-ref",
            runner=failing_runner,
            max_attempts=1,
            policy="low-nist",
        )(_state({"terminal_bench_task_id": "example"}), None)
    )
    metadata = result_state.metadata["terminalbench_refsol"]
    assert metadata["answer"] == "INVALID"
    assert metadata["benchmark_status"]["failure_class"] == "hardening_preflight"
    assert metadata["benchmark_status"]["valid_for_analysis"] is False


@pytest.mark.parametrize("policy", ["non-root", "low-nist"])
def test_refsol_rejects_unsupported_verifier_semantics_before_provisioning(
    tmp_path, monkeypatch, policy
):
    bundle = _bundle(tmp_path)
    bundle = replace(
        bundle,
        verifier_environment_mode="separate",
    )
    fake = _FakeDaytona()
    monkeypatch.setattr(
        refsol_eval,
        "load_terminalbench_daytona_bundle",
        lambda *, task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr("daytona_sdk.Daytona", lambda: fake)

    with pytest.raises(RuntimeError, match="environment mode 'separate'"):
        run_one_refsol_task("example", ref="sha256:test-ref", policy=policy)

    assert fake.created_params == []


def test_provision_rides_out_capacity_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(refsol_eval, "CAPACITY_WAIT_INTERVAL_SEC", 0)
    fake = _FakeDaytona(
        create_errors=[
            RuntimeError(
                "Failed to create sandbox: Total disk limit exceeded. "
                "Maximum allowed: 300GiB."
            )
        ]
    )
    result, _ = _run(tmp_path, monkeypatch, daytona=fake)

    assert result.reward == 1.0
    assert len(fake.created_params) == 1


def test_solver_reraises_persistent_capacity_errors(monkeypatch):
    def capacity_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        raise RuntimeError(
            "Failed to create sandbox: Total disk limit exceeded. "
            "Maximum allowed: 300GiB."
        )

    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref", runner=capacity_runner, max_attempts=1
    )
    state = _state({"terminal_bench_task_id": "example"})
    with pytest.raises(RuntimeError, match="Total disk limit exceeded"):
        asyncio.run(solver_fn(state, None))


def test_egress_failure_raises_transient_for_solver_retry(tmp_path, monkeypatch):
    fake = _FakeDaytona(
        reward_txt="0.0\n",
        solution_stdout="curl: (35) Recv failure: Connection reset by peer",
    )
    with pytest.raises(refsol_eval._TransientEgressError):
        _run(tmp_path, monkeypatch, daytona=fake)
    assert fake.deleted, "sandbox must be cleaned up before the retry"


def test_egress_transient_is_retried_by_solver(monkeypatch):
    calls = {"n": 0}

    def flaky_runner(task_id, *, ref, solution_timeout_sec=None, policy="none"):
        calls["n"] += 1
        if calls["n"] == 1:
            raise refsol_eval._TransientEgressError(
                f"{refsol_eval._EGRESS_MARKER}: blocked"
            )
        return refsol_eval.RefsolRunResult(
            task_id=task_id,
            harbor_ref=ref,
            image="img",
            solution_path="/solution/solve.sh",
            solution_exit_code=0,
            solution_timed_out=False,
            solution_stdout_tail="ok",
            verifier=SimpleNamespace(
                value=1.0,
                answer="PASS",
                to_metadata=lambda: {"value": 1.0, "answer": "PASS"},
            ),
            sandbox_id="sb",
            run_id=None,
            cleanup={"status": "complete", "leftover_count": 0},
        )

    monkeypatch.setattr(refsol_eval.asyncio, "sleep", _instant_sleep)
    solver_fn = refsol_eval.refsol_daytona_solver(
        ref="sha256:test-ref", runner=flaky_runner, max_attempts=3
    )
    state = _state({"terminal_bench_task_id": "example"})
    result_state = asyncio.run(solver_fn(state, None))

    assert calls["n"] == 2
    score = asyncio.run(refsol_daytona_scorer()(result_state, None))
    assert score.value == 1.0


async def _instant_sleep(_seconds):
    return None


@pytest.mark.parametrize(
    "image,expected",
    [
        ("alexgshaw/build-cython-ext:20251031", "2025-11-01"),
        ("alexgshaw/mteb-retrieve:20260430", "2026-05-01"),
        ("alexgshaw/overfull-hbox:20260403", "2026-04-04"),
        ("localhost:5000/foo:20260403", "2026-04-04"),
        ("repo/img:2026-04-03", "2026-04-04"),
        ("example/refsol-image:1", None),
        ("repo/img:latest", None),
        ("img-no-tag", None),
        ("repo/img:20251345", None),
    ],
)
def test_image_build_cutoff_date_parses_only_dated_tags(image, expected):
    assert refsol_eval._image_build_cutoff_date(image) == expected


def test_pip_shim_wrapper_routes_installs_through_uv_else_real_pip():
    wrapper = refsol_eval._PIP_SHIM_WRAPPER
    assert 'exec "$UV" pip "$@"' in wrapper
    assert "UV_EXCLUDE_NEWER" in wrapper
    assert "install|uninstall|freeze|list|show|check|sync|tree)" in wrapper
    assert 'exec "$REAL" "$@"' in wrapper
    for guard in ("VIRTUAL_ENV", "--user", "--target", "--prefix", "--python"):
        assert guard in wrapper
    for src in ("--index-url", "--extra-index-url", "--find-links", "--no-index"):
        assert src in wrapper


def _run_pip_wrapper(tmp_path, argv, *, self_name="pip", virtual_env=None):
    """Execute the shim wrapper for real with stub uv/real-pip and return the
    first stdout token stream, so routing decisions are asserted behaviourally
    rather than by string-matching the template."""

    import os
    import subprocess

    shimdir = tmp_path / "shim"
    shimdir.mkdir(exist_ok=True)
    (shimdir / "cutoff").write_text("2025-11-01")
    uv = tmp_path / "uv-stub"
    uv.write_text('#!/bin/sh\necho "UV $*"\n')
    uv.chmod(0o755)
    (shimdir / "uvpath").write_text(str(uv))
    real = shimdir / f"{self_name}.real"
    real.write_text('#!/bin/sh\necho "REAL $*"\n')
    real.chmod(0o755)
    wrapper_src = refsol_eval._PIP_SHIM_WRAPPER.replace(
        f"SHIMDIR={refsol_eval._PIP_SHIM_DIR}", f"SHIMDIR={shimdir}"
    )
    entry = tmp_path / self_name
    entry.write_text(wrapper_src)
    entry.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    if virtual_env:
        env["VIRTUAL_ENV"] = virtual_env
    proc = subprocess.run(
        ["/bin/sh", str(entry), *argv],
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.stdout.strip()


def test_pip_wrapper_plain_install_routes_through_uv_with_system(tmp_path):
    out = _run_pip_wrapper(tmp_path, ["install", "planarity"])
    assert out == "UV pip install planarity --system"


def test_pip_wrapper_index_url_falls_through_to_real_pip(tmp_path):
    out = _run_pip_wrapper(
        tmp_path,
        [
            "install",
            "torch==2.7.0",
            "--index-url",
            "https://download.pytorch.org/whl/cpu",
        ],
    )
    assert (
        out
        == "REAL install torch==2.7.0 --index-url https://download.pytorch.org/whl/cpu"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["install", "-i", "http://localhost:8080/simple", "pkg"],
        ["install", "--extra-index-url", "http://localhost:8080/simple", "pkg"],
        ["install", "--find-links", "/wheels", "pkg"],
        ["install", "--no-index", "--find-links", "/wheels", "pkg"],
    ],
)
def test_pip_wrapper_alternate_sources_fall_through_to_real_pip(tmp_path, argv):
    out = _run_pip_wrapper(tmp_path, argv)
    assert out.startswith("REAL install")
    assert "--system" not in out


def test_pip_wrapper_user_and_venv_skip_system_but_stay_on_uv(tmp_path):
    assert (
        _run_pip_wrapper(tmp_path, ["install", "--user", "pkg"])
        == "UV pip install --user pkg"
    )
    assert (
        _run_pip_wrapper(tmp_path, ["install", "pkg"], virtual_env="/venv")
        == "UV pip install pkg"
    )


def test_pip_wrapper_non_install_verbs_reach_real_pip(tmp_path):
    assert _run_pip_wrapper(tmp_path, ["download", "pkg"]) == "REAL download pkg"
    assert _run_pip_wrapper(tmp_path, ["--version"]) == "REAL --version"


class _OverrideFs:
    def __init__(self) -> None:
        self.uploaded: list[tuple[str, str, bytes]] = []

    def upload_file(self, local_path: str, remote_path: str) -> None:
        with open(local_path, "rb") as handle:
            self.uploaded.append((local_path, remote_path, handle.read()))


class _OverrideProc:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        return _FakeResult(0, "")


class _OverrideSandbox:
    def __init__(self) -> None:
        self.fs = _OverrideFs()
        self.process = _OverrideProc()


def _executable_lines(script: str) -> str:
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )


def test_committed_caffe_override_uses_mirror_not_toronto():
    path = refsol_eval._solution_override_solve_path("caffe-cifar-10")
    assert path is not None, "caffe-cifar-10 override solve.sh must be committed"
    body = path.read_text()
    code = _executable_lines(body)
    assert "cs.toronto.edu" not in code
    assert "get_cifar10.sh" not in code
    assert "cifar-10-binary.tar.gz" in code
    assert "create_cifar10.sh" in code and "train_quick.sh" in code


def test_solution_override_absent_for_unlisted_task():
    assert refsol_eval._solution_override_solve_path("openssl-selfsigned-cert") is None


@pytest.mark.parametrize(
    "value,enabled",
    [(None, True), ("1", True), ("0", False), ("off", False), ("false", False)],
)
def test_solution_overrides_kill_switch(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv(refsol_eval.SOLUTION_OVERRIDES_ENV, raising=False)
    else:
        monkeypatch.setenv(refsol_eval.SOLUTION_OVERRIDES_ENV, value)
    assert refsol_eval._solution_overrides_enabled() is enabled


def test_apply_solution_override_uploads_override_for_caffe(monkeypatch):
    monkeypatch.delenv(refsol_eval.SOLUTION_OVERRIDES_ENV, raising=False)
    sandbox = _OverrideSandbox()
    info = refsol_eval._apply_solution_override(sandbox, "caffe-cifar-10")
    assert info["applied"] is True
    assert len(sandbox.fs.uploaded) == 1
    _, remote, body = sandbox.fs.uploaded[0]
    assert remote == refsol_eval.REMOTE_SOLUTION_PATH
    code = _executable_lines(body.decode())
    assert "cs.toronto.edu" not in code and "cifar-10-binary.tar.gz" in code
    assert any("chmod" in c for c in sandbox.process.commands)


def test_apply_solution_override_noop_without_override(monkeypatch):
    monkeypatch.delenv(refsol_eval.SOLUTION_OVERRIDES_ENV, raising=False)
    sandbox = _OverrideSandbox()
    info = refsol_eval._apply_solution_override(sandbox, "openssl-selfsigned-cert")
    assert info["applied"] is False
    assert sandbox.fs.uploaded == []


def test_apply_solution_override_respects_kill_switch(monkeypatch):
    monkeypatch.setenv(refsol_eval.SOLUTION_OVERRIDES_ENV, "0")
    sandbox = _OverrideSandbox()
    info = refsol_eval._apply_solution_override(sandbox, "caffe-cifar-10")
    assert info == {"applied": False, "reason": "disabled"}
    assert sandbox.fs.uploaded == []


@pytest.mark.parametrize(
    "value,enabled",
    [
        (None, True),
        ("1", True),
        ("true", True),
        ("0", False),
        ("false", False),
        ("off", False),
        ("no", False),
    ],
)
def test_pip_time_shim_kill_switch(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv(refsol_eval.PIP_TIME_SHIM_ENV, raising=False)
    else:
        monkeypatch.setenv(refsol_eval.PIP_TIME_SHIM_ENV, value)
    assert refsol_eval._pip_time_shim_enabled() is enabled


class _ShimProcess:
    def __init__(self, shim_output: str) -> None:
        self.shim_output = shim_output
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        return _FakeResult(0, self.shim_output)


def test_install_pip_time_shim_reports_ok_and_carries_cutoff():
    proc = _ShimProcess("IA_SHIM_OK cutoff=2025-11-01 uv=/usr/local/bin/uv")
    info = refsol_eval._install_pip_time_shim(
        SimpleNamespace(process=proc), cutoff_date="2025-11-01"
    )
    assert info == {
        "enabled": True,
        "installed": True,
        "cutoff_date": "2025-11-01",
        "uv_available": True,
        "exit_code": 0,
        "output_tail": "IA_SHIM_OK cutoff=2025-11-01 uv=/usr/local/bin/uv",
    }
    assert "2025-11-01" in proc.commands[0]
    assert refsol_eval._PIP_SHIM_DIR in proc.commands[0]


def test_install_pip_time_shim_reports_when_uv_unavailable():
    proc = _ShimProcess("IA_SHIM_NO_UV")
    info = refsol_eval._install_pip_time_shim(
        SimpleNamespace(process=proc), cutoff_date="2025-11-01"
    )
    assert info["installed"] is False
    assert info["uv_available"] is False


def _run_with_task_toml(
    tmp_path: Path, monkeypatch, task_toml: str, *, shim_output: str
) -> RefsolRunResult:
    (tmp_path / "task.toml").write_text(task_toml)
    solution_dir = tmp_path / "solution"
    solution_dir.mkdir()
    (solution_dir / "solve.sh").write_text("#!/bin/bash\necho solved\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test.sh").write_text("echo verifying\n")
    bundle = TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="example",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=tests_dir / "test.sh",
        verifier_timeout_sec=120,
        verifier_user="root",
        verifier_environment_mode="shared",
        verifier_environment_mode_source="harbor_default",
    )

    class _ShimAwareDaytona(_FakeDaytona):
        def create(self, params, *, timeout: int):
            sandbox = super().create(params, timeout=timeout)
            real_exec = sandbox.process.exec

            def exec_with_shim(command: str, *, timeout: int, env=None):
                if "IA_SHIM_OK" in command or refsol_eval._PIP_SHIM_DIR in command:
                    sandbox.process.commands.append(command)
                    return _FakeResult(0, shim_output)
                return real_exec(command, timeout=timeout, env=env)

            sandbox.process.exec = exec_with_shim  # type: ignore[assignment]
            return sandbox

    fake = _ShimAwareDaytona()
    monkeypatch.setattr(
        refsol_eval,
        "load_terminalbench_daytona_bundle",
        lambda *, task_id, harbor_ref: bundle,
    )
    monkeypatch.setattr("daytona_sdk.Daytona", lambda: fake)
    monkeypatch.setattr(refsol_eval, "LEFTOVER_CHECK_ATTEMPTS", 1)
    monkeypatch.setattr(refsol_eval, "LEFTOVER_CHECK_SLEEP_SEC", 0)
    monkeypatch.setenv("BOUNDARYBENCH_RUN_ID", "refsol-run-1")
    monkeypatch.delenv(refsol_eval.PIP_TIME_SHIM_ENV, raising=False)
    result = run_one_refsol_task("example", ref="sha256:test-ref")
    return result, fake


_DATED_TASK_TOML = """
[agent]
timeout_sec = 123.0

[verifier]
timeout_sec = 120.0

[environment]
docker_image = "alexgshaw/example:20251031"
cpus = 1
memory_mb = 2048
storage_mb = 10240
gpus = 0

[solution.env]
"""


def test_shim_installed_for_dated_image_and_recorded_in_metadata(tmp_path, monkeypatch):
    result, fake = _run_with_task_toml(
        tmp_path,
        monkeypatch,
        _DATED_TASK_TOML,
        shim_output="IA_SHIM_OK cutoff=2025-11-01 uv=/usr/local/bin/uv",
    )
    assert result.reward == 1.0
    assert result.pip_time_shim["enabled"] is True
    assert result.pip_time_shim["installed"] is True
    assert result.pip_time_shim["cutoff_date"] == "2025-11-01"
    commands = fake.sandboxes[0].process.commands
    assert any(refsol_eval._PIP_SHIM_DIR in c and "2025-11-01" in c for c in commands)
    assert any(".real" in c and "cutoff" not in c for c in commands)


def test_no_shim_installed_for_non_dated_image(tmp_path, monkeypatch):
    result, fake = _run_with_task_toml(
        tmp_path,
        monkeypatch,
        TASK_TOML,
        shim_output="unused",
    )
    assert result.reward == 1.0
    assert result.pip_time_shim["enabled"] is False
    assert result.pip_time_shim.get("reason") == "no_image_build_date"
    commands = fake.sandboxes[0].process.commands
    assert not any(refsol_eval._PIP_SHIM_DIR in c for c in commands)
