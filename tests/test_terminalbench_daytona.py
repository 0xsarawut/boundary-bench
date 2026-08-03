from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tarfile
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from inspect_ai.dataset import Sample

import boundarybench.terminalbench.daytona as daytona_module
from boundarybench.terminalbench.daytona import (
    TerminalBenchTaskBundle,
    parse_reward_content,
    run_daytona_harbor_verifier,
    tar_directory_bytes,
    terminalbench_bundle_from_sample,
    upload_tests_dir_to_daytona,
)


_VERIFIER_MARKER = "__BOUNDARYBENCH_VERIFIER_IDENTITY__"


def test_terminalbench_bundle_from_sample_preserves_harbor_verifier_metadata(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n")
    sample = Sample(
        id="terminal-bench/example",
        input="do the task",
        metadata={
            "task_name": "terminal-bench/example",
            "task_dir": str(tmp_path),
            "tests_dir": str(tests_dir),
            "test_path": str(test_path),
            "verifier_timeout_sec": 123,
            "max_agent_timeout_sec": 900.0,
            "verifier_env": {"A": "B"},
            "verifier_user": "1000",
            "harbor_config": {
                "verifier": {"environment_mode": "shared", "environment": None}
            },
        },
    )

    bundle = terminalbench_bundle_from_sample(sample)

    assert bundle.sample_id == "terminal-bench/example"
    assert bundle.input == "do the task"
    assert bundle.task_name == "terminal-bench/example"
    assert bundle.tests_dir == tests_dir
    assert bundle.test_path == test_path
    assert bundle.verifier_timeout_sec == 123
    assert bundle.agent_timeout_sec == 900
    assert bundle.verifier_env == {"A": "B"}
    assert bundle.verifier_user == "1000"
    assert bundle.verifier_environment_mode == "shared"
    assert bundle.verifier_environment_mode_source == "verifier.environment_mode"
    assert bundle.metadata == sample.metadata


def test_terminalbench_bundle_from_sample_rejects_missing_harbor_config(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n")
    sample = Sample(
        id="terminal-bench/example",
        input="do the task",
        metadata={
            "task_name": "terminal-bench/example",
            "task_dir": str(tmp_path),
            "tests_dir": str(tests_dir),
            "test_path": str(test_path),
        },
    )

    with pytest.raises(ValueError, match="harbor_config"):
        terminalbench_bundle_from_sample(sample)


def test_terminalbench_bundle_reads_agent_timeout_from_task_toml(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n")
    (tmp_path / "task.toml").write_text(
        "[agent]\ntimeout_sec = 2400.0\n",
        encoding="utf-8",
    )
    (tmp_path / "task.yaml").write_text(
        "instruction: legacy\nmax_agent_timeout_sec: 1200.0\n",
        encoding="utf-8",
    )
    sample = Sample(
        id="terminal-bench/example",
        input="do the task",
        metadata={
            "task_name": "terminal-bench/example",
            "task_dir": str(tmp_path),
            "tests_dir": str(tests_dir),
            "test_path": str(test_path),
            "verifier_timeout_sec": 123,
            "harbor_config": {"verifier": {}},
        },
    )

    bundle = terminalbench_bundle_from_sample(sample)

    assert bundle.agent_timeout_sec == 2400


def test_terminalbench_bundle_ignores_legacy_task_yaml_timeout(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n")
    (tmp_path / "task.yaml").write_text(
        "instruction: legacy\nmax_agent_timeout_sec: 2400.0\n",
        encoding="utf-8",
    )
    sample = Sample(
        id="terminal-bench/example",
        input="do the task",
        metadata={
            "task_name": "terminal-bench/example",
            "task_dir": str(tmp_path),
            "tests_dir": str(tests_dir),
            "test_path": str(test_path),
            "verifier_timeout_sec": 123,
            "harbor_config": {"verifier": {}},
        },
    )

    bundle = terminalbench_bundle_from_sample(sample)

    assert bundle.agent_timeout_sec is None


def test_terminalbench_bundle_from_sample_rejects_missing_metadata():
    sample = Sample(id="x", input="task", metadata={})

    with pytest.raises(ValueError, match="missing required fields"):
        terminalbench_bundle_from_sample(sample)


def test_parse_reward_content_matches_harbor_reward_contract():
    assert parse_reward_content(reward_txt="1.0\n") == (1.0, None)
    assert parse_reward_content(reward_txt="\n") == (0.0, None)

    payload = {"reward": 0.5, "details": "partial"}
    assert parse_reward_content(reward_json=json.dumps(payload)) == (0.5, payload)

    fallback_payload = {"score": 0.25}
    assert parse_reward_content(reward_json=json.dumps(fallback_payload)) == (
        0.25,
        fallback_payload,
    )


def test_parse_reward_content_uses_trailing_numeric_reward_after_shell_warnings():
    reward_txt = (
        "shell-init: error retrieving current directory: getcwd: "
        "cannot access parent directories: No such file or directory\n"
        "job-working-directory: error retrieving current directory: getcwd: "
        "cannot access parent directories: No such file or directory\n"
        "1\n"
    )

    assert parse_reward_content(reward_txt=reward_txt) == (1.0, None)


def test_parse_reward_content_rejects_missing_reward():
    with pytest.raises(FileNotFoundError):
        parse_reward_content()

    with pytest.raises(ValueError, match="non-empty object"):
        parse_reward_content(reward_json="[]")

    with pytest.raises(ValueError, match="exactly one numeric key"):
        parse_reward_content(
            reward_json=json.dumps({"score": 0.5, "details": "partial"})
        )

    with pytest.raises(ValueError, match="value must be numeric"):
        parse_reward_content(reward_json=json.dumps({"score": "1.0"}))


def test_tar_directory_bytes_has_exact_non_duplicate_member_names(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "verify.sh").write_text("echo ok\n")
    (tmp_path / "root.txt").write_text("root\n")

    archive = tar_directory_bytes(tmp_path)

    assert archive.startswith(b"\x1f\x8b")
    with tarfile.open(fileobj=BytesIO(archive), mode="r:gz") as tar:
        names = tar.getnames()

    assert names == ["nested", "nested/verify.sh", "root.txt"]
    assert len(names) == len(set(names))


def test_upload_tests_retries_empty_transport_error_when_sandbox_is_live(
    tmp_path, monkeypatch
):
    process = _FlakyUploadProcess(live=True)
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path)
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    upload_tests_dir_to_daytona(sandbox, bundle, staging_dir="/tmp/verifier-stage")

    assert process.extraction_attempts == 2
    assert process.liveness_attempts == 1
    assert len(sandbox.fs.uploads) == 1


def test_upload_tests_retries_empty_upload_error(tmp_path, monkeypatch):
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = _test_bundle(tmp_path)
    attempts = 0
    original_upload = sandbox.fs.upload_file

    def flaky_upload(local_path, remote_path):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("DaytonaError('Failed to upload files: ')")
        return original_upload(local_path, remote_path)

    sandbox.fs.upload_file = flaky_upload
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    upload_tests_dir_to_daytona(sandbox, bundle, staging_dir="/tmp/verifier-stage")

    assert attempts == 2
    assert len(sandbox.fs.uploads) == 1
    assert "true" in sandbox.process.commands


def test_upload_tests_raises_original_transport_error_when_sandbox_is_dead(
    tmp_path, monkeypatch
):
    process = _FlakyUploadProcess(live=False)
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path)
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError) as exc_info:
        upload_tests_dir_to_daytona(sandbox, bundle, staging_dir="/tmp/verifier-stage")

    assert exc_info.value is process.transport_error
    assert process.extraction_attempts == 1
    assert process.liveness_attempts == 1


def test_daytona_harbor_verifier_quotes_remote_shell_paths(tmp_path):
    tests_dir = tmp_path / "tests dir"
    tests_dir.mkdir()
    test_path = tests_dir / "verify script.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    result = run_daytona_harbor_verifier(
        sandbox,
        bundle,
        remote_tests_dir="/tests dir",
        remote_logs_dir="/logs dir/verifier",
    )

    commands = sandbox.process.commands
    uploaded_remote_paths = [remote for _local, remote in sandbox.fs.uploads]
    assert result.value == 1.0
    assert result.verifier_identity == {
        "effective_uid": 0,
        "effective_user": "root",
    }
    assert len(uploaded_remote_paths) == 1
    staging_dir = uploaded_remote_paths[0].rsplit("/", 1)[0]
    assert staging_dir.startswith("/tmp/boundarybench-verifier-")
    assert uploaded_remote_paths == [f"{staging_dir}/tests.tar.gz"]
    assert any(
        f"mkdir -- {staging_dir}" in command
        and f"chmod 700 {staging_dir}" in command
        and f"chown 0:0 {staging_dir}" in command
        for command in commands
    )
    extraction_command = next(command for command in commands if "tar -xzf" in command)
    assert "test -f" in extraction_command
    assert "test ! -L" in extraction_command
    assert '"$(stat -c %u' in extraction_command
    assert "chmod 600" in extraction_command
    assert "umask 077" in extraction_command
    assert "rm -rf -- '/tests dir'" in extraction_command
    assert "install -d -m 700 -o 0 -g 0 '/tests dir'" in extraction_command
    assert f"tar -xzf {staging_dir}/tests.tar.gz -C '/tests dir'" in extraction_command
    assert "chown -R 0:0 '/tests dir'" in extraction_command
    assert "chmod -R go-rwx '/tests dir'" in extraction_command
    logs_command = next(
        command
        for command in commands
        if "install -d -m 700" in command and "/logs dir/verifier" in command
    )
    assert "rm -rf -- '/logs dir/verifier'" in logs_command
    assert "-o 0 -g 0 '/logs dir/verifier'" in logs_command
    verifier_command = next(
        command for command in commands if _VERIFIER_MARKER in command
    )
    assert "$(id -u)" in verifier_command
    assert verifier_command.endswith("cd /app && bash -l '/tests dir/verify script.sh'")
    assert not any("boundarybench-verifier-identity.json" in c for c in commands)
    assert "cat '/logs dir/verifier/reward.txt'" in commands
    assert commands[-1] == f"rm -rf -- {staging_dir}"


def test_daytona_harbor_verifier_drops_privileges_in_command(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
        verifier_user="daytona",
    )

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.verifier_identity == {
        "effective_uid": 1000,
        "effective_user": "daytona",
    }
    verifier_command = next(
        command for command in sandbox.process.commands if _VERIFIER_MARKER in command
    )
    assert verifier_command.startswith(
        "setpriv --reuid daytona --init-groups -- bash -lc "
    )
    assert verifier_command.endswith("cd /app && bash -l /tests/verify.sh'")


@pytest.mark.parametrize(
    "remote_workdir", ["/workspace", "/app/personal-site", "/app/dclm"]
)
def test_daytona_harbor_verifier_runs_from_task_workdir(tmp_path, remote_workdir):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    result = run_daytona_harbor_verifier(sandbox, bundle, remote_workdir=remote_workdir)

    assert result.to_metadata()["verifier_identity"] == {
        "effective_uid": 0,
        "effective_user": "root",
    }
    verifier_command = next(
        command for command in sandbox.process.commands if _VERIFIER_MARKER in command
    )
    assert verifier_command.endswith(f"cd {remote_workdir} && bash -l /tests/verify.sh")


def test_daytona_harbor_verifier_never_inherits_agent_user_site_packages(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    assert "include_daytona_user_site" not in inspect.signature(
        run_daytona_harbor_verifier
    ).parameters
    assert not hasattr(daytona_module, "_with_daytona_user_site_packages")

    run_daytona_harbor_verifier(sandbox, bundle)

    verifier_env = next(env for env in sandbox.process.envs if env.get("TEST_DIR"))
    assert "/home/daytona/.local" not in verifier_env.get("PYTHONPATH", "")
    assert verifier_env.get("HOME") == "/root"


def test_verifier_env_pins_home_to_root_but_lets_trusted_task_override(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")

    default_sandbox = _FakeDaytonaVerifierSandbox()
    run_daytona_harbor_verifier(
        default_sandbox,
        TerminalBenchTaskBundle(
            sample_id="sample",
            input="task",
            task_name="task",
            task_dir=tmp_path,
            tests_dir=tests_dir,
            test_path=test_path,
            verifier_timeout_sec=30,
        ),
    )
    default_env = next(
        env for env in default_sandbox.process.envs if env.get("TEST_DIR")
    )
    assert default_env.get("HOME") == "/root"

    override_sandbox = _FakeDaytonaVerifierSandbox()
    run_daytona_harbor_verifier(
        override_sandbox,
        TerminalBenchTaskBundle(
            sample_id="sample",
            input="task",
            task_name="task",
            task_dir=tmp_path,
            tests_dir=tests_dir,
            test_path=test_path,
            verifier_timeout_sec=30,
            verifier_env={"HOME": "/opt/harbor-home"},
        ),
    )
    override_env = next(
        env for env in override_sandbox.process.envs if env.get("TEST_DIR")
    )
    assert override_env.get("HOME") == "/opt/harbor-home"


def test_preinstalled_user_site_vectorops_cannot_satisfy_verifier_import(tmp_path):
    fake_user_site = tmp_path / "daytona-user-site"
    package_dir = fake_user_site / "vectorops"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")

    def probe_import(pythonpath: str | None) -> "subprocess.CompletedProcess[str]":
        probe_env = {"PATH": "/usr/bin:/bin"}
        if pythonpath:
            probe_env["PYTHONPATH"] = pythonpath
        return subprocess.run(
            [sys.executable, "-s", "-c", "import vectorops"],
            env=probe_env,
            capture_output=True,
            text=True,
            check=False,
        )

    contaminated = probe_import(str(fake_user_site))
    assert contaminated.returncode == 0, contaminated.stderr

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="pypi-server",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    run_daytona_harbor_verifier(sandbox, bundle)

    verifier_env = next(env for env in sandbox.process.envs if env.get("TEST_DIR"))
    agent_visible = ":".join(
        str(fake_user_site) if "/home/daytona/.local" in entry else entry
        for entry in verifier_env.get("PYTHONPATH", "").split(":")
        if entry
    )
    verifier_probe = probe_import(agent_visible or None)
    assert verifier_probe.returncode != 0
    assert "ModuleNotFoundError" in verifier_probe.stderr


def test_daytona_harbor_verifier_appends_git_safe_directory_without_global_mutation(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox()
    original_verifier_env = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/dev/null",
    }
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
        verifier_env=dict(original_verifier_env),
    )
    monkeypatch.setenv("PATH", "/agent/runtime/path")
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    run_daytona_harbor_verifier(
        sandbox,
        bundle,
        remote_workdir="/app/dclm",
    )

    verifier_env = next(env for env in sandbox.process.envs if env.get("TEST_DIR"))
    assert verifier_env["GIT_CONFIG_COUNT"] == "2"
    assert verifier_env["GIT_CONFIG_KEY_0"] == "core.hooksPath"
    assert verifier_env["GIT_CONFIG_VALUE_0"] == "/dev/null"
    assert verifier_env["GIT_CONFIG_KEY_1"] == "safe.directory"
    assert verifier_env["GIT_CONFIG_VALUE_1"] == "*"
    assert bundle.verifier_env == original_verifier_env
    assert os.environ["PATH"] == "/agent/runtime/path"
    assert "GIT_CONFIG_COUNT" not in os.environ


def test_daytona_harbor_verifier_stages_env_in_same_private_directory(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox(process=_SuccessfulSessionProcess())
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
        verifier_env={"SECRETISH": "value"},
    )

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.value == 1.0
    remote_uploads = [remote for _local, remote in sandbox.fs.uploads]
    assert len(remote_uploads) == 2
    staging_dirs = {remote.rsplit("/", 1)[0] for remote in remote_uploads}
    assert len(staging_dirs) == 1
    staging_dir = staging_dirs.pop()
    assert set(remote_uploads) == {
        f"{staging_dir}/tests.tar.gz",
        f"{staging_dir}/verifier-env.sh",
    }
    verifier_env = sandbox.fs.uploaded_contents[f"{staging_dir}/verifier-env.sh"]
    assert "export GIT_CONFIG_COUNT=1" in verifier_env
    assert "export GIT_CONFIG_KEY_0=safe.directory" in verifier_env
    assert "export GIT_CONFIG_VALUE_0='*'" in verifier_env
    env_validation = next(
        command
        for command in sandbox.process.commands
        if f"{staging_dir}/verifier-env.sh" in command and "stat -c %u" in command
    )
    assert "test -f" in env_validation
    assert "test ! -L" in env_validation
    assert "chmod 600" in env_validation
    assert sandbox.process.commands[-1] == f"rm -rf -- {staging_dir}"


def test_daytona_harbor_verifier_cleans_private_stage_when_reward_is_missing(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox(
        process=_FakeDaytonaVerifierProcess(reward_exit_code=1)
    )
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    with pytest.raises(FileNotFoundError, match="No reward file"):
        run_daytona_harbor_verifier(sandbox, bundle)

    staging_dir = sandbox.fs.uploads[0][1].rsplit("/", 1)[0]
    assert sandbox.process.commands[-1] == f"rm -rf -- {staging_dir}"


def test_daytona_harbor_verifier_session_timeout_is_verifier_error(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox(process=_FakeDaytonaVerifierSessionProcess())
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=1,
        verifier_env={"A": "B"},
    )
    times = iter([0.0, 2.0, 3.0])
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.value == 0.0
    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code is None
    assert "verifier timed out after 1s" in result.stdout
    assert any('kill "$signal"' in command for command in sandbox.process.commands)
    assert sandbox.process.deleted_sessions == ["ia-verifier-test"]


def test_daytona_harbor_verifier_timeout_stays_timed_out_when_term_exits_process(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox(
        process=_TerminatedDaytonaVerifierSessionProcess()
    )
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=1,
    )
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143
    assert "verifier timed out after 1s" in result.stdout
    signal_commands = [
        command for command in sandbox.process.commands if "signal=-" in command
    ]
    assert any("signal=-TERM" in command for command in signal_commands)
    assert not any("signal=-KILL" in command for command in signal_commands)


def test_daytona_harbor_verifier_retries_transient_poll_on_same_session(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    process = _RetryingDaytonaVerifierSessionProcess(
        [
            RuntimeError("DaytonaError('Failed to get session command: ')"),
            SimpleNamespace(exit_code=0),
        ]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "PASS"
    assert process.session_command_calls == [
        (process.created_session_id, "cmd-1"),
        (process.created_session_id, "cmd-1"),
    ]
    assert process.execute_session_command_calls == 1
    assert process.deleted_sessions == [process.created_session_id]


def test_daytona_harbor_verifier_stops_after_configured_transient_poll_attempts(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    transient_error = RuntimeError(
        "Failed to get session command: failed to resolve container IP"
    )
    process = _RetryingDaytonaVerifierSessionProcess(
        [transient_error, transient_error, SimpleNamespace(exit_code=0)]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="failed to resolve container IP"):
        run_daytona_harbor_verifier(sandbox, bundle)

    assert len(process.session_command_calls) == 2
    assert process.execute_session_command_calls == 1
    assert process.deleted_sessions == [process.created_session_id]


@pytest.mark.parametrize(
    "message",
    [
        "Failed to get session command: sandbox container not found: no such container",
        "Failed to get session command: permission denied",
    ],
)
def test_daytona_harbor_verifier_does_not_retry_terminal_poll_error(
    tmp_path, monkeypatch, message
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    process = _RetryingDaytonaVerifierSessionProcess(
        [RuntimeError(message), SimpleNamespace(exit_code=0)]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match=message):
        run_daytona_harbor_verifier(sandbox, bundle)

    assert len(process.session_command_calls) == 1
    assert process.execute_session_command_calls == 1
    assert process.deleted_sessions == [process.created_session_id]


def test_daytona_harbor_verifier_defaults_to_three_transient_poll_attempts(
    tmp_path, monkeypatch
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    transient_error = RuntimeError(
        "Failed to get session command: failed to resolve container IP"
    )
    process = _RetryingDaytonaVerifierSessionProcess(
        [
            transient_error,
            transient_error,
            transient_error,
            SimpleNamespace(exit_code=0),
        ]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )
    monkeypatch.delenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", raising=False)
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="failed to resolve container IP"):
        run_daytona_harbor_verifier(sandbox, bundle)

    assert len(process.session_command_calls) == 3


def test_daytona_harbor_verifier_stops_poll_retry_when_liveness_probe_fails(
    tmp_path, monkeypatch
):
    transient_error = RuntimeError(
        "Failed to get session command: failed to resolve container IP"
    )
    process = _RetryingDaytonaVerifierSessionProcess(
        [transient_error, SimpleNamespace(exit_code=0)], live=False
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path)
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError) as exc_info:
        run_daytona_harbor_verifier(sandbox, bundle)

    assert exc_info.value is transient_error
    assert len(process.session_command_calls) == 1
    assert process.liveness_attempts == 1
    assert process.execute_session_command_calls == 1


def test_daytona_harbor_verifier_deadline_includes_poll_retry_probe_and_sleep(
    tmp_path, monkeypatch
):
    transient_error = RuntimeError(
        "Failed to get session command: failed to resolve container IP"
    )
    process = _RetryingDaytonaVerifierSessionProcess(
        [transient_error, SimpleNamespace(exit_code=143)]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    clock = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "3")
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", fake_sleep)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143
    assert sleeps[0] == pytest.approx(1.0)
    assert len(process.session_command_calls) == 2
    assert process.liveness_attempts == 1


def test_daytona_harbor_verifier_rejects_completion_observed_after_deadline(
    tmp_path, monkeypatch
):
    process = _RetryingDaytonaVerifierSessionProcess(
        [SimpleNamespace(exit_code=0), SimpleNamespace(exit_code=143)]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143


def test_daytona_harbor_verifier_deadline_includes_dispatch_acknowledgement(
    tmp_path, monkeypatch
):
    clock = [0.0]

    class DelayedDispatchProcess(_RetryingDaytonaVerifierSessionProcess):
        def __init__(self):
            super().__init__([SimpleNamespace(exit_code=143)])
            self.dispatch_timeouts: list[int] = []

        def execute_session_command(self, session_id, request, timeout):
            self.dispatch_timeouts.append(timeout)
            clock[0] = 2.0
            return super().execute_session_command(session_id, request, timeout)

    process = DelayedDispatchProcess()
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143
    assert process.dispatch_timeouts == [1]
    assert len(process.session_command_calls) == 1


def test_daytona_harbor_verifier_dispatch_error_at_deadline_is_timeout(
    tmp_path, monkeypatch
):
    clock = [0.0]
    dispatch_error = RuntimeError("dispatch transport failed")

    class ExpiredDispatchErrorProcess(_RetryingDaytonaVerifierSessionProcess):
        def __init__(self):
            super().__init__([])

        def execute_session_command(self, session_id, request, timeout):
            self.execute_session_command_calls += 1
            clock[0] = 2.0
            raise dispatch_error

        def get_session_command(self, session_id, cmd_id):
            raise AssertionError("poll attempted without a command ID")

        def get_session_command_logs(self, session_id, cmd_id):
            raise AssertionError("logs requested without a command ID")

    process = ExpiredDispatchErrorProcess()
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code is None
    assert process.execute_session_command_calls == 1
    assert process.deleted_sessions == [process.created_session_id]
    signal_commands = [command for command in process.commands if "signal=-" in command]
    assert any("signal=-TERM" in command for command in signal_commands)
    assert any("signal=-KILL" in command for command in signal_commands)


def test_daytona_harbor_verifier_early_dispatch_error_preserves_original(
    tmp_path, monkeypatch
):
    clock = [0.0]
    dispatch_error = RuntimeError("dispatch rejected early")

    class EarlyDispatchErrorProcess(_RetryingDaytonaVerifierSessionProcess):
        def __init__(self):
            super().__init__([])

        def execute_session_command(self, session_id, request, timeout):
            self.execute_session_command_calls += 1
            raise dispatch_error

    process = EarlyDispatchErrorProcess()
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError) as exc_info:
        run_daytona_harbor_verifier(sandbox, bundle)

    assert exc_info.value is dispatch_error
    assert process.execute_session_command_calls == 1
    assert process.deleted_sessions == [process.created_session_id]
    assert not any("signal=-" in command for command in process.commands)


def test_daytona_harbor_verifier_expired_deadline_wins_over_poll_retry_exhaustion(
    tmp_path, monkeypatch
):
    clock = [0.0]
    transient_error = RuntimeError("DaytonaError('Failed to get session command: ')")

    class DelayedPollErrorProcess(_RetryingDaytonaVerifierSessionProcess):
        def get_session_command(self, session_id, cmd_id):
            result = next(self.session_command_results)
            self.session_command_calls.append((session_id, cmd_id))
            if isinstance(result, BaseException):
                clock[0] = 2.0
                raise result
            return result

    process = DelayedPollErrorProcess([transient_error, SimpleNamespace(exit_code=143)])
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "1")
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143
    assert len(process.session_command_calls) == 2
    assert process.liveness_attempts == 0


def test_daytona_harbor_verifier_expired_deadline_wins_over_failed_liveness(
    tmp_path, monkeypatch
):
    clock = [0.0]
    transient_error = RuntimeError("DaytonaError('Failed to get session command: ')")

    class DelayedFailedLivenessProcess(_RetryingDaytonaVerifierSessionProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            if command == "true":
                self.liveness_attempts += 1
                clock[0] = 2.0
                raise RuntimeError("sandbox container not found")
            return super().exec(command, timeout=timeout, env=env)

    process = DelayedFailedLivenessProcess(
        [transient_error, SimpleNamespace(exit_code=143)]
    )
    sandbox = _FakeDaytonaVerifierSandbox(process=process)
    bundle = _test_bundle(tmp_path, verifier_timeout_sec=1)
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", "2")
    monkeypatch.setattr(daytona_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(daytona_module.time, "sleep", lambda _seconds: None)

    result = run_daytona_harbor_verifier(sandbox, bundle)

    assert result.answer == "ERROR"
    assert result.timed_out is True
    assert result.exit_code == 143
    assert len(process.session_command_calls) == 2
    assert process.liveness_attempts == 1


@pytest.mark.parametrize("raw", ["not-an-integer", "0", "-2", "11"])
def test_verifier_max_attempts_rejects_invalid_values(monkeypatch, raw):
    monkeypatch.setenv("BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS", raw)

    with pytest.raises(
        ValueError,
        match=(
            "BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS must be an integer "
            "between 1 and 10"
        ),
    ):
        daytona_module.verifier_max_attempts()


def test_daytona_harbor_verifier_missing_reward_without_timeout_is_error(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    sandbox = _FakeDaytonaVerifierSandbox(
        process=_FakeDaytonaVerifierProcess(reward_exit_code=1)
    )
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )

    with pytest.raises(FileNotFoundError, match="No reward file"):
        run_daytona_harbor_verifier(sandbox, bundle)


@pytest.mark.parametrize(
    ("failure_phase", "expected_observations"),
    [
        ("staging", []),
        ("upload", []),
        ("reset", ["tests_uploaded_after_agent"]),
        ("pre_command", ["tests_uploaded_after_agent"]),
        (
            "command",
            ["tests_uploaded_after_agent", "verifier_process_started"],
        ),
    ],
)
def test_verifier_observations_report_only_completed_phase_boundaries(
    tmp_path, monkeypatch, failure_phase, expected_observations
):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    bundle = TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=30,
    )
    observations: list[str] = []

    def create_staging(sandbox):
        if failure_phase == "staging":
            raise RuntimeError("staging failed")
        return "/tmp/verifier-stage"

    def upload_tests(*args, **kwargs):
        if failure_phase == "upload":
            raise RuntimeError("upload failed")

    def reset_logs(*args, **kwargs):
        if failure_phase == "reset":
            raise RuntimeError("reset failed")

    def run_command(*args, on_process_started, **kwargs):
        if failure_phase == "pre_command":
            raise RuntimeError("pre-command failed")
        on_process_started()
        raise RuntimeError("command failed")

    monkeypatch.setattr(daytona_module, "_create_verifier_staging_dir", create_staging)
    monkeypatch.setattr(daytona_module, "upload_tests_dir_to_daytona", upload_tests)
    monkeypatch.setattr(daytona_module, "_reset_verifier_logs_dir", reset_logs)
    monkeypatch.setattr(
        daytona_module, "_run_verifier_command_with_deadline", run_command
    )
    monkeypatch.setattr(
        daytona_module, "_remove_verifier_staging_dir", lambda *args: None
    )

    with pytest.raises(RuntimeError):
        run_daytona_harbor_verifier(
            object(),
            bundle,
            observation_callback=observations.append,
        )

    assert observations == expected_observations


def test_fallback_verifier_exec_does_not_report_start_on_transport_failure():
    observations: list[str] = []

    class RaisingProcess:
        def exec(self, *args, **kwargs):
            raise RuntimeError("command transport failed")

    sandbox = type("Sandbox", (), {"process": RaisingProcess()})()

    with pytest.raises(RuntimeError, match="command transport failed"):
        daytona_module._run_verifier_command_with_deadline(
            sandbox,
            command="bash /tests/verify.sh",
            timeout=30,
            env={},
            timeout_markers=("/tests/verify.sh",),
            staging_dir="/tmp/verifier-stage",
            on_process_started=lambda: observations.append("verifier_process_started"),
        )

    assert observations == []


@pytest.mark.parametrize("exit_code", [0, 17])
def test_fallback_verifier_exec_reports_start_after_acknowledged_result(exit_code):
    observations: list[str] = []

    class ReturningProcess:
        def exec(self, *args, **kwargs):
            return _FakeDaytonaVerifierExecResult(
                exit_code=exit_code,
                result="verifier output",
            )

    sandbox = type("Sandbox", (), {"process": ReturningProcess()})()

    result = daytona_module._run_verifier_command_with_deadline(
        sandbox,
        command="bash /tests/verify.sh",
        timeout=30,
        env={},
        timeout_markers=("/tests/verify.sh",),
        staging_dir="/tmp/verifier-stage",
        on_process_started=lambda: observations.append("verifier_process_started"),
    )

    assert result.exit_code == exit_code
    assert result.stdout == "verifier output"
    assert observations == ["verifier_process_started"]


class _FakeDaytonaVerifierFs:
    def __init__(self) -> None:
        self.uploads: list[tuple[str, str]] = []
        self.uploaded_contents: dict[str, str] = {}

    def upload_file(self, _local_path, _remote_path):
        self.uploads.append((_local_path, _remote_path))
        if str(_remote_path).endswith("/verifier-env.sh"):
            self.uploaded_contents[_remote_path] = Path(_local_path).read_text(
                encoding="utf-8"
            )
        return None


class _FakeDaytonaVerifierExecResult:
    def __init__(self, *, exit_code: int = 0, result: str = "") -> None:
        self.exit_code = exit_code
        self.result = result


class _FakeDaytonaVerifierProcess:
    def __init__(self, *, reward_exit_code: int = 0) -> None:
        self.commands: list[str] = []
        self.envs: list[dict[str, str]] = []
        self.reward_exit_code = reward_exit_code

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        self.envs.append(dict(env or {}))
        if "__BOUNDARYBENCH_VERIFIER_IDENTITY__" in command:
            if "setpriv --reuid daytona" in command:
                return _FakeDaytonaVerifierExecResult(
                    result=(
                        "__BOUNDARYBENCH_VERIFIER_IDENTITY__ "
                        "effective_uid=1000 effective_user=daytona\n"
                    )
                )
            return _FakeDaytonaVerifierExecResult(
                result=(
                    "__BOUNDARYBENCH_VERIFIER_IDENTITY__ "
                    "effective_uid=0 effective_user=root\n"
                )
            )
        if command.startswith("cat "):
            return _FakeDaytonaVerifierExecResult(
                exit_code=self.reward_exit_code,
                result="1.0\n" if self.reward_exit_code == 0 else "",
            )
        return _FakeDaytonaVerifierExecResult()


class _FlakyUploadProcess(_FakeDaytonaVerifierProcess):
    def __init__(self, *, live: bool) -> None:
        super().__init__()
        self.live = live
        self.transport_error = RuntimeError(
            "DaytonaError('Failed to execute command: ')"
        )
        self.extraction_attempts = 0
        self.liveness_attempts = 0

    def exec(self, command: str, *, timeout: int, env=None):
        if command == "true":
            self.liveness_attempts += 1
            if not self.live:
                raise RuntimeError("sandbox container not found")
            return _FakeDaytonaVerifierExecResult()
        if "tar -xzf" in command:
            self.extraction_attempts += 1
            if self.extraction_attempts == 1:
                raise self.transport_error
        return super().exec(command, timeout=timeout, env=env)


class _FakeDaytonaVerifierSessionProcess(_FakeDaytonaVerifierProcess):
    def __init__(self) -> None:
        super().__init__(reward_exit_code=1)
        self.deleted_sessions: list[str] = []

    def create_session(self, session_id: str) -> None:
        assert session_id.startswith("ia-verifier-")

    def execute_session_command(self, session_id, request, timeout):
        assert request.run_async is True
        assert "bash -l /tests/verify.sh" in request.command
        return SimpleNamespace(cmd_id="cmd-1")

    def get_session_command(self, session_id, cmd_id):
        return SimpleNamespace(exit_code=None)

    def get_session_command_logs(self, session_id, cmd_id):
        return SimpleNamespace(stdout="verifier output before timeout")

    def delete_session(self, session_id: str) -> None:
        self.deleted_sessions.append("ia-verifier-test")


class _TerminatedDaytonaVerifierSessionProcess(_FakeDaytonaVerifierSessionProcess):
    def __init__(self) -> None:
        super().__init__()
        self.poll_count = 0

    def get_session_command(self, session_id, cmd_id):
        self.poll_count += 1
        return SimpleNamespace(exit_code=None if self.poll_count == 1 else 143)


class _SuccessfulSessionProcess(_FakeDaytonaVerifierSessionProcess):
    def __init__(self) -> None:
        super().__init__()
        self.reward_exit_code = 0

    def get_session_command(self, session_id, cmd_id):
        return SimpleNamespace(exit_code=0)

    def get_session_command_logs(self, session_id, cmd_id):
        return SimpleNamespace(
            stdout=(
                "__BOUNDARYBENCH_VERIFIER_IDENTITY__ "
                "effective_uid=0 effective_user=root\n"
            )
        )


class _RetryingDaytonaVerifierSessionProcess(_SuccessfulSessionProcess):
    def __init__(self, session_command_results, *, live: bool = True) -> None:
        super().__init__()
        self.session_command_results = iter(session_command_results)
        self.live = live
        self.liveness_attempts = 0
        self.session_command_calls: list[tuple[str, str]] = []
        self.execute_session_command_calls = 0
        self.created_session_id = ""

    def create_session(self, session_id: str) -> None:
        self.created_session_id = session_id
        super().create_session(session_id)

    def execute_session_command(self, session_id, request, timeout):
        self.execute_session_command_calls += 1
        return super().execute_session_command(session_id, request, timeout)

    def get_session_command(self, session_id, cmd_id):
        self.session_command_calls.append((session_id, cmd_id))
        result = next(self.session_command_results)
        if isinstance(result, BaseException):
            raise result
        return result

    def exec(self, command: str, *, timeout: int, env=None):
        if command == "true":
            self.liveness_attempts += 1
            if not self.live:
                raise RuntimeError("sandbox container not found")
            return _FakeDaytonaVerifierExecResult()
        return super().exec(command, timeout=timeout, env=env)

    def delete_session(self, session_id: str) -> None:
        self.deleted_sessions.append(session_id)


class _FakeDaytonaVerifierSandbox:
    def __init__(self, *, process=None) -> None:
        self.fs = _FakeDaytonaVerifierFs()
        self.process = process or _FakeDaytonaVerifierProcess()


def _test_bundle(tmp_path, *, verifier_timeout_sec: int = 30):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "verify.sh"
    test_path.write_text("echo ok\n", encoding="utf-8")
    return TerminalBenchTaskBundle(
        sample_id="sample",
        input="task",
        task_name="task",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=verifier_timeout_sec,
    )
