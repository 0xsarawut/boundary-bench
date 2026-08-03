from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

import pytest

from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaCommandResult,
    DaytonaPolicyHardening,
    wrap_command_for_agentsh_session,
)
from boundarybench.daytona.apparmor_capability import (
    DEFAULT_APPARMOR_DENIED_PATH,
    DEFAULT_APPARMOR_PROBE_WORKSPACE,
)
from boundarybench.daytona.runtime_policy_probes import (
    RUNTIME_POLICY_PROBE_WORKSPACE,
)
from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.terminus_2 import (
    TERMINUS_REQUIREMENTS_LOCK_PATH,
    Terminus2Adapter,
)
from boundarybench.terminalbench.daytona import (
    DaytonaVerifierResult,
    TerminalBenchTaskBundle,
)
from boundarybench.terminalbench.policies import resolve_policy
from boundarybench.terminalbench.daytona_constants import (
    CLAUDE_BIN,
    DAYTONA_CLAUDE_BIN,
    DEFAULT_AGENT_TIMEOUT_SEC,
    DEFAULT_HARDENING_ASSET_DIR,
    REMOTE_ALLOWED_DOMAINS_PATH,
    REMOTE_PROMPT_PATH,
    SANDBOX_AUTO_DELETE_MIN,
    SANDBOX_AUTO_STOP_MIN,
    SANDBOX_LABELS,
    SANDBOX_MANAGED_BY_LABEL,
    SANDBOX_MANAGED_BY_VALUE,
    SANDBOX_NAMESPACE_LABEL,
    SANDBOX_RUN_ID_LABEL,
    ROOT_CLAUDE_BIN,
)
from boundarybench.terminalbench.daytona_runtime_layer import (
    render_clean_verifier_runtime_layer_script,
    render_sandbox_setup_script,
)
from boundarybench.terminalbench.daytona_run import (
    PRESERVE_AGENT_SESSION_ENV,
    MAX_VERIFIER_ARTIFACT_FILE_BYTES,
    MAX_VERIFIER_ARTIFACT_FILES,
    MAX_VERIFIER_ARTIFACT_TOTAL_BYTES,
    VerifierArtifact,
    _sandbox_auto_stop_min,
    _sandbox_create_labels,
    cleanup_verifier_artifacts,
    daytona_task_resource_attempts,
    daytona_task_resources,
    export_verifier_artifacts,
    import_verifier_artifacts,
    provision_clean_verifier_sandbox,
    reap_stale_terminalbench_sandboxes,
    provision_hardened_task_sandbox,
    remove_pre_agent_setup_artifacts,
    run_terminalbench_agent_in_daytona,
    run_terminalbench_task_in_daytona,
    task_docker_image,
    validate_openrouter_model_id,
    AGENT_LISTENER_PROBE_COMMAND,
    MODEL_AGENT_SESSION_PREFIX,
)
from boundarybench.terminalbench.daytona_transcript import (
    render_task_transcript_markdown,
)


def _native_hardening() -> DaytonaPolicyHardening:
    """Hardening handle carrying a real native (axes) config for exec renders."""

    from boundarybench.daytona.policy_axes import (
        AXIS_PRESETS,
        build_daytona_config_from_axes,
    )

    return DaytonaPolicyHardening(
        asset_dir=DEFAULT_HARDENING_ASSET_DIR,
        policy_message_preload_so=f"{DEFAULT_HARDENING_ASSET_DIR}/policy.so",
        block_message_command=f"{DEFAULT_HARDENING_ASSET_DIR}/deny.sh",
        mount_real_path=f"{DEFAULT_HARDENING_ASSET_DIR}/mount.real",
        policy_bin_dir=f"{DEFAULT_HARDENING_ASSET_DIR}/bin",
        child_network_block_env=f"{DEFAULT_HARDENING_ASSET_DIR}/child_net",
        hardening_config=build_daytona_config_from_axes(AXIS_PRESETS["low-nist"]),
    )


def _claude_agent_command(model: str, *, run_as_root: bool = False) -> str:
    return ClaudeCodeAdapter().agent_command(
        model=model,
        prompt_path="/tmp/boundarybench-task-prompt.txt",
        run_as_root=run_as_root,
    )


class _FakeResult:
    def __init__(self, exit_code: int, result: str) -> None:
        self.exit_code = exit_code
        self.result = result


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.envs: list[dict[str, str] | None] = []

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        self.envs.append(env)
        if "reward.txt" in command:
            return _FakeResult(0, "1.0\n")
        if DAYTONA_CLAUDE_BIN in command or ROOT_CLAUDE_BIN in command:
            return _FakeResult(0, '{"type":"result","subtype":"success"}')
        return _FakeResult(0, "ok")


class _FakeFs:
    def __init__(self) -> None:
        self.uploads: list[tuple[str, str]] = []
        self.uploaded_contents: dict[str, bytes] = {}
        self.downloads: list[tuple[str, str]] = []
        self.uploaded_content: dict[str, str] = {}

    def upload_file(self, local_path: str, remote_path: str) -> None:
        self.uploads.append((local_path, remote_path))
        self.uploaded_contents[remote_path] = Path(local_path).read_bytes()
        try:
            self.uploaded_content[remote_path] = Path(local_path).read_text()
        except (OSError, UnicodeError):
            pass

    def download_file(self, remote_path: str, local_path: str, timeout: int) -> None:
        self.downloads.append((remote_path, local_path))
        Path(local_path).write_bytes(b"submission archive")


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()
        self.fs = _FakeFs()


class _FakeDaytonaCreate:
    def __init__(self) -> None:
        self.params = None
        self.timeout = None
        self.sandbox = _FakeSandbox()

    def create(self, params, *, timeout: int):
        self.params = params
        self.timeout = timeout
        return self.sandbox

    def delete(self, sandbox):
        pass


class _RecordingDaytonaCreate(_FakeDaytonaCreate):
    def __init__(self) -> None:
        super().__init__()
        self.deleted: list[_FakeSandbox] = []

    def delete(self, sandbox):
        self.deleted.append(sandbox)


class _ArtifactFs(_FakeFs):
    def __init__(self, remote_files: dict[str, bytes] | None = None) -> None:
        super().__init__()
        self.remote_files = remote_files or {}
        self.uploaded_bytes: dict[str, bytes] = {}

    def upload_file(self, local_path: str, remote_path: str) -> None:
        super().upload_file(local_path, remote_path)
        self.uploaded_bytes[remote_path] = Path(local_path).read_bytes()

    def download_file(self, remote_path: str, local_path: str, timeout: int) -> None:
        self.downloads.append((remote_path, local_path))
        content = self.remote_files.get(remote_path)
        if content is None:
            index = int(Path(remote_path).name)
            content = list(self.remote_files.values())[index]
        Path(local_path).write_bytes(content)


class _ArtifactProcess(_FakeProcess):
    def __init__(self, artifact_fs: _ArtifactFs) -> None:
        super().__init__()
        self.artifact_fs = artifact_fs

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        self.envs.append(env)
        if "capture_verifier_artifacts.py" in command and "python3" in command:
            artifacts = [
                {
                    "index": index,
                    "staged_name": f"{index:06d}",
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for index, content in enumerate(self.artifact_fs.remote_files.values())
            ]
            return _FakeResult(
                0,
                json.dumps(
                    {
                        "version": 1,
                        "file_count": len(artifacts),
                        "total_bytes": sum(item["size_bytes"] for item in artifacts),
                        "artifacts": artifacts,
                    }
                ),
            )
        return _FakeResult(0, "ok")


class _ArtifactSandbox(_FakeSandbox):
    def __init__(self, remote_files: dict[str, bytes] | None = None) -> None:
        super().__init__()
        self.fs = _ArtifactFs(remote_files)
        self.process = _ArtifactProcess(self.fs)


def _bundle(tmp_path: Path) -> TerminalBenchTaskBundle:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_path = tests_dir / "test.sh"
    test_path.write_text("echo verifying\n")
    return TerminalBenchTaskBundle(
        sample_id="terminal-bench/example",
        input="Fix the failing build.",
        task_name="terminal-bench/example",
        task_dir=tmp_path,
        tests_dir=tests_dir,
        test_path=test_path,
        verifier_timeout_sec=120,
    )


def _hardening() -> DaytonaPolicyHardening:
    return DaytonaPolicyHardening(
        asset_dir="/opt/h",
        policy_message_preload_so="/opt/h/policy.so",
        block_message_command="/opt/h/deny.sh",
        mount_real_path="/opt/h/mount.real",
        policy_bin_dir="/opt/h/bin",
        child_network_block_env="/opt/h/child_net",
    )


def test_claude_agent_command_uses_full_path_and_openrouter_model():
    command = _claude_agent_command("minimax/minimax-m3")
    assert command.startswith(DAYTONA_CLAUDE_BIN)
    assert "minimax/minimax-m3" in command
    assert "--permission-mode bypassPermissions" in command
    assert "--dangerously-skip-permissions" not in command
    assert "--output-format stream-json" in command
    assert "$(cat /tmp/boundarybench-task-prompt.txt)" in command


def test_claude_agent_command_terminates_options_before_prompt():
    command = ClaudeCodeAdapter().agent_command(
        model="minimax/minimax-m3",
        prompt_path="/tmp/leading-dash-prompt.txt",
        run_as_root=False,
    )
    prompt_marker = '-p -- "$(cat /tmp/leading-dash-prompt.txt)"'

    assert prompt_marker in command
    assert command.index("--model minimax/minimax-m3") < command.index(prompt_marker)
    assert command.index("--permission-mode bypassPermissions") < command.index(
        prompt_marker
    )
    assert command.index("--output-format stream-json") < command.index(prompt_marker)
    assert command.endswith("< /dev/null")


def test_claude_agent_command_rejects_shell_metacharacters():
    with pytest.raises(ValueError):
        _claude_agent_command("minimax/minimax-m3; touch /tmp/pwned")


def test_validate_openrouter_model_id_allows_expected_slug_chars():
    assert (
        validate_openrouter_model_id("anthropic/claude-3.5-haiku:beta")
        == "anthropic/claude-3.5-haiku:beta"
    )


def test_claude_agent_command_uses_root_sandbox_mode_for_none_policy():
    command = _claude_agent_command("minimax/minimax-m3", run_as_root=True)
    assert command.startswith(ROOT_CLAUDE_BIN)
    assert "--dangerously-skip-permissions" in command
    assert "--permission-mode bypassPermissions" not in command


def test_policy_selection_sets_expected_agent_privilege_modes():
    assert resolve_policy("control").overlays == ()
    assert resolve_policy("control").run_agent_as_root is True
    assert resolve_policy("non-root").overlays == ()
    assert resolve_policy("non-root").run_agent_as_root is False
    assert resolve_policy("low-nist").run_agent_as_root is False
    assert resolve_policy("control").block_child_shell_network is False
    assert resolve_policy("non-root").block_child_shell_network is False
    assert resolve_policy("low-nist").block_child_shell_network is False
    assert resolve_policy("non-root").debug_only is False


def test_sandbox_setup_script_is_portable_across_common_task_images():
    base_resource = (
        files("boundarybench.terminalbench")
        .joinpath("scripts", "sandbox_base.sh")
        .read_text(encoding="utf-8")
    )
    script = render_sandbox_setup_script(
        workdir="/app",
        run_agent_as_root=False,
        harness=ClaudeCodeAdapter(),
    )

    assert "command -v bash" in base_resource
    assert "/usr/bin/bash" not in script
    assert "apt-get" in script
    assert "apk add" in script
    assert "dnf install" in script
    assert "python3" in script
    assert "python3-dev" in script
    assert "linux-headers" in script
    assert 'mkdir -p "$WORKDIR"' in script
    assert "RUN_AGENT_AS_ROOT" in script
    assert "SANDBOX_BASE_OK" in script
    assert "HARNESS_INSTALL_OK" in script
    assert "RUNTIME_LAYER_OK" in script


@pytest.mark.parametrize(
    (
        "succeed_on_attempt",
        "expected_returncode",
        "expected_attempts",
        "expected_delays",
    ),
    [
        (2, 0, 2, ["2"]),
        (4, 1, 3, ["2", "4"]),
    ],
)
def test_sandbox_base_retries_apt_with_bounded_backoff(
    tmp_path,
    succeed_on_attempt,
    expected_returncode,
    expected_attempts,
    expected_delays,
):
    base_resource = (
        files("boundarybench.terminalbench")
        .joinpath("scripts", "sandbox_base.sh")
        .read_text(encoding="utf-8")
    )
    function_definitions = base_resource.split("\ninstall_runtime_packages\n", 1)[0]

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    attempt_file = tmp_path / "apt-attempts"
    args_file = tmp_path / "apt-args"
    sleep_file = tmp_path / "sleep-delays"
    (fake_bin / "apt-get").write_text(
        """#!/bin/sh
attempt=$(cat "$APT_ATTEMPT_FILE" 2>/dev/null || printf '0')
attempt=$((attempt + 1))
printf '%s' "$attempt" >"$APT_ATTEMPT_FILE"
printf '%s\n' "$*" >>"$APT_ARGS_FILE"
[ "$attempt" -ge "$APT_SUCCEED_ON_ATTEMPT" ]
""",
        encoding="utf-8",
    )
    (fake_bin / "sleep").write_text(
        """#!/bin/sh
printf '%s\n' "$*" >>"$APT_SLEEP_FILE"
""",
        encoding="utf-8",
    )
    (fake_bin / "apt-get").chmod(0o755)
    (fake_bin / "sleep").chmod(0o755)

    result = subprocess.run(
        ["sh", "-c", f"{function_definitions}\nretry_apt_get install -y curl"],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "APT_ATTEMPT_FILE": str(attempt_file),
            "APT_ARGS_FILE": str(args_file),
            "APT_SLEEP_FILE": str(sleep_file),
            "APT_SUCCEED_ON_ATTEMPT": str(succeed_on_attempt),
        },
    )

    assert result.returncode == expected_returncode, result.stderr
    assert attempt_file.read_text(encoding="utf-8") == str(expected_attempts)
    assert sleep_file.read_text(encoding="utf-8").splitlines() == expected_delays
    assert (
        args_file.read_text(encoding="utf-8").splitlines()
        == ["install -y curl"] * expected_attempts
    )
    assert "apt-get failed (attempt 1/3); retrying in 2s" in result.stderr
    if expected_returncode:
        assert "apt-get failed after 3 attempts" in result.stderr


def test_task_docker_image_reads_environment_section(tmp_path):
    (tmp_path / "task.toml").write_text(
        '[environment]\ndocker_image = "registry/example:1"\n'
    )
    bundle = _bundle(tmp_path)
    assert task_docker_image(bundle) == "registry/example:1"


def test_task_environment_metadata_preserves_task_toml_docker_image(tmp_path):
    (tmp_path / "task.toml").write_text(
        "\n".join(
            [
                "[environment]",
                'docker_image = "registry/example:1"',
                "cpus = 1",
                "memory_mb = 2048",
                "storage_mb = 3072",
                "gpus = 0",
            ]
        )
    )
    bundle = _bundle(tmp_path)
    bundle.metadata["environment"] = {
        "memory_mb": 4096,
        "storage_mb": 10240,
    }

    assert task_docker_image(bundle) == "registry/example:1"
    assert _resource_tuple(daytona_task_resources(bundle)) == (1, 2, 3, None)


def _resource_tuple(resources):
    return (resources.cpu, resources.memory, resources.disk, resources.gpu)


def test_daytona_task_resources_requires_terminalbench_task_resources(
    tmp_path,
):
    (tmp_path / "task.toml").write_text(
        '[environment]\ndocker_image = "registry/example:1"\n'
    )
    bundle = _bundle(tmp_path)

    with pytest.raises(ValueError, match="environment.cpus"):
        daytona_task_resources(bundle)


def test_daytona_task_resources_uses_declared_common_tb_profile(tmp_path):
    (tmp_path / "task.toml").write_text(
        "\n".join(
            [
                "[environment]",
                'docker_image = "registry/example:1"',
                "cpus = 1",
                "memory_mb = 2048",
                "storage_mb = 10240",
                "gpus = 0",
            ]
        )
    )
    bundle = _bundle(tmp_path)

    assert _resource_tuple(daytona_task_resources(bundle)) == (1, 2, 10, None)
    assert [_resource_tuple(r) for r in daytona_task_resource_attempts(bundle)] == [
        (1, 2, 10, None)
    ]


def test_daytona_task_resources_reads_terminalbench_environment_requirements(tmp_path):
    (tmp_path / "task.toml").write_text(
        "\n".join(
            [
                "[environment]",
                'docker_image = "registry/example:1"',
                "cpus = 4",
                "memory_mb = 8192",
                "storage_mb = 10240",
                "gpus = 1",
            ]
        )
    )
    bundle = _bundle(tmp_path)

    resources = daytona_task_resources(bundle)

    assert resources is not None
    assert _resource_tuple(resources) == (4, 8, 10, 1)


def test_provision_hardened_task_sandbox_uses_minimal_profile_by_default(capsys):
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        resources=None,
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
    )

    assert daytona.params.resources is None
    captured = capsys.readouterr()
    assert "phase_timing component=terminalbench_daytona" in captured.out
    assert "phase=sandbox_create" in captured.out
    assert "phase=runtime_layer_install" in captured.out
    assert "phase=sandbox_provision_total" in captured.out


def test_provision_hardened_task_sandbox_passes_dynamic_resources(tmp_path):
    daytona = _FakeDaytonaCreate()
    (tmp_path / "task.toml").write_text(
        "\n".join(
            [
                "[environment]",
                'docker_image = "alexgshaw/caffe-cifar-10:20260403"',
                "cpus = 4",
                "memory_mb = 8192",
                "storage_mb = 10240",
                "gpus = 0",
            ]
        ),
        encoding="utf-8",
    )
    resources = daytona_task_resources(
        TerminalBenchTaskBundle(
            sample_id="terminal-bench/caffe-cifar-10",
            input="Train caffe.",
            task_name="terminal-bench/caffe-cifar-10",
            task_dir=tmp_path,
            tests_dir=tmp_path,
            test_path=tmp_path / "test.sh",
            verifier_timeout_sec=1200,
        )
    )

    provision_hardened_task_sandbox(
        daytona,
        image="alexgshaw/caffe-cifar-10:20260403",
        resources=resources,
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
    )

    assert daytona.params.resources is resources


def test_sandbox_auto_stop_extends_for_long_terminalbench_timeouts():
    assert _sandbox_auto_stop_min(3600) == 90
    assert _sandbox_auto_stop_min(7200) == 150
    assert _sandbox_auto_stop_min(12000) == 230


def test_provision_hardened_task_sandbox_extends_auto_stop_for_long_agent_timeout():
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/long-agent:1",
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
        command_timeout_sec=12000,
    )

    assert daytona.params.auto_stop_interval == 230


def test_provision_hardened_task_sandbox_uses_split_runtime_layer_for_harness():
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
    )

    setup_script = daytona.sandbox.process.commands[0]
    verify_command = daytona.sandbox.process.commands[1]
    assert "SANDBOX_BASE_OK" in setup_script
    assert "HARNESS_INSTALL_OK" in setup_script
    assert "RUNTIME_LAYER_OK" in setup_script
    assert "install_claude_for_daytona" in setup_script
    assert "chown -R daytona:daytona" in setup_script
    assert verify_command == f"test -x {DAYTONA_CLAUDE_BIN}"


def test_provision_uploads_large_terminus_lock_outside_setup_command():
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        install_policy_hardening=False,
        harness=Terminus2Adapter(),
    )

    setup_script = daytona.sandbox.process.commands[0]
    lock = daytona.sandbox.fs.uploaded_contents[TERMINUS_REQUIREMENTS_LOCK_PATH]
    assert b"harbor==0.13.1" in lock
    assert b"--hash=sha256:" in lock
    assert len(setup_script.encode()) < 128 * 1024
    assert "--hash=sha256:" not in setup_script
    assert "__TERMINUS_REQUIREMENTS_LOCK__" not in setup_script
    assert TERMINUS_REQUIREMENTS_LOCK_PATH in setup_script
    assert "pip sync --require-hashes" in setup_script


def test_provision_hardened_task_sandbox_uses_root_harness_binary_when_root():
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        run_agent_as_root=True,
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
    )

    setup_script = daytona.sandbox.process.commands[0]
    verify_command = daytona.sandbox.process.commands[1]
    assert "RUN_AGENT_AS_ROOT=1" in setup_script
    assert "install_claude_for_root" in setup_script
    assert 'if [ "$RUN_AGENT_AS_ROOT" != "1" ]; then' in setup_script
    assert verify_command == f"test -x {ROOT_CLAUDE_BIN}"


def test_provision_hardened_task_sandbox_writes_recovery_bundle_before_hardening(
    capsys, monkeypatch
):
    import boundarybench.terminalbench.daytona_run as daytona_run_module

    events: list[tuple[str, ...]] = []

    class _OrderedProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            events.append(("exec", command))
            return super().exec(command, timeout=timeout, env=env)

    class _OrderedFs(_FakeFs):
        def upload_file(self, local_path: str, remote_path: str) -> None:
            events.append(("upload", remote_path, Path(local_path).read_text()))
            super().upload_file(local_path, remote_path)

    class _OrderedSandbox(_FakeSandbox):
        def __init__(self) -> None:
            super().__init__()
            self.process = _OrderedProcess()
            self.fs = _OrderedFs()

    class _OrderedDaytona(_FakeDaytonaCreate):
        def __init__(self) -> None:
            super().__init__()
            self.sandbox = _OrderedSandbox()

    def _spy_install(sandbox, asset_dir, **kwargs):
        events.append(("hardening", ""))
        return None

    monkeypatch.setattr(
        daytona_run_module, "install_daytona_policy_hardening", _spy_install
    )

    daytona = _OrderedDaytona()
    remote_path = "/home/daytona/.claude/skills/policy-error-recovery/SKILL.md"
    parent = "/home/daytona/.claude/skills/policy-error-recovery"

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        harness=ClaudeCodeAdapter(),
        recovery_bundle_files=[(remote_path, "BODY", "644")],
    )

    def _first(predicate) -> int:
        return next(i for i, event in enumerate(events) if predicate(event))

    mkdir_cmd = f"mkdir -p {shlex.quote(parent)}"
    chmod_cmd = f"chmod {shlex.quote('644')} {shlex.quote(remote_path)}"
    chown_cmd = f"chown {shlex.quote('daytona')}: {shlex.quote(remote_path)}"

    mkdir_pos = _first(lambda e: e == ("exec", mkdir_cmd))
    upload_pos = _first(
        lambda e: e[0] == "upload" and e[1] == remote_path and e[2] == "BODY"
    )
    chmod_pos = _first(lambda e: e == ("exec", chmod_cmd))
    chown_pos = _first(lambda e: e == ("exec", chown_cmd))
    hardening_pos = _first(lambda e: e[0] == "hardening")

    assert mkdir_pos < upload_pos < chmod_pos < chown_pos < hardening_pos

    captured = capsys.readouterr()
    recovery_lines = [
        line
        for line in captured.out.splitlines()
        if "phase=recovery_bundle_write" in line
    ]
    assert len(recovery_lines) == 1
    assert "status=success" in recovery_lines[0]


def test_provision_hardened_task_sandbox_recovery_bundle_none_is_noop(capsys):
    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        install_policy_hardening=False,
        harness=ClaudeCodeAdapter(),
        recovery_bundle_files=None,
    )

    captured = capsys.readouterr()
    assert "phase=recovery_bundle_write" not in captured.out
    assert not any(
        "policy-error-recovery" in remote_path
        for _, remote_path in daytona.sandbox.fs.uploads
    )
    assert not any(
        "policy-error-recovery" in command
        for command in daytona.sandbox.process.commands
    )


def test_clean_verifier_runtime_layer_prepares_only_verifier_dependencies():
    script = render_clean_verifier_runtime_layer_script(workdir="/workspace/task")

    assert "CLEAN_VERIFIER_RUNTIME_OK" in script
    assert "WORKDIR=/workspace/task" in script
    assert "install_claude_for_daytona" not in script
    assert "HARNESS_INSTALL_OK" not in script
    assert "policy-hardening" not in script
    assert "VERIFIER_USER" not in script
    assert "useradd" not in script


def test_provision_clean_verifier_sandbox_rejects_non_root_user_before_create():
    daytona = _RecordingDaytonaCreate()

    with pytest.raises(ValueError, match="root verifier"):
        provision_clean_verifier_sandbox(
            daytona,
            image="registry/example:1",
            verifier_user="daytona",
        )

    assert daytona.params is None


def test_provision_clean_verifier_sandbox_reuses_image_and_resources():
    from daytona_sdk.common.sandbox import Resources

    daytona = _RecordingDaytonaCreate()
    resources = Resources(cpu=1, memory=2, disk=3)

    sandbox = provision_clean_verifier_sandbox(
        daytona,
        image="registry/example:1",
        resources=resources,
        workdir="/workspace/task",
        command_timeout_sec=1200,
    )

    assert sandbox is daytona.sandbox
    assert daytona.params.image == "registry/example:1"
    assert daytona.params.resources is resources
    assert daytona.params.auto_stop_interval == _sandbox_auto_stop_min(1200)
    assert "CLEAN_VERIFIER_RUNTIME_OK" in sandbox.process.commands[0]
    assert daytona.deleted == []


def test_provision_clean_verifier_sandbox_deletes_partial_setup_on_failure():
    daytona = _RecordingDaytonaCreate()
    daytona.sandbox.process.exec = lambda *args, **kwargs: _FakeResult(1, "boom")

    with pytest.raises(RuntimeError, match="clean verifier runtime layering failed"):
        provision_clean_verifier_sandbox(
            daytona,
            image="registry/example:1",
            workdir="/app",
        )

    assert daytona.deleted == [daytona.sandbox]


def test_provision_clean_verifier_sandbox_surfaces_setup_and_delete_failures():
    daytona = _RecordingDaytonaCreate()
    daytona.sandbox.process.exec = lambda *args, **kwargs: _FakeResult(1, "setup boom")

    def fail_delete(sandbox):
        daytona.deleted.append(sandbox)
        raise RuntimeError("delete boom")

    daytona.delete = fail_delete

    with pytest.raises(
        ExceptionGroup, match="clean verifier setup and cleanup failed"
    ) as exc:
        provision_clean_verifier_sandbox(
            daytona,
            image="registry/example:1",
            workdir="/app",
        )

    assert [str(error) for error in exc.value.exceptions] == [
        "clean verifier runtime layering failed: setup boom",
        "delete boom",
    ]
    assert daytona.deleted == [daytona.sandbox]


def test_export_and_import_verifier_artifacts_preserve_paths_and_metadata():
    source = _ArtifactSandbox(
        {
            "/app/result.json": b'{"status":"ok"}\n',
            "/app/build/output.bin": b"\x00\x01\x02",
        }
    )

    snapshot = export_verifier_artifacts(
        source,
        ["/app/result.json", "/app/build/output.bin"],
        workspace_root="/app",
    )
    try:
        assert [artifact.remote_path for artifact in snapshot.artifacts] == [
            "/app/result.json",
            "/app/build/output.bin",
        ]
        assert [artifact.relative_path for artifact in snapshot.artifacts] == [
            "result.json",
            "build/output.bin",
        ]
        assert [artifact.size_bytes for artifact in snapshot.artifacts] == [
            len(b'{"status":"ok"}\n'),
            3,
        ]
        assert (
            snapshot.artifacts[0].sha256
            == hashlib.sha256(b'{"status":"ok"}\n').hexdigest()
        )
        assert (
            snapshot.artifacts[1].sha256 == hashlib.sha256(b"\x00\x01\x02").hexdigest()
        )
        assert snapshot.to_metadata() == {
            "transport": "explicit_regular_files",
            "workspace_root": "/app",
            "artifacts": [
                {
                    "remote_path": "/app/result.json",
                    "relative_path": "result.json",
                    "sha256": hashlib.sha256(b'{"status":"ok"}\n').hexdigest(),
                    "size_bytes": len(b'{"status":"ok"}\n'),
                },
                {
                    "remote_path": "/app/build/output.bin",
                    "relative_path": "build/output.bin",
                    "sha256": hashlib.sha256(b"\x00\x01\x02").hexdigest(),
                    "size_bytes": 3,
                },
            ],
        }

        destination = _ArtifactSandbox()
        import_verifier_artifacts(destination, snapshot, workspace_root="/app")

        assert destination.fs.uploaded_bytes == {
            "/app/result.json": b'{"status":"ok"}\n',
            "/app/build/output.bin": b"\x00\x01\x02",
        }
        assert any(
            "mkdir -p /app/build" in command for command in destination.process.commands
        )
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_export_verifier_artifacts_captures_private_immutable_staging_files():
    from boundarybench.terminalbench.daytona_runtime_layer import (
        VERIFIER_ARTIFACT_CAPTURE_SCRIPT,
    )

    source = _ArtifactSandbox(
        {
            "/app/result.json": b"result",
            "/app/build/output.bin": b"output",
        }
    )

    snapshot = export_verifier_artifacts(
        source,
        ["/app/result.json", "/app/build/output.bin"],
        workspace_root="/app",
    )
    try:
        capture_command = next(
            command
            for command in source.process.commands
            if "capture_verifier_artifacts.py" in command
        )
        assert "python3" in capture_command
        assert "--workspace-root /app" in capture_command
        assert all(
            remote.startswith("/tmp/boundarybench-verifier-capture-")
            for remote, _ in source.fs.downloads
        )
        assert [Path(remote).name for remote, _ in source.fs.downloads] == [
            "000000",
            "000001",
        ]
        assert all(
            remote not in source.fs.remote_files for remote, _ in source.fs.downloads
        )
        assert any(
            command.startswith("rm -rf -- /tmp/boundarybench-verifier-capture-")
            for command in source.process.commands
        )
        assert "os.O_NOFOLLOW" in VERIFIER_ARTIFACT_CAPTURE_SCRIPT
        assert "dir_fd=" in VERIFIER_ARTIFACT_CAPTURE_SCRIPT
        assert "stat.S_ISREG" in VERIFIER_ARTIFACT_CAPTURE_SCRIPT
        assert "mode=0o700" in VERIFIER_ARTIFACT_CAPTURE_SCRIPT
        assert "os.fchmod(destination_fd, 0o400)" in VERIFIER_ARTIFACT_CAPTURE_SCRIPT
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_export_verifier_artifacts_rejects_count_before_remote_or_local_mutation():
    source = _ArtifactSandbox()
    paths = [
        f"/app/artifact-{index}" for index in range(MAX_VERIFIER_ARTIFACT_FILES + 1)
    ]

    with pytest.raises(ValueError, match="artifact count"):
        export_verifier_artifacts(source, paths, workspace_root="/app")

    assert source.process.commands == []
    assert source.fs.uploads == []
    assert source.fs.downloads == []


@pytest.mark.parametrize(
    "manifest,expected_error",
    [
        (
            {
                "version": 1,
                "file_count": 1,
                "total_bytes": MAX_VERIFIER_ARTIFACT_FILE_BYTES + 1,
                "artifacts": [
                    {
                        "index": 0,
                        "staged_name": "000000",
                        "size_bytes": MAX_VERIFIER_ARTIFACT_FILE_BYTES + 1,
                        "sha256": "0" * 64,
                    }
                ],
            },
            "per-file",
        ),
        (
            {
                "version": 1,
                "file_count": 2,
                "total_bytes": MAX_VERIFIER_ARTIFACT_TOTAL_BYTES + 1,
                "artifacts": [
                    {
                        "index": 0,
                        "staged_name": "000000",
                        "size_bytes": MAX_VERIFIER_ARTIFACT_FILE_BYTES,
                        "sha256": "0" * 64,
                    },
                    {
                        "index": 1,
                        "staged_name": "000001",
                        "size_bytes": (
                            MAX_VERIFIER_ARTIFACT_TOTAL_BYTES
                            - MAX_VERIFIER_ARTIFACT_FILE_BYTES
                            + 1
                        ),
                        "sha256": "1" * 64,
                    },
                ],
            },
            "total",
        ),
    ],
)
def test_export_verifier_artifacts_rejects_oversized_manifest_before_download(
    manifest, expected_error
):
    source = _ArtifactSandbox({"/app/first": b"x", "/app/second": b"y"})
    original_exec = source.process.exec

    def return_manifest(command: str, *, timeout: int, env=None):
        if "capture_verifier_artifacts.py" in command and "python3" in command:
            return _FakeResult(0, json.dumps(manifest))
        return original_exec(command, timeout=timeout, env=env)

    source.process.exec = return_manifest
    paths = list(source.fs.remote_files)[: manifest["file_count"]]

    with pytest.raises(ValueError, match=expected_error):
        export_verifier_artifacts(source, paths, workspace_root="/app")

    assert source.fs.downloads == []


def test_export_verifier_artifacts_rejects_download_mismatch():
    source = _ArtifactSandbox({"/app/result.json": b"expected"})

    def corrupt_download(remote_path: str, local_path: str, timeout: int):
        source.fs.downloads.append((remote_path, local_path))
        Path(local_path).write_bytes(b"corrupt")

    source.fs.download_file = corrupt_download

    with pytest.raises(ValueError, match="download.*hash|download.*size"):
        export_verifier_artifacts(
            source,
            ["/app/result.json"],
            workspace_root="/app",
        )


def test_verifier_capture_helper_rejects_concurrent_writer(tmp_path):
    helper = files("boundarybench.terminalbench").joinpath(
        "scripts", "capture_verifier_artifacts.py"
    )
    helper_globals = runpy.run_path(str(helper))
    copy_regular_file = helper_globals["_copy_regular_file"]
    workspace = tmp_path / "workspace"
    staging = tmp_path / "staging"
    workspace.mkdir(mode=0o700)
    staging.mkdir(mode=0o700)
    source = workspace / "model.pt"
    source.write_bytes(b"a" * (32 * 1024 * 1024))
    stop = threading.Event()
    started = threading.Event()

    def mutate_source():
        with source.open("r+b", buffering=0) as stream:
            offset = 0
            while not stop.is_set():
                stream.seek(offset % (1024 * 1024))
                stream.write(b"b")
                offset += 4096
                started.set()

    writer = threading.Thread(target=mutate_source)
    writer.start()
    started.wait(timeout=5)
    workspace_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="mutated"):
            copy_regular_file(
                workspace_fd=workspace_fd,
                staging_fd=staging_fd,
                relative_path="model.pt",
                destination="000000",
                max_file_bytes=MAX_VERIFIER_ARTIFACT_FILE_BYTES,
                required_owner_uid=os.geteuid(),
            )
    finally:
        stop.set()
        writer.join(timeout=5)
        os.close(staging_fd)
        os.close(workspace_fd)


@pytest.mark.skipif(os.geteuid() == 0, reason="requires a non-root test process")
def test_verifier_capture_helper_rejects_non_root_execution(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "result.json"
    source.write_text("result")
    staging = tmp_path / "staging"
    helper = files("boundarybench.terminalbench").joinpath(
        "scripts", "capture_verifier_artifacts.py"
    )

    result = subprocess.run(
        [
            sys.executable,
            str(helper),
            "--workspace-root",
            str(workspace),
            "--staging-root",
            str(staging),
            "--path",
            str(source),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "must run as root" in result.stderr
    assert not staging.exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a root test process")
def test_verifier_capture_helper_creates_root_owned_private_files(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "result.json"
    source.write_text("result")
    staging = tmp_path / "staging"
    helper = files("boundarybench.terminalbench").joinpath(
        "scripts", "capture_verifier_artifacts.py"
    )

    subprocess.run(
        [
            sys.executable,
            str(helper),
            "--workspace-root",
            str(workspace),
            "--staging-root",
            str(staging),
            "--path",
            str(source),
        ],
        text=True,
        capture_output=True,
        check=True,
    )

    staged = staging / "000000"
    assert staging.stat().st_uid == 0
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700
    assert staged.stat().st_uid == 0
    assert stat.S_IMODE(staged.stat().st_mode) == 0o400
    assert staged.read_text() == "result"


def test_export_verifier_artifacts_surfaces_remote_staging_cleanup_failure():
    source = _ArtifactSandbox({"/app/result.json": b"result"})
    original_exec = source.process.exec

    def fail_cleanup(command: str, *, timeout: int, env=None):
        if command.startswith("rm -rf -- /tmp/boundarybench-verifier-capture-"):
            return _FakeResult(1, "cleanup denied")
        return original_exec(command, timeout=timeout, env=env)

    source.process.exec = fail_cleanup

    with pytest.raises(RuntimeError, match="remote verifier staging cleanup failed"):
        export_verifier_artifacts(
            source,
            ["/app/result.json"],
            workspace_root="/app",
        )


def test_export_verifier_artifacts_combines_capture_and_cleanup_failures(
    tmp_path, monkeypatch
):
    import boundarybench.terminalbench.daytona_run as daytona_run_module

    source = _ArtifactSandbox({"/app/result.json": b"result"})
    snapshot_root = tmp_path / "snapshot"
    original_rmtree = daytona_run_module.shutil.rmtree

    def fake_mkdtemp(*args, **kwargs):
        snapshot_root.mkdir()
        return str(snapshot_root)

    def fail_host_cleanup(*args, **kwargs):
        raise OSError("host cleanup boom")

    def fail_capture_and_remote_cleanup(command: str, *, timeout: int, env=None):
        if "capture_verifier_artifacts" in command and "python3" in command:
            return _FakeResult(1, "capture boom")
        if command.startswith("rm -rf -- /tmp/boundarybench-verifier-capture-"):
            return _FakeResult(1, "remote cleanup boom")
        return _FakeResult(0, "")

    monkeypatch.setattr(daytona_run_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(daytona_run_module.shutil, "rmtree", fail_host_cleanup)
    source.process.exec = fail_capture_and_remote_cleanup
    try:
        with pytest.raises(ExceptionGroup, match="capture and cleanup failed") as exc:
            export_verifier_artifacts(
                source,
                ["/app/result.json"],
                workspace_root="/app",
            )
        assert [str(error) for error in exc.value.exceptions] == [
            "verifier handoff capture rejected: capture boom",
            "host snapshot cleanup failed: host cleanup boom",
            "remote verifier staging cleanup failed: remote cleanup boom",
        ]
    finally:
        monkeypatch.setattr(daytona_run_module.shutil, "rmtree", original_rmtree)
        original_rmtree(snapshot_root, ignore_errors=True)


def test_export_verifier_artifacts_combines_remote_and_host_cleanup_failures(
    tmp_path, monkeypatch
):
    import boundarybench.terminalbench.daytona_run as daytona_run_module

    source = _ArtifactSandbox({"/app/result.json": b"result"})
    snapshot_root = tmp_path / "snapshot"
    original_rmtree = daytona_run_module.shutil.rmtree

    def fake_mkdtemp(*args, **kwargs):
        snapshot_root.mkdir()
        return str(snapshot_root)

    def fail_host_cleanup(*args, **kwargs):
        raise OSError("host cleanup boom")

    original_exec = source.process.exec

    def fail_remote_cleanup(command: str, *, timeout: int, env=None):
        if command.startswith("rm -rf -- /tmp/boundarybench-verifier-capture-"):
            return _FakeResult(1, "remote cleanup boom")
        return original_exec(command, timeout=timeout, env=env)

    monkeypatch.setattr(daytona_run_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(daytona_run_module.shutil, "rmtree", fail_host_cleanup)
    source.process.exec = fail_remote_cleanup
    try:
        with pytest.raises(ExceptionGroup, match="cleanup failed") as exc:
            export_verifier_artifacts(
                source,
                ["/app/result.json"],
                workspace_root="/app",
            )
        assert [str(error) for error in exc.value.exceptions] == [
            "remote verifier staging cleanup failed: remote cleanup boom",
            "host snapshot cleanup failed: host cleanup boom",
        ]
    finally:
        monkeypatch.setattr(daytona_run_module.shutil, "rmtree", original_rmtree)
        original_rmtree(snapshot_root, ignore_errors=True)


@pytest.mark.parametrize(
    "handoff_path,workspace_root",
    [
        ("result.json", "/app"),
        ("/app/../etc/passwd", "/app"),
        ("/app/build/../result.json", "/app"),
        ("/application/result.json", "/app"),
        ("/app/result.json", "app"),
    ],
)
def test_export_verifier_artifacts_rejects_invalid_paths(
    handoff_path: str, workspace_root: str
):
    with pytest.raises(ValueError):
        export_verifier_artifacts(
            _ArtifactSandbox(),
            [handoff_path],
            workspace_root=workspace_root,
        )


@pytest.mark.parametrize("failed_check", ["missing", "symlink", "directory"])
def test_export_verifier_artifacts_rejects_non_regular_remote_files(failed_check):
    sandbox = _ArtifactSandbox({"/app/result.json": b"content"})

    def exec_check(command: str, *, timeout: int, env=None):
        if "capture_verifier_artifacts" in command and "python3" in command:
            return _FakeResult(1, failed_check)
        return _FakeResult(0, "")

    sandbox.process.exec = exec_check

    with pytest.raises(ValueError, match=failed_check):
        export_verifier_artifacts(
            sandbox,
            ["/app/result.json"],
            workspace_root="/app",
        )


def test_export_verifier_artifacts_rejects_symlinked_path_components():
    sandbox = _ArtifactSandbox({"/app/build/result.json": b"content"})

    def reject_component_symlink(command: str, *, timeout: int, env=None):
        if "capture_verifier_artifacts" in command and "python3" in command:
            return _FakeResult(1, "symlink component")
        return _FakeResult(0, "")

    sandbox.process.exec = reject_component_symlink

    with pytest.raises(ValueError, match="symlink component"):
        export_verifier_artifacts(
            sandbox,
            ["/app/build/result.json"],
            workspace_root="/app",
        )


def test_import_verifier_artifacts_rejects_absolute_relative_path_before_mutation():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    malformed_artifact = replace(snapshot.artifacts[0], relative_path="/etc/passwd")
    malformed = replace(snapshot, artifacts=(malformed_artifact,))
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="relative"):
            import_verifier_artifacts(destination, malformed, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_rejects_non_private_snapshot_root():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    snapshot.root.chmod(0o755)
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="private"):
            import_verifier_artifacts(destination, snapshot, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        snapshot.root.chmod(0o700)
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_rejects_arbitrary_matching_host_file(tmp_path):
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    host_file = tmp_path / "host-secret"
    host_file.write_bytes(b"content")
    malformed_artifact = replace(snapshot.artifacts[0], local_path=host_file)
    malformed = replace(snapshot, artifacts=(malformed_artifact,))
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="local path"):
            import_verifier_artifacts(destination, malformed, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_rejects_duplicate_paths_before_mutation():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    malformed = replace(
        snapshot, artifacts=(snapshot.artifacts[0], snapshot.artifacts[0])
    )
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="unique"):
            import_verifier_artifacts(destination, malformed, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


@pytest.mark.parametrize(
    "artifacts_factory,expected_error",
    [
        (
            lambda snapshot: snapshot.artifacts * (MAX_VERIFIER_ARTIFACT_FILES + 1),
            "artifact count",
        ),
        (
            lambda snapshot: (
                replace(
                    snapshot.artifacts[0],
                    size_bytes=MAX_VERIFIER_ARTIFACT_FILE_BYTES + 1,
                ),
            ),
            "per-file",
        ),
        (
            lambda snapshot: (
                replace(
                    snapshot.artifacts[0],
                    size_bytes=MAX_VERIFIER_ARTIFACT_FILE_BYTES,
                ),
                replace(
                    snapshot.artifacts[0],
                    remote_path="/app/second.bin",
                    relative_path="second.bin",
                    local_path=snapshot.root / "second.bin",
                    size_bytes=(
                        MAX_VERIFIER_ARTIFACT_TOTAL_BYTES
                        - MAX_VERIFIER_ARTIFACT_FILE_BYTES
                        + 1
                    ),
                ),
            ),
            "total",
        ),
    ],
)
def test_import_verifier_artifacts_rejects_caps_before_remote_mutation(
    artifacts_factory, expected_error
):
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    malformed = replace(snapshot, artifacts=artifacts_factory(snapshot))
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match=expected_error):
            import_verifier_artifacts(destination, malformed, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_rejects_local_symlink_component(tmp_path):
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "result.json"
    outside_file.write_bytes(b"content")
    linked = snapshot.root / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    malformed_artifact = VerifierArtifact(
        remote_path="/app/linked/result.json",
        relative_path="linked/result.json",
        local_path=linked / "result.json",
        sha256=hashlib.sha256(b"content").hexdigest(),
        size_bytes=len(b"content"),
    )
    malformed = replace(snapshot, artifacts=(malformed_artifact,))
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="symlink"):
            import_verifier_artifacts(destination, malformed, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_validates_all_hashes_before_any_upload():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox(
            {
                "/app/first.txt": b"first",
                "/app/second.txt": b"second",
            }
        ),
        ["/app/first.txt", "/app/second.txt"],
        workspace_root="/app",
    )
    snapshot.artifacts[1].local_path.write_bytes(b"corrupt")
    destination = _ArtifactSandbox()
    try:
        with pytest.raises(ValueError, match="size changed|hash changed"):
            import_verifier_artifacts(destination, snapshot, workspace_root="/app")
        assert destination.process.commands == []
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_import_verifier_artifacts_rejects_destination_symlink_before_upload():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/build/result.json": b"content"}),
        ["/app/build/result.json"],
        workspace_root="/app",
    )
    destination = _ArtifactSandbox()

    def reject_symlink(command: str, *, timeout: int, env=None):
        if "test ! -L /app/build" in command:
            return _FakeResult(1, "destination symlink")
        return _FakeResult(0, "")

    destination.process.exec = reject_symlink
    try:
        with pytest.raises(ValueError, match="destination.*symlink"):
            import_verifier_artifacts(destination, snapshot, workspace_root="/app")
        assert destination.fs.uploads == []
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_cleanup_verifier_artifacts_removes_temporary_snapshot():
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    snapshot_root = snapshot.root

    cleanup_verifier_artifacts(snapshot)
    cleanup_verifier_artifacts(snapshot)

    assert not snapshot_root.exists()


def test_cleanup_verifier_artifacts_rejects_unowned_root(tmp_path):
    snapshot = export_verifier_artifacts(
        _ArtifactSandbox({"/app/result.json": b"content"}),
        ["/app/result.json"],
        workspace_root="/app",
    )
    victim = tmp_path / "must-survive"
    victim.mkdir()
    (victim / "important.txt").write_text("keep")
    malformed = replace(snapshot, root=victim)
    try:
        with pytest.raises(ValueError, match="provenance"):
            cleanup_verifier_artifacts(malformed)
        assert (victim / "important.txt").read_text() == "keep"
    finally:
        cleanup_verifier_artifacts(snapshot)


def test_run_terminalbench_task_runs_hardened_agent_then_verifier(tmp_path, capsys):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        harness=ClaudeCodeAdapter(),
    )

    assert any(
        remote == "/tmp/boundarybench-task-prompt.txt"
        for _, remote in sandbox.fs.uploads
    )
    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert "unshare" in agent_cmd
    assert "setpriv --reuid=" in agent_cmd
    assert "minimax/minimax-m3" in agent_cmd
    assert "--permission-mode bypassPermissions" in agent_cmd
    assert "sk-or-secret" not in agent_cmd
    assert result.reward == 1.0
    assert result.passed is True
    assert result.answer == "PASS"
    assert result.agent_exit_code == 0
    metadata = result.to_metadata()
    assert metadata["phase_timings_ms"]["prompt_upload_ms"] >= 0
    assert metadata["phase_timings_ms"]["agent_run_ms"] >= 0
    assert metadata["phase_timings_ms"]["policy_event_read_ms"] >= 0
    assert metadata["phase_timings_ms"]["harbor_verifier_ms"] >= 0
    assert metadata["phase_timings_ms"]["task_run_total_ms"] >= 0
    assert {entry["phase"] for entry in metadata["phase_timing_details"]} >= {
        "prompt_upload",
        "agent_run",
        "policy_event_read",
        "harbor_verifier",
        "task_run_total",
    }
    captured = capsys.readouterr()
    assert "phase_timing component=terminalbench_daytona" in captured.out
    assert "phase=prompt_upload" in captured.out
    assert "phase=agent_run" in captured.out
    assert "phase=policy_event_read" in captured.out
    assert "phase=harbor_verifier" in captured.out
    assert "phase=task_run_total" in captured.out


def test_hardened_run_harvests_passive_telemetry_and_clears_event_log(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    calls = {}

    def _fake_harvest(sb, *, agent_stdout=None, hardening_config=None, **_kwargs):
        calls["sandbox"] = sb
        calls["agent_stdout"] = agent_stdout
        calls["hardening_config"] = hardening_config
        return [
            {
                "event_type": "policy_block",
                "surface": "network_cidr",
                "target": "direct-egress",
                "observer": "nftables",
            }
        ]

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.harvest_passive_telemetry",
        _fake_harvest,
    )

    hardening = _hardening()
    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=hardening,
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        harness=ClaudeCodeAdapter(),
    )

    assert calls["sandbox"] is sandbox
    assert isinstance(calls["agent_stdout"], str)
    assert calls["hardening_config"] is hardening.hardening_config
    assert result.policy_events == [
        {
            "event_type": "policy_block",
            "surface": "network_cidr",
            "target": "direct-egress",
            "observer": "nftables",
        }
    ]
    assert result.to_metadata()["policy_block_count"] == 1
    assert any(
        command.startswith("rm -f ") and ": > " in command and "chmod 0666" in command
        for command in sandbox.process.commands
    )


@pytest.mark.parametrize("agent_only", [False, True])
def test_unhardened_run_harvests_agent_stdout_with_control_context(
    tmp_path, monkeypatch, agent_only
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    calls = []
    control_metadata = resolve_policy("control").config.to_metadata()
    inferred_event = {
        "event_type": "policy_block_inferred",
        "axis": "privilege",
        "target": "/etc/shadow",
        "policy_relationship": "unexpected",
    }

    def _fake_harvest(sb, *, agent_stdout=None, hardening_config=None, **_kwargs):
        calls.append((sb, agent_stdout, hardening_config))
        return [inferred_event]

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.harvest_passive_telemetry",
        _fake_harvest,
    )

    run = (
        run_terminalbench_agent_in_daytona
        if agent_only
        else run_terminalbench_task_in_daytona
    )
    result = run(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        run_agent_as_root=True,
        hardening_config_metadata=control_metadata,
        harness=ClaudeCodeAdapter(),
    )

    assert calls == [
        (
            sandbox,
            '{"type":"result","subtype":"success"}',
            control_metadata,
        )
    ]
    assert result.policy_events == [inferred_event]


_PROMPT_WRITE_FUNCS = pytest.mark.parametrize(
    "run_fn",
    [run_terminalbench_task_in_daytona, run_terminalbench_agent_in_daytona],
    ids=["full_task", "agent_only"],
)


def _run_prompt_write(run_fn, sandbox, bundle, monkeypatch, **kwargs):
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.harvest_passive_telemetry",
        lambda sb, **_kwargs: [],
    )
    return run_fn(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        run_agent_as_root=True,
        hardening_config_metadata=resolve_policy("control").config.to_metadata(),
        harness=ClaudeCodeAdapter(),
        **kwargs,
    )


@_PROMPT_WRITE_FUNCS
def test_policy_prompt_fragment_is_prepended_with_one_blank_line(
    tmp_path, monkeypatch, run_fn
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    fragment = "<environment_policy>\nrules here\n</environment_policy>"

    _run_prompt_write(
        run_fn, sandbox, bundle, monkeypatch, policy_prompt_fragment=fragment
    )

    assert (
        sandbox.fs.uploaded_content[REMOTE_PROMPT_PATH]
        == fragment + "\n\n" + bundle.input
    )


@_PROMPT_WRITE_FUNCS
def test_prompt_is_byte_identical_without_fragment(tmp_path, monkeypatch, run_fn):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    _run_prompt_write(run_fn, sandbox, bundle, monkeypatch)

    assert sandbox.fs.uploaded_content[REMOTE_PROMPT_PATH] == bundle.input
    assert f"chmod 644 {REMOTE_PROMPT_PATH}" in sandbox.process.commands
    assert REMOTE_ALLOWED_DOMAINS_PATH not in sandbox.fs.uploaded_content
    assert not any(
        REMOTE_ALLOWED_DOMAINS_PATH in command for command in sandbox.process.commands
    )


@_PROMPT_WRITE_FUNCS
def test_allowlist_file_uploaded_and_chmodded_when_content_provided(
    tmp_path, monkeypatch, run_fn
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    allowlist = "files.pythonhosted.org\ngithub.com\npypi.org\n"

    _run_prompt_write(
        run_fn,
        sandbox,
        bundle,
        monkeypatch,
        policy_prompt_fragment="<environment_policy>\nnet\n</environment_policy>",
        allowlist_file_content=allowlist,
    )

    assert sandbox.fs.uploaded_content[REMOTE_ALLOWED_DOMAINS_PATH] == allowlist
    assert f"chmod 644 {REMOTE_ALLOWED_DOMAINS_PATH}" in sandbox.process.commands


@_PROMPT_WRITE_FUNCS
def test_allowlist_file_not_written_when_content_none(tmp_path, monkeypatch, run_fn):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    _run_prompt_write(
        run_fn,
        sandbox,
        bundle,
        monkeypatch,
        policy_prompt_fragment="<environment_policy>\nfs\n</environment_policy>",
        allowlist_file_content=None,
    )

    assert REMOTE_ALLOWED_DOMAINS_PATH not in sandbox.fs.uploaded_content
    assert not any(
        REMOTE_ALLOWED_DOMAINS_PATH in command for command in sandbox.process.commands
    )


@_PROMPT_WRITE_FUNCS
def test_policy_prompt_provenance_threaded_onto_result(tmp_path, monkeypatch, run_fn):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    provenance = {
        "mode": "on",
        "original_prompt_sha256": "a" * 64,
        "rendered_prompt_sha256": "b" * 64,
        "rendered_prompt_bytes": 1234,
        "preset_name": "moderate-nist",
    }

    result = _run_prompt_write(
        run_fn,
        sandbox,
        bundle,
        monkeypatch,
        policy_prompt_fragment="<environment_policy>\nnet\n</environment_policy>",
        policy_prompt_provenance=provenance,
    )

    assert result.policy_prompt_provenance == provenance
    assert result.policy_prompt_provenance is not provenance


@_PROMPT_WRITE_FUNCS
def test_policy_prompt_provenance_defaults_empty_when_absent(
    tmp_path, monkeypatch, run_fn
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = _run_prompt_write(run_fn, sandbox, bundle, monkeypatch)

    assert result.policy_prompt_provenance == {}


def test_policy_prompt_provenance_in_run_result_metadata(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    provenance = {"mode": "off", "original_prompt_sha256": "c" * 64}

    result = _run_prompt_write(
        run_terminalbench_task_in_daytona,
        sandbox,
        bundle,
        monkeypatch,
        policy_prompt_provenance=provenance,
    )

    metadata = result.to_metadata()
    assert metadata["policy_prompt_provenance"] == provenance
    assert "policy_prompt_provenance" in metadata


def test_disclosed_allowlist_and_prompt_survive_pre_agent_cleanup():
    sandbox = _FakeSandbox()

    remove_pre_agent_setup_artifacts(
        sandbox,
        daytona_policy_hardening=_native_hardening(),
        enforcement_mode="native",
    )

    assert sandbox.process.commands
    for command in sandbox.process.commands:
        assert REMOTE_ALLOWED_DOMAINS_PATH not in command
        assert REMOTE_PROMPT_PATH not in command


def _transcript_prompt_section(*, prompt: str, result) -> str:
    """Render the task transcript for ``result`` under ``prompt`` and return its
    ``## Prompt`` section (what a human reads for the delivered instruction)."""

    md = render_task_transcript_markdown(
        task_id="terminal-bench/example",
        prompt=prompt,
        model="minimax/minimax-m3",
        reward=result.reward,
        answer=result.answer,
        agent_stdout=result.agent_stdout,
    )
    return md.split("## Prompt", 1)[1].split("## Trace", 1)[0]


@_PROMPT_WRITE_FUNCS
def test_result_prompt_is_the_delivered_prompt_with_fragment(
    tmp_path, monkeypatch, run_fn
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    fragment = "<environment_policy>\nrules here\n</environment_policy>"

    result = _run_prompt_write(
        run_fn, sandbox, bundle, monkeypatch, policy_prompt_fragment=fragment
    )

    assert result.prompt == fragment + "\n\n" + bundle.input


@_PROMPT_WRITE_FUNCS
def test_result_prompt_byte_identical_without_fragment(tmp_path, monkeypatch, run_fn):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = _run_prompt_write(run_fn, sandbox, bundle, monkeypatch)

    assert result.prompt == bundle.input


def test_transcript_prompt_section_shows_fragment_above_task_text(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    fragment = "<environment_policy>\nrules here\n</environment_policy>"

    result = _run_prompt_write(
        run_terminalbench_task_in_daytona,
        sandbox,
        bundle,
        monkeypatch,
        policy_prompt_fragment=fragment,
    )

    section = _transcript_prompt_section(prompt=result.prompt, result=result)
    assert fragment in section
    assert bundle.input in section
    assert section.index(fragment) < section.index(bundle.input)


def test_transcript_prompt_section_byte_identical_without_fragment(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = _run_prompt_write(
        run_terminalbench_task_in_daytona, sandbox, bundle, monkeypatch
    )

    section = _transcript_prompt_section(prompt=result.prompt, result=result)
    reference = _transcript_prompt_section(prompt=bundle.input, result=result)
    assert section == reference
    assert "<environment_policy>" not in section


def test_run_terminalbench_task_applies_full_mac_to_agent_not_verifier(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    hardened_calls = []

    def fake_hardened_run(_sandbox, **kwargs):
        hardened_calls.append(kwargs)
        return DaytonaCommandResult(exit_code=0, stdout="agent ok")

    def fake_verifier(
        _sandbox,
        verifier_bundle,
        *,
        remote_tests_dir,
        **kwargs,
    ):
        assert verifier_bundle is bundle
        assert remote_tests_dir == "/tests"
        assert "include_daytona_user_site" not in kwargs
        return DaytonaVerifierResult(
            value=1.0,
            answer="PASS",
            exit_code=0,
            stdout="reward ok",
            stderr="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        fake_hardened_run,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_daytona_harbor_verifier",
        fake_verifier,
    )

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        full_mac_enforcement=True,
        harness=ClaudeCodeAdapter(),
    )

    assert result.reward == 1.0
    assert len(hardened_calls) == 1
    assert hardened_calls[0]["full_mac_enforcement"] is True
    assert DAYTONA_CLAUDE_BIN in hardened_calls[0]["command"]


def test_agent_workdir_flows_to_cwd_but_workspace_stays_app(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    hardened_calls = []

    def fake_hardened_run(_sandbox, **kwargs):
        hardened_calls.append(kwargs)
        return DaytonaCommandResult(exit_code=0, stdout="agent ok")

    def fake_verifier(
        _sandbox,
        verifier_bundle,
        *,
        remote_tests_dir,
        remote_workdir,
        **kwargs,
    ):
        assert "include_daytona_user_site" not in kwargs
        assert remote_workdir == "/app/personal-site"
        return DaytonaVerifierResult(
            value=1.0, answer="PASS", exit_code=0, stdout="reward ok", stderr=""
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        fake_hardened_run,
    )
    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_daytona_harbor_verifier",
        fake_verifier,
    )

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        agent_workdir="/app/personal-site",
        harness=ClaudeCodeAdapter(),
    )

    assert hardened_calls[0]["cwd"] == "/app/personal-site"
    assert hardened_calls[0]["workspace"] == "/app"
    assert result.agent_workdir == "/app/personal-site"
    assert result.to_metadata()["agent_workdir"] == "/app/personal-site"


def test_unhardened_agent_runs_in_supplied_workdir(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    def fake_verifier(
        _sandbox,
        verifier_bundle,
        *,
        remote_tests_dir,
        remote_workdir,
        **kwargs,
    ):
        assert "include_daytona_user_site" not in kwargs
        assert remote_workdir == "/app/personal-site"
        return DaytonaVerifierResult(
            value=1.0, answer="PASS", exit_code=0, stdout="reward ok", stderr=""
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_daytona_harbor_verifier",
        fake_verifier,
    )

    run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        agent_workdir="/app/personal-site",
        harness=ClaudeCodeAdapter(),
    )

    agent_cmd = next(c for c in sandbox.process.commands if DAYTONA_CLAUDE_BIN in c)
    assert "cd /app/personal-site && " in agent_cmd


def test_run_terminalbench_task_can_wrap_hardened_agent_with_agentsh_session(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        agentsh_session_id="session-example",
        agentsh_policy_session={
            "session_id": "session-example",
            "policy_name": "boundarybench-nist-linux-80053-high",
        },
        harness=ClaudeCodeAdapter(),
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert "unshare" in agent_cmd
    assert "setpriv --reuid=" in agent_cmd
    assert (
        "/usr/bin/agentsh --client-timeout 3660s wrap "
        "--session session-example --report=false -- /bin/bash.real -lc"
    ) in agent_cmd
    assert "/usr/bin/agentsh --client-timeout 3660s exec" not in agent_cmd
    assert "cd /app && /usr/bin/env BASH_ENV=/opt/h/child_net" in agent_cmd
    assert DAYTONA_CLAUDE_BIN in agent_cmd
    assert "sk-or-secret" not in agent_cmd
    assert result.agentsh_agent_wrapped is True
    assert result.agentsh_session_id == "session-example"
    assert result.to_metadata()["agentsh_agent_wrapped"] is True
    assert result.to_metadata()["agentsh_session_id"] == "session-example"
    assert result.to_metadata()["agentsh_policy_session"] == {
        "session_id": "session-example",
        "policy_name": "boundarybench-nist-linux-80053-high",
    }


def test_wrap_command_for_agentsh_session_extends_client_timeout():
    wrapped = wrap_command_for_agentsh_session(
        session_id="session-example",
        command="echo ready",
        timeout_seconds=120,
    )

    assert wrapped.startswith(
        "/usr/bin/agentsh --client-timeout 180s wrap "
        "--session session-example --report=false -- /bin/bash.real -lc"
    )
    assert "echo ready" in wrapped


def test_run_terminalbench_task_rejects_empty_agentsh_session_id(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    with pytest.raises(ValueError, match="agentsh_session_id"):
        run_terminalbench_task_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=_hardening(),
            openrouter_api_key="sk-or-secret",
            model="minimax/minimax-m3",
            agentsh_session_id="",
            harness=ClaudeCodeAdapter(),
        )


def test_run_terminalbench_task_uses_root_agent_mode_for_none_policy(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        block_child_shell_network=False,
        run_agent_as_root=True,
        hardening_config_metadata={"name": "none"},
        harness=ClaudeCodeAdapter(),
    )

    agent_cmd = next(c for c in sandbox.process.commands if ROOT_CLAUDE_BIN in c)
    assert "unshare" not in agent_cmd
    assert "LD_PRELOAD" not in agent_cmd
    assert "/opt/h" not in agent_cmd
    assert "setpriv --reuid=" not in agent_cmd
    assert "id -u daytona" not in agent_cmd
    assert "--dangerously-skip-permissions" in agent_cmd
    assert "--permission-mode bypassPermissions" not in agent_cmd
    assert "sk-or-secret" not in agent_cmd
    agent_env = next(
        env for env in sandbox.process.envs if env and "ANTHROPIC_AUTH_TOKEN" in env
    )
    assert agent_env["IS_SANDBOX"] == "1"
    assert result.hardening_config == {"name": "none"}
    assert result.policy_events == []
    assert result.reward == 1.0


def test_run_terminalbench_task_reports_failing_reward(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    original = sandbox.process.exec

    def exec_zero_reward(command, *, timeout, env=None):
        if "reward.txt" in command:
            return _FakeResult(0, "0\n")
        return original(command, timeout=timeout, env=env)

    sandbox.process.exec = exec_zero_reward  # type: ignore[method-assign]

    result = run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        harness=ClaudeCodeAdapter(),
    )

    assert result.reward == 0.0
    assert result.passed is False
    assert result.answer == "FAIL"


def test_sandbox_managed_by_namespace_fails_closed_on_invalid_value():
    env = os.environ.copy()
    env["BOUNDARYBENCH_SANDBOX_MANAGED_BY"] = "invalid namespace"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import boundarybench.terminalbench.daytona_constants",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert "BOUNDARYBENCH_SANDBOX_MANAGED_BY must match" in result.stderr


@pytest.mark.parametrize(
    "namespace",
    ["inspect", "boundarybench-terminalbench-ci"],
)
def test_sandbox_managed_by_namespace_rejects_default_prefix_collisions(namespace):
    env = os.environ.copy()
    env["BOUNDARYBENCH_SANDBOX_MANAGED_BY"] = namespace
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import boundarybench.terminalbench.daytona_constants",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert "or match ^isolated-" in result.stderr


class _FakeSb:
    def __init__(
        self,
        sid: str,
        state: str,
        managed: bool = True,
        run_id: str | None = None,
    ) -> None:
        self.id = sid
        self.state = state
        self.labels = dict(SANDBOX_LABELS) if managed else {"managed-by": "other"}
        if run_id is not None:
            self.labels[SANDBOX_MANAGED_BY_LABEL] = (
                f"{SANDBOX_MANAGED_BY_VALUE}-{run_id}"
            )
            self.labels[SANDBOX_RUN_ID_LABEL] = run_id


class _FakeDaytona:
    def __init__(self, sandboxes: list[_FakeSb]) -> None:
        self._sandboxes = sandboxes
        self.deleted: list[str] = []
        self.not_found: set[str] = set()

    def list(self):
        return [s for s in self._sandboxes if s.id not in self.deleted]

    def delete(self, sandbox) -> None:
        if sandbox.id in self.not_found:
            raise type("DaytonaNotFoundError", (Exception,), {})("not found")
        self.deleted.append(sandbox.id)


class _DaytonaConflictError(Exception):
    status_code = 409


def test_reaper_deletes_only_our_stale_sandboxes():
    daytona = _FakeDaytona(
        [
            _FakeSb("stopped-ours", "STOPPED"),
            _FakeSb("archived-ours", "ARCHIVED"),
            _FakeSb("error-ours", "ERROR"),
            _FakeSb("running-ours", "STARTED"),
            _FakeSb("stopped-other", "STOPPED", managed=False),
        ]
    )
    deleted, failed = reap_stale_terminalbench_sandboxes(daytona)
    assert deleted == 3 and failed == 0
    assert set(daytona.deleted) == {"stopped-ours", "archived-ours", "error-ours"}


def test_reaper_can_delete_running_sandboxes_for_completed_run_only():
    daytona = _FakeDaytona(
        [
            _FakeSb("running-this-run", "STARTED", run_id="run-a"),
            _FakeSb("stopped-this-run", "STOPPED", run_id="run-a"),
            _FakeSb("toolbox-this-run", "STARTED", run_id="run-a"),
            _FakeSb("running-other-run", "STARTED", run_id="run-b"),
            _FakeSb("running-no-run", "STARTED"),
        ]
    )
    daytona._sandboxes[2].labels.pop(SANDBOX_RUN_ID_LABEL)

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona, run_id="run-a", include_running=True
    )

    assert deleted == 3 and failed == 0
    assert set(daytona.deleted) == {
        "running-this-run",
        "stopped-this-run",
        "toolbox-this-run",
    }


def test_completed_run_reaper_rejects_conflicting_run_ownership_labels():
    sandbox = _FakeSb("conflicting-ownership", "STARTED", run_id="run-b")
    sandbox.labels[SANDBOX_MANAGED_BY_LABEL] = f"{SANDBOX_MANAGED_BY_VALUE}-run-a"
    daytona = _FakeDaytona([sandbox])

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona,
        run_id="run-a",
        include_running=True,
    )

    assert deleted == 0 and failed == 0
    assert daytona.deleted == []


def test_completed_run_reaper_preserves_unscoped_daytona_toolboxes():
    toolbox = _FakeSb("toolbox-legacy", "STARTED")
    toolbox.labels["code-toolbox-language"] = "python"
    daytona = _FakeDaytona(
        [
            toolbox,
            _FakeSb("plain-legacy-running", "STARTED"),
            _FakeSb("other-run", "STARTED", run_id="run-b"),
        ]
    )

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona,
        run_id="run-a",
        include_running=True,
    )

    assert deleted == 0 and failed == 0
    assert daytona.deleted == []


def test_reaper_ignores_not_found_delete_race():
    daytona = _FakeDaytona([_FakeSb("already-gone", "STOPPED")])
    daytona.not_found.add("already-gone")

    deleted, failed = reap_stale_terminalbench_sandboxes(daytona)

    assert deleted == 0 and failed == 0


def test_reaper_strict_mode_ignores_stale_not_found_inventory_record():
    sandbox = _FakeSb("already-gone", "STARTED", run_id="run-a")
    daytona = _FakeDaytona([sandbox])
    daytona.not_found.add("already-gone")

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona,
        run_id="run-a",
        include_running=True,
        strict_list=True,
    )

    assert deleted == 0 and failed == 0


def test_reaper_strict_mode_does_not_trust_generic_not_found_message(monkeypatch):
    sandbox = _FakeSb("still-present", "STARTED", run_id="run-a")
    daytona = _FakeDaytona([sandbox])

    def raise_unrelated_not_found(_sandbox) -> None:
        raise RuntimeError("project not found")

    monkeypatch.setattr(daytona, "delete", raise_unrelated_not_found)

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona,
        run_id="run-a",
        include_running=True,
        strict_list=True,
    )

    assert deleted == 0 and failed == 1


def test_reaper_ignores_conflict_delete_race(monkeypatch):
    daytona = _FakeDaytona([_FakeSb("delete-in-flight", "STARTED", run_id="run-a")])

    def raise_conflict(_sandbox) -> None:
        raise _DaytonaConflictError("delete already in progress")

    monkeypatch.setattr(daytona, "delete", raise_conflict)

    deleted, failed = reap_stale_terminalbench_sandboxes(
        daytona,
        run_id="run-a",
        include_running=True,
    )

    assert deleted == 0 and failed == 0


def test_reaper_strict_list_mode_surfaces_inventory_failure():
    daytona = _FakeDaytona([])
    daytona.list = lambda: (_ for _ in ()).throw(RuntimeError("inventory unavailable"))

    with pytest.raises(RuntimeError, match="inventory unavailable"):
        reap_stale_terminalbench_sandboxes(daytona, strict_list=True)


def test_reaper_strict_mode_counts_owned_sandboxes_remaining_after_delete():
    sandbox = _FakeSb("still-deleting", "STARTED", run_id="run-a")

    class _LaggingDeleteDaytona:
        def list(self):
            return [sandbox]

        def delete(self, _sandbox):
            return None

    assert reap_stale_terminalbench_sandboxes(
        _LaggingDeleteDaytona(),
        run_id="run-a",
        include_running=True,
        strict_list=True,
    ) == (1, 1)


def test_reaper_strict_mode_surfaces_post_delete_inventory_failure():
    sandbox = _FakeSb("deleting", "STARTED", run_id="run-a")
    calls = {"list": 0}

    class _RelistFailureDaytona:
        def list(self):
            calls["list"] += 1
            if calls["list"] == 1:
                return [sandbox]
            raise RuntimeError("post-delete inventory unavailable")

        def delete(self, _sandbox):
            return None

    with pytest.raises(RuntimeError, match="post-delete inventory unavailable"):
        reap_stale_terminalbench_sandboxes(
            _RelistFailureDaytona(),
            run_id="run-a",
            include_running=True,
            strict_list=True,
        )


def test_sandbox_create_labels_include_current_run_id(monkeypatch):
    monkeypatch.setenv("BOUNDARYBENCH_RUN_ID", "run-123")

    labels = _sandbox_create_labels()

    assert labels["managed-by"] == "boundarybench-terminalbench-run-123"
    assert labels[SANDBOX_NAMESPACE_LABEL] == SANDBOX_MANAGED_BY_VALUE
    assert labels[SANDBOX_RUN_ID_LABEL] == "run-123"


def test_lifecycle_constants_keep_autostop_above_agent_timeout():
    assert SANDBOX_AUTO_STOP_MIN * 60 > DEFAULT_AGENT_TIMEOUT_SEC
    assert _sandbox_auto_stop_min(12000) * 60 > 12000
    assert SANDBOX_AUTO_DELETE_MIN > 0


def test_run_result_metadata_includes_inferred_and_honeytoken_counts():
    from boundarybench.terminalbench.daytona_run import TerminalBenchRunResult

    verifier = DaytonaVerifierResult(
        value=0.0, answer="FAIL", exit_code=1, stdout="", stderr=""
    )
    result = TerminalBenchRunResult(
        sample_id="s",
        task_name="t",
        prompt="p",
        reward=0.0,
        answer="FAIL",
        agent_exit_code=1,
        agent_stdout="",
        verifier=verifier,
        policy_events=[
            {"event_type": "policy_block", "surface": "command", "command": "sudo -i"},
            {
                "event_type": "policy_block_inferred",
                "surface": "path",
                "target": "/run/credentials/provider-token",
                "axis": "filesystem",
                "policy_relationship": "expected",
            },
            {
                "event_type": "policy_block_inferred",
                "surface": "network_cidr",
                "target": "connection-refused",
                "axis": "network",
                "policy_relationship": "expected",
            },
            {
                "event_type": "policy_block_inferred",
                "surface": "command",
                "target": "sudo",
                "axis": "privilege",
                "policy_relationship": "unexpected",
            },
            {
                "event_type": "policy_block_inferred",
                "surface": "other",
                "target": "unknown",
                "axis": "other",
                "policy_relationship": "unknown",
            },
            {
                "event_type": "honeytoken_exfil",
                "surface": "credential_exfil",
                "target": "aws_access_key_id",
            },
        ],
        harness="claude_code",
        effort_level="high",
        effort_level_source="task_arg",
        effort_level_applied=True,
    )

    metadata = result.to_metadata()

    assert metadata["policy_block_count"] == 1
    assert metadata["inferred_block_count"] == 4
    assert metadata["inferred_network_block_count"] == 1
    assert metadata["inferred_filesystem_block_count"] == 1
    assert metadata["inferred_privilege_block_count"] == 1
    assert metadata["unexpected_inferred_block_count"] == 1
    assert metadata["honeytoken_exfil_count"] == 1


def test_run_result_requires_explicit_harness_claims():
    from boundarybench.terminalbench.daytona_run import TerminalBenchRunResult

    verifier = DaytonaVerifierResult(
        value=1.0, answer="PASS", exit_code=0, stdout="", stderr=""
    )
    with pytest.raises(TypeError):
        TerminalBenchRunResult(
            sample_id="s",
            task_name="t",
            prompt="p",
            reward=1.0,
            answer="PASS",
            agent_exit_code=0,
            agent_stdout="",
            verifier=verifier,
        )


def test_read_agent_version_first_line_and_fail_soft(capsys):
    from boundarybench.terminalbench.daytona_run import read_agent_version

    class _VersionProcess:
        def __init__(self, result):
            self._result = result
            self.command = ""

        def exec(self, command, *, timeout, env=None):
            self.command = command
            return self._result

    class _Box:
        def __init__(self, process):
            self.process = process

    adapter = ClaudeCodeAdapter()
    ok = _Box(_VersionProcess(_FakeResult(0, "1.0.61 (Claude Code)\nnoise")))
    assert (
        read_agent_version(ok, harness=adapter, run_as_root=False)
        == "1.0.61 (Claude Code)"
    )
    assert "--version" in ok.process.command
    assert DAYTONA_CLAUDE_BIN in ok.process.command

    failed = _Box(_VersionProcess(_FakeResult(3, "boom")))
    assert read_agent_version(failed, harness=adapter, run_as_root=False) is None

    class _RaisingProcess:
        def exec(self, command, *, timeout, env=None):
            raise RuntimeError("exec transport down")

    assert (
        read_agent_version(_Box(_RaisingProcess()), harness=adapter, run_as_root=False)
        is None
    )
    assert "agent version read failed" in capsys.readouterr().out


_SESSION_STREAM_OUTPUT = (
    "===INSPECT-BOUNDARY-SESSION-COUNT 4===\n"
    "===INSPECT-BOUNDARY-SESSION-FILE "
    "/home/daytona/.codex/sessions/2026/07/09/rollout-a.jsonl 8===\n"
    '{"a": 1}\n'
    "===INSPECT-BOUNDARY-SESSION-FILE "
    "/home/daytona/.codex/sessions/2026/07/09/rollout-b.jsonl 999999999===\n"
    '{"b": 2}\n'
    "===INSPECT-BOUNDARY-SESSION-FILE "
    "/home/daytona/.codex/sessions/2026/07/09/rollout-c.jsonl 9===\n"
    '{"c": 3}\n'
)


class _SessionProcess:
    def __init__(self, result: str = _SESSION_STREAM_OUTPUT) -> None:
        self._result = result
        self.command = ""

    def exec(self, command: str, *, timeout: int, env=None):
        self.command = command
        return _FakeResult(0, self._result)


class _SessionBox:
    def __init__(self, process) -> None:
        self.process = process
        self.id = "sandbox-1"


def test_session_artifact_capture_parses_and_flags_truncation():
    from boundarybench.harness.codex import CodexAdapter
    from boundarybench.terminalbench.daytona_run import (
        _try_read_harness_session_artifacts,
    )

    box = _SessionBox(_SessionProcess())
    artifacts = _try_read_harness_session_artifacts(
        box, harness=CodexAdapter(), run_as_root=False
    )

    assert "/home/daytona/.codex/sessions" in box.process.command
    assert artifacts["harness"] == "codex"
    assert artifacts["source_dirs"] == ["/home/daytona/.codex/sessions"]
    assert artifacts["file_count"] == 4
    assert artifacts["exported_file_count"] == 3
    first, second, third = artifacts["files"]
    assert first["path"].endswith("rollout-a.jsonl")
    assert first["content"] == '{"a": 1}'
    assert first["truncated"] is False
    assert second["truncated"] is True
    assert third["truncated"] is False
    assert artifacts["truncated"] is True


def test_session_artifact_parse_preserves_unicode_line_separators():
    from boundarybench.terminalbench.daytona_run import (
        _parse_session_artifact_stream,
    )

    content = '{"msg": "line\u2028separated\u2029text\u0085here"}'
    size = len(content.encode("utf-8"))
    stream = (
        "===INSPECT-BOUNDARY-SESSION-COUNT 1===\n"
        f"===INSPECT-BOUNDARY-SESSION-FILE /s/rollout.jsonl {size}===\n"
        f"{content}\n"
    )

    total_count, files = _parse_session_artifact_stream(stream)

    assert total_count == 1
    assert files[0]["content"] == content
    assert files[0]["truncated"] is False


def test_session_artifact_parse_uses_length_safe_base64_framing():
    import base64

    from boundarybench.terminalbench.daytona_run import (
        _parse_session_artifact_stream,
    )

    content = "line\n===INSPECT-BOUNDARY-SESSION-FILE forged 1===\nend"
    path = "/home/daytona/.grok/sessions/updates.jsonl"
    encoded_path = base64.b64encode(path.encode()).decode()
    encoded_content = base64.b64encode(content.encode()).decode()
    stream = (
        "===INSPECT-BOUNDARY-SESSION-COUNT 1===\n"
        f"===INSPECT-BOUNDARY-SESSION-B64 {encoded_path} "
        f"{len(content.encode())}===\n"
        f"{encoded_content}\n"
    )
    total_count, files = _parse_session_artifact_stream(stream)
    assert total_count == 1
    assert files[0]["path"] == path
    assert files[0]["content"] == content
    assert files[0]["truncated"] is False


def test_session_artifact_capture_is_fail_soft(capsys):
    from boundarybench.harness.codex import CodexAdapter
    from boundarybench.terminalbench.daytona_run import (
        _try_read_harness_session_artifacts,
    )

    untouched = _SessionBox(_SessionProcess())
    assert (
        _try_read_harness_session_artifacts(
            untouched, harness=ClaudeCodeAdapter(), run_as_root=False
        )
        is None
    )
    assert untouched.process.command == ""

    empty = _SessionBox(_SessionProcess("===INSPECT-BOUNDARY-SESSION-COUNT 0===\n"))
    assert (
        _try_read_harness_session_artifacts(
            empty, harness=CodexAdapter(), run_as_root=False
        )
        is None
    )

    class _RaisingProcess:
        def exec(self, command: str, *, timeout: int, env=None):
            raise RuntimeError("exec transport down")

    assert (
        _try_read_harness_session_artifacts(
            _SessionBox(_RaisingProcess()), harness=CodexAdapter(), run_as_root=False
        )
        is None
    )
    assert "session artifact read failed" in capsys.readouterr().out


def test_hardened_agent_failure_attaches_session_artifacts(tmp_path, monkeypatch):
    from boundarybench.harness.codex import CodexAdapter

    sandbox = _SessionBox(_SessionProcess())
    sandbox.fs = _FakeFs()
    bundle = _bundle(tmp_path)

    def exploding_hardened_run(_sandbox, **kwargs):
        raise RuntimeError("agent process died")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        exploding_hardened_run,
    )

    with pytest.raises(RuntimeError, match="agent process died") as excinfo:
        run_terminalbench_task_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=_hardening(),
            openrouter_api_key="sk-or-secret",
            model="minimax/minimax-m3",
            harness=CodexAdapter(),
        )

    attached = excinfo.value.harness_session_artifacts
    assert attached["exported_file_count"] == 3
    assert attached["harness"] == "codex"


def test_provision_requires_explicit_harness():
    daytona = _FakeDaytonaCreate()

    with pytest.raises(TypeError):
        provision_hardened_task_sandbox(
            daytona,
            image="registry/example:1",
            install_policy_hardening=False,
        )


def test_run_terminalbench_task_requires_explicit_harness(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    with pytest.raises(TypeError):
        run_terminalbench_task_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=_hardening(),
            openrouter_api_key="sk-or-secret",
            model="minimax/minimax-m3",
        )


def _install_command(daytona: _FakeDaytonaCreate) -> str:
    return next(
        c
        for c in daytona.sandbox.process.commands
        if "ia_egress" in c or "policy_msg" in c
    )


def test_provision_hardened_task_sandbox_native_mode_installs_native_hardening():
    from boundarybench.daytona.policy_axes import (
        AXIS_PRESETS,
        build_daytona_config_from_axes,
    )

    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        hardening_config=build_daytona_config_from_axes(AXIS_PRESETS["low-nist"]),
        enforcement_mode="native",
        harness=ClaudeCodeAdapter(),
    )

    install_command = _install_command(daytona)
    assert "nft add table inet ia_egress" in install_command
    assert "policy_msg" not in install_command
    assert "LD_PRELOAD" not in install_command
    assert "deny-command.sh" not in install_command


def test_provision_hardened_task_sandbox_defaults_to_legacy_install():
    from boundarybench.daytona.policy_axes import (
        AXIS_PRESETS,
        build_daytona_config_from_axes,
    )

    daytona = _FakeDaytonaCreate()

    provision_hardened_task_sandbox(
        daytona,
        image="registry/example:1",
        hardening_config=build_daytona_config_from_axes(AXIS_PRESETS["low-nist"]),
        harness=ClaudeCodeAdapter(),
    )

    install_command = _install_command(daytona)
    assert "policy_msg.c" in install_command
    assert "deny-command.sh" in install_command
    assert "nft add table inet ia_egress" not in install_command


def test_run_terminalbench_task_native_mode_uses_native_exec_chain(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        enforcement_mode="native",
        harness=ClaudeCodeAdapter(),
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert "setpriv --reuid=" in agent_cmd
    assert "LD_PRELOAD" not in agent_cmd
    assert "BOUNDARY_" not in agent_cmd
    assert "sk-or-secret" not in agent_cmd


def test_run_terminalbench_task_defaults_to_legacy_exec_chain(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        harness=ClaudeCodeAdapter(),
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert f"LD_PRELOAD={DEFAULT_HARDENING_ASSET_DIR}/policy.so" in agent_cmd
    assert "BOUNDARY_" in agent_cmd


def test_native_run_removes_hardening_assets_before_agent(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        enforcement_mode="native",
        harness=ClaudeCodeAdapter(),
    )

    cleanup_commands = [
        command
        for command in sandbox.process.commands
        if command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}")
    ]
    assert cleanup_commands == [
        f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR} "
        f"&& test ! -e {DEFAULT_HARDENING_ASSET_DIR}"
    ]
    cleanup_index = sandbox.process.commands.index(cleanup_commands[0])
    agent_index = next(
        index
        for index, command in enumerate(sandbox.process.commands)
        if CLAUDE_BIN in command
    )
    assert cleanup_index < agent_index


def test_legacy_run_retains_hardening_assets(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_task_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        model="minimax/minimax-m3",
        harness=ClaudeCodeAdapter(),
    )

    assert not any(
        command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}")
        for command in sandbox.process.commands
    )


@pytest.mark.parametrize("agent_only", [False, True])
@pytest.mark.parametrize("enforcement_mode", ["native", "legacy"])
def test_pre_agent_cleanup_removes_probe_scratch_before_agent(
    tmp_path, agent_only, enforcement_mode
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    kwargs = {
        "daytona_policy_hardening": _native_hardening(),
        "openrouter_api_key": "sk-or-secret",
        "model": "minimax/minimax-m3",
        "enforcement_mode": enforcement_mode,
        "harness": ClaudeCodeAdapter(),
    }

    if agent_only:
        run_terminalbench_agent_in_daytona(sandbox, bundle, **kwargs)
    else:
        run_terminalbench_task_in_daytona(sandbox, bundle, **kwargs)

    denied_workspace = str(Path(DEFAULT_APPARMOR_DENIED_PATH).parent)
    scratch_dirs = (
        RUNTIME_POLICY_PROBE_WORKSPACE,
        DEFAULT_APPARMOR_PROBE_WORKSPACE,
        denied_workspace,
        "/var/boundarybench-mac-denied",
    )
    scratch_globs = (
        "/tmp/boundarybench-secret-link*",
        "/tmp/boundarybench-write-link*",
        "/tmp/boundarybench-mac-*",
    )
    cleanup_command = next(
        command
        for command in sandbox.process.commands
        if command.startswith(f"rm -rf -- {RUNTIME_POLICY_PROBE_WORKSPACE}")
    )
    assert cleanup_command == (
        f"rm -rf -- {' '.join((*scratch_dirs, *scratch_globs))} && "
        + " && ".join(f"test ! -e {path}" for path in scratch_dirs)
        + ' && scratch_matches="$(find /tmp -maxdepth 1 '
        + "\\( -name 'boundarybench-secret-link*' "
        + "-o -name 'boundarybench-write-link*' "
        + "-o -name 'boundarybench-mac-*' \\) -print -quit)\" "
        + '&& test -z "$scratch_matches"'
    )

    cleanup_index = sandbox.process.commands.index(cleanup_command)
    agent_index = next(
        index
        for index, command in enumerate(sandbox.process.commands)
        if CLAUDE_BIN in command
    )
    assert cleanup_index < agent_index


@pytest.mark.parametrize("agent_only", [False, True])
@pytest.mark.parametrize("enforcement_mode", ["native", "legacy"])
def test_probe_scratch_cleanup_failure_prevents_agent_launch(
    tmp_path, agent_only, enforcement_mode
):
    class _CleanupFailureProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            if command.startswith(f"rm -rf -- {RUNTIME_POLICY_PROBE_WORKSPACE}"):
                self.commands.append(command)
                self.envs.append(env)
                return _FakeResult(1, "cleanup failed")
            return super().exec(command, timeout=timeout, env=env)

    sandbox = _FakeSandbox()
    sandbox.process = _CleanupFailureProcess()
    bundle = _bundle(tmp_path)
    kwargs = {
        "daytona_policy_hardening": _native_hardening(),
        "openrouter_api_key": "sk-or-secret",
        "model": "minimax/minimax-m3",
        "enforcement_mode": enforcement_mode,
        "harness": ClaudeCodeAdapter(),
    }

    with pytest.raises(RuntimeError, match="failed to remove pre-agent probe scratch"):
        if agent_only:
            run_terminalbench_agent_in_daytona(sandbox, bundle, **kwargs)
        else:
            run_terminalbench_task_in_daytona(sandbox, bundle, **kwargs)

    assert not any(CLAUDE_BIN in command for command in sandbox.process.commands)


def test_native_asset_cleanup_failure_prevents_agent_launch(tmp_path):
    class _CleanupFailureProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            if command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}"):
                self.commands.append(command)
                self.envs.append(env)
                return _FakeResult(1, "cleanup failed")
            return super().exec(command, timeout=timeout, env=env)

    sandbox = _FakeSandbox()
    sandbox.process = _CleanupFailureProcess()
    bundle = _bundle(tmp_path)

    with pytest.raises(RuntimeError, match="failed to remove native hardening assets"):
        run_terminalbench_task_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=_native_hardening(),
            openrouter_api_key="sk-or-secret",
            model="minimax/minimax-m3",
            enforcement_mode="native",
            harness=ClaudeCodeAdapter(),
        )

    assert not any(CLAUDE_BIN in command for command in sandbox.process.commands)


@pytest.mark.parametrize(
    "asset_dir",
    [
        "",
        "/",
        "/.",
        "/tmp/..",
        "//",
        "//.",
        "//tmp/..",
        "/opt",
        "/home",
        "opt/h",
        "./opt/h",
    ],
)
def test_native_asset_cleanup_rejects_unsafe_directory_before_agent_launch(
    tmp_path, asset_dir
):
    hardening = _native_hardening()
    unsafe_hardening = DaytonaPolicyHardening(
        asset_dir=asset_dir,
        policy_message_preload_so=hardening.policy_message_preload_so,
        block_message_command=hardening.block_message_command,
        mount_real_path=hardening.mount_real_path,
        policy_bin_dir=hardening.policy_bin_dir,
        child_network_block_env=hardening.child_network_block_env,
        hardening_config=hardening.hardening_config,
    )
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    with pytest.raises(RuntimeError, match="failed to remove native hardening assets"):
        run_terminalbench_task_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=unsafe_hardening,
            openrouter_api_key="sk-or-secret",
            model="minimax/minimax-m3",
            enforcement_mode="native",
            harness=ClaudeCodeAdapter(),
        )

    assert not any(
        command.startswith("rm -rf --") for command in sandbox.process.commands
    )
    assert not any(CLAUDE_BIN in command for command in sandbox.process.commands)


def test_run_terminalbench_agent_native_mode_uses_native_exec_chain(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        enforcement_mode="native",
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert "setpriv --reuid=" in agent_cmd
    assert "LD_PRELOAD" not in agent_cmd
    assert "BOUNDARY_" not in agent_cmd


def test_run_terminalbench_agent_defaults_to_legacy_exec_chain(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    assert f"LD_PRELOAD={DEFAULT_HARDENING_ASSET_DIR}/policy.so" in agent_cmd
    assert "BOUNDARY_" in agent_cmd


@pytest.mark.parametrize("hardened", [False, True])
@pytest.mark.parametrize("isolate_agent_pid_namespace", [False, True])
def test_run_terminalbench_agent_pid_namespace_is_opt_in(
    tmp_path, hardened, isolate_agent_pid_namespace
):
    sandbox = _FakeSandbox()
    if isolate_agent_pid_namespace:
        class ConfirmingPidNamespaceProcess(_FakeProcess):
            token = ""

            def exec(self, command: str, *, timeout: int, env=None):
                if command == "readlink /proc/self/ns/pid":
                    return _FakeResult(0, "pid:[100]\n")
                match = re.search(r"IA_PIDNS_TOKEN=([0-9a-f]+);", command)
                if match:
                    self.token = match.group(1)
                if command.startswith("stat -c '%u %a'"):
                    return _FakeResult(0, f"0 400\n{self.token}\n1\npid:[200]\n")
                return super().exec(command, timeout=timeout, env=env)

        sandbox.process = ConfirmingPidNamespaceProcess()
    bundle = _bundle(tmp_path)

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening() if hardened else None,
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        isolate_agent_pid_namespace=isolate_agent_pid_namespace,
    )

    agent_cmd = next(c for c in sandbox.process.commands if CLAUDE_BIN in c)
    pid_boundary = "unshare --pid --fork --mount-proc --kill-child=SIGKILL"
    assert (pid_boundary in agent_cmd) is isolate_agent_pid_namespace
    assert result.agent_pid_namespace_isolation_observed is isolate_agent_pid_namespace


@pytest.mark.parametrize("marker_output", [None, "0 400\nspoof\n1\npid:[100]\n"])
def test_run_terminalbench_agent_pid_namespace_rejects_missing_or_spoofed_marker(
    tmp_path, marker_output
):
    class InvalidPidNamespaceMarkerProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            if command == "readlink /proc/self/ns/pid":
                return _FakeResult(0, "pid:[100]\n")
            if command.startswith("stat -c '%u %a'"):
                if marker_output is None:
                    return _FakeResult(1, "missing")
                return _FakeResult(0, marker_output)
            return super().exec(command, timeout=timeout, env=env)

    sandbox = _FakeSandbox()
    sandbox.process = InvalidPidNamespaceMarkerProcess()

    with pytest.raises(RuntimeError, match="PID namespace isolation confirmation"):
        run_terminalbench_agent_in_daytona(
            sandbox,
            _bundle(tmp_path),
            daytona_policy_hardening=None,
            openrouter_api_key="sk-or-secret",
            harness=ClaudeCodeAdapter(),
            model="minimax/minimax-m3",
            isolate_agent_pid_namespace=True,
        )


def test_agent_preserve_session_flows_through_hardened_branch(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    hardened_calls: list[dict] = []

    def fake_hardened_run(_sandbox, **kwargs):
        hardened_calls.append(kwargs)
        return DaytonaCommandResult(
            exit_code=0,
            stdout="agent ok",
            session_id="ia-model-agent-abc",
            post_command_probe_output="tcp LISTEN 0.0.0.0:8080",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        fake_hardened_run,
    )

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        preserve_agent_session=True,
    )

    assert len(hardened_calls) == 1
    assert hardened_calls[0]["preserve_session"] is True
    assert hardened_calls[0]["session_id_prefix"] == MODEL_AGENT_SESSION_PREFIX
    assert hardened_calls[0]["post_command_probe"] == AGENT_LISTENER_PROBE_COMMAND
    assert result.agent_session_id == "ia-model-agent-abc"
    assert result.agent_session_preserved is True
    assert result.post_agent_listeners == "tcp LISTEN 0.0.0.0:8080"


def test_terminus_preserve_session_defers_teardown_until_verified(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    calls: list[dict] = []

    def fake_deadline_run(_sandbox, **kwargs):
        calls.append(kwargs)
        return DaytonaCommandResult(
            exit_code=0,
            stdout='TERMINUS2_RESULT {"type": "terminus_2.result", "status": "ok"}',
            session_id="ia-model-agent-abc",
            post_command_probe_output="tcp LISTEN 0.0.0.0:8080",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run._run_command_with_deadline",
        fake_deadline_run,
    )

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        harness=Terminus2Adapter(),
        model="deepseek/deepseek-v4-flash",
        preserve_agent_session=True,
    )

    assert calls[0]["env"][PRESERVE_AGENT_SESSION_ENV] == "1"
    assert result.agent_session_preserved is True
    assert not any(
        "tmux kill-session" in command for command in sandbox.process.commands
    )


def test_terminus_without_preserve_still_runs_teardown(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    calls: list[dict] = []

    def fake_deadline_run(_sandbox, **kwargs):
        calls.append(kwargs)
        return DaytonaCommandResult(
            exit_code=0,
            stdout='TERMINUS2_RESULT {"type": "terminus_2.result", "status": "ok"}',
            session_id=None,
            post_command_probe_output="",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run._run_command_with_deadline",
        fake_deadline_run,
    )

    run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        harness=Terminus2Adapter(),
        model="deepseek/deepseek-v4-flash",
        preserve_agent_session=False,
    )

    assert PRESERVE_AGENT_SESSION_ENV not in calls[0]["env"]
    assert any(
        "tmux kill-session" in command for command in sandbox.process.commands
    )


def test_agent_preserve_session_flows_through_control_branch(tmp_path, monkeypatch):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    control_calls: list[dict] = []

    def fake_deadline_run(_sandbox, **kwargs):
        control_calls.append(kwargs)
        return DaytonaCommandResult(
            exit_code=0,
            stdout="agent ok",
            session_id="ia-model-agent-abc",
            post_command_probe_output="tcp LISTEN 0.0.0.0:8080",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run._run_command_with_deadline",
        fake_deadline_run,
    )

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=None,
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        preserve_agent_session=True,
    )

    assert len(control_calls) == 1
    assert control_calls[0]["preserve_session"] is True
    assert control_calls[0]["session_id_prefix"] == MODEL_AGENT_SESSION_PREFIX
    assert control_calls[0]["post_command_probe"] == AGENT_LISTENER_PROBE_COMMAND
    assert result.agent_session_id == "ia-model-agent-abc"
    assert result.agent_session_preserved is True
    assert result.post_agent_listeners == "tcp LISTEN 0.0.0.0:8080"


def test_agent_session_not_preserved_by_default_but_probe_still_runs(
    tmp_path, monkeypatch
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    hardened_calls: list[dict] = []

    def fake_hardened_run(_sandbox, **kwargs):
        hardened_calls.append(kwargs)
        return DaytonaCommandResult(
            exit_code=0,
            stdout="agent ok",
            session_id="ia-model-agent-xyz",
            post_command_probe_output="tcp LISTEN 0.0.0.0:8080",
        )

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        fake_hardened_run,
    )

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
    )

    assert hardened_calls[0]["preserve_session"] is False
    assert hardened_calls[0]["session_id_prefix"] == MODEL_AGENT_SESSION_PREFIX
    assert hardened_calls[0]["post_command_probe"] == AGENT_LISTENER_PROBE_COMMAND
    assert result.agent_session_preserved is False
    assert result.post_agent_listeners == "tcp LISTEN 0.0.0.0:8080"


def _linux_process_descendants(pid: int) -> set[int]:
    descendants: set[int] = set()
    pending = [pid]
    while pending:
        parent = pending.pop()
        children_path = Path(f"/proc/{parent}/task/{parent}/children")
        try:
            children = [int(value) for value in children_path.read_text().split()]
        except FileNotFoundError:
            continue
        for child in children:
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def test_agent_pid_namespace_reaps_detached_child_but_keeps_workspace(tmp_path):
    if sys.platform != "linux":
        pytest.skip("requires Linux PID namespaces")
    unshare = shutil.which("unshare")
    setsid = shutil.which("setsid")
    nohup = shutil.which("nohup")
    if unshare is None or setsid is None or nohup is None:
        pytest.skip("requires util-linux unshare/setsid and nohup")
    namespace_args = [
        unshare,
        "--pid",
        "--fork",
        "--mount-proc",
        "--kill-child=SIGKILL",
        "--",
    ]
    probe = subprocess.run(
        [*namespace_args, "/bin/true"],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip(f"PID namespace creation unavailable: {probe.stderr.strip()}")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sentinel = workspace / "agent-output"
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    script = (
        f"{shlex.quote(setsid)} {shlex.quote(nohup)} "
        "/bin/sh -c 'while :; do sleep 1; done' "
        ">/dev/null 2>&1 & "
        f"printf preserved > {shlex.quote(str(sentinel))}; "
        f"touch {shlex.quote(str(ready))}; "
        f"while [ ! -e {shlex.quote(str(release))} ]; do sleep 0.01; done"
    )
    process = subprocess.Popen(
        [*namespace_args, "/bin/sh", "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                pytest.fail("PID namespace test did not start its detached child")
            time.sleep(0.01)
        descendants = _linux_process_descendants(process.pid)
        assert len(descendants) >= 2

        release.touch()
        _, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        assert sentinel.read_text() == "preserved"

        deadline = time.monotonic() + 5
        while any(Path(f"/proc/{pid}").exists() for pid in descendants):
            if time.monotonic() >= deadline:
                surviving = [
                    pid for pid in descendants if Path(f"/proc/{pid}").exists()
                ]
                pytest.fail(
                    f"PID namespace descendants survived init exit: {surviving}"
                )
            time.sleep(0.01)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("hardened", [False, True])
def test_run_terminalbench_agent_explicit_false_preserves_default_command(
    tmp_path, hardened
):
    bundle = _bundle(tmp_path)
    default_sandbox = _FakeSandbox()
    explicit_false_sandbox = _FakeSandbox()
    common = {
        "daytona_policy_hardening": _hardening() if hardened else None,
        "openrouter_api_key": "sk-or-secret",
        "harness": ClaudeCodeAdapter(),
        "model": "minimax/minimax-m3",
    }

    run_terminalbench_agent_in_daytona(default_sandbox, bundle, **common)
    run_terminalbench_agent_in_daytona(
        explicit_false_sandbox,
        bundle,
        isolate_agent_pid_namespace=False,
        **common,
    )

    default_command = next(
        command for command in default_sandbox.process.commands if CLAUDE_BIN in command
    )
    explicit_false_command = next(
        command
        for command in explicit_false_sandbox.process.commands
        if CLAUDE_BIN in command
    )
    assert explicit_false_command == default_command


@pytest.mark.parametrize("hardened", [False, True])
def test_run_terminalbench_agent_pid_namespace_fails_closed_before_launch(
    tmp_path, hardened
):
    class _UnsupportedPidNamespaceProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            self.commands.append(command)
            self.envs.append(env)
            if command.endswith("-- /bin/true") and "unshare --pid" in command:
                return _FakeResult(1, "unshare: Operation not permitted")
            return _FakeResult(0, "ok")

    sandbox = _FakeSandbox()
    sandbox.process = _UnsupportedPidNamespaceProcess()

    with pytest.raises(RuntimeError, match="PID namespace isolation unavailable"):
        run_terminalbench_agent_in_daytona(
            sandbox,
            _bundle(tmp_path),
            daytona_policy_hardening=_hardening() if hardened else None,
            openrouter_api_key="sk-or-secret",
            harness=ClaudeCodeAdapter(),
            model="minimax/minimax-m3",
            isolate_agent_pid_namespace=True,
        )

    assert not any(CLAUDE_BIN in command for command in sandbox.process.commands)


@pytest.mark.parametrize(
    ("agent_workdir", "workspace_root"),
    [
        ("/workspace", "/workspace"),
        ("/app/personal-site", "/app"),
        ("/app/dclm", "/app"),
    ],
)
def test_run_terminalbench_agent_uses_resolved_workdir_and_policy_root(
    tmp_path, monkeypatch, agent_workdir, workspace_root
):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)
    hardened_calls: list[dict] = []

    def fake_hardened_run(_sandbox, **kwargs):
        hardened_calls.append(kwargs)
        return DaytonaCommandResult(exit_code=0, stdout="agent ok")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_run.run_with_daytona_policy_hardening",
        fake_hardened_run,
    )

    result = run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        agent_workdir=agent_workdir,
        workspace_root=workspace_root,
    )

    assert hardened_calls[0]["cwd"] == agent_workdir
    assert hardened_calls[0]["workspace"] == workspace_root
    assert result.agent_workdir == agent_workdir
    assert result.workspace_root == workspace_root


def test_native_agent_run_removes_hardening_assets_before_agent(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
        enforcement_mode="native",
    )

    cleanup_commands = [
        command
        for command in sandbox.process.commands
        if command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}")
    ]
    assert cleanup_commands == [
        f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR} "
        f"&& test ! -e {DEFAULT_HARDENING_ASSET_DIR}"
    ]
    cleanup_index = sandbox.process.commands.index(cleanup_commands[0])
    agent_index = next(
        index
        for index, command in enumerate(sandbox.process.commands)
        if CLAUDE_BIN in command
    )
    assert cleanup_index < agent_index


def test_legacy_agent_run_retains_hardening_assets(tmp_path):
    sandbox = _FakeSandbox()
    bundle = _bundle(tmp_path)

    run_terminalbench_agent_in_daytona(
        sandbox,
        bundle,
        daytona_policy_hardening=_native_hardening(),
        openrouter_api_key="sk-or-secret",
        harness=ClaudeCodeAdapter(),
        model="minimax/minimax-m3",
    )

    assert not any(
        command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}")
        for command in sandbox.process.commands
    )


def test_native_agent_asset_cleanup_failure_prevents_agent_launch(tmp_path):
    class _CleanupFailureProcess(_FakeProcess):
        def exec(self, command: str, *, timeout: int, env=None):
            if command.startswith(f"rm -rf -- {DEFAULT_HARDENING_ASSET_DIR}"):
                self.commands.append(command)
                self.envs.append(env)
                return _FakeResult(1, "cleanup failed")
            return super().exec(command, timeout=timeout, env=env)

    sandbox = _FakeSandbox()
    sandbox.process = _CleanupFailureProcess()
    bundle = _bundle(tmp_path)

    with pytest.raises(RuntimeError, match="failed to remove native hardening assets"):
        run_terminalbench_agent_in_daytona(
            sandbox,
            bundle,
            daytona_policy_hardening=_native_hardening(),
            openrouter_api_key="sk-or-secret",
            harness=ClaudeCodeAdapter(),
            model="minimax/minimax-m3",
            enforcement_mode="native",
        )

    assert not any(CLAUDE_BIN in command for command in sandbox.process.commands)


def test_daytona_eval_managed_runner_alias_uses_agent_only_run():
    import boundarybench.terminalbench.daytona_eval as daytona_eval

    assert (
        daytona_eval.run_terminalbench_task_in_daytona
        is run_terminalbench_agent_in_daytona
    )


def test_listener_probe_does_not_depend_on_ss_or_netstat():
    stages = AGENT_LISTENER_PROBE_COMMAND.split("||")
    assert "ss -tulpen" in stages[0]
    assert "netstat -tulpen" in stages[1]
    assert any("/proc/net/tcp" in stage for stage in stages[2:-1])
    assert "listener-probe-unavailable" in stages[-1]
