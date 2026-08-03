from __future__ import annotations

import json
from types import SimpleNamespace

import yaml

from boundarybench.daytona.agentsh_session import (
    prepare_daytona_agentsh_session,
)
from boundarybench.terminalbench.policies import (
    _NIST_LINUX_80053_HIGH_AGENTSH_CONFIG,
    _NIST_LINUX_80053_LOW_AGENTSH_CONFIG,
)


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: int):
        self.commands.append(command)
        if "agentsh session create" in command:
            return SimpleNamespace(
                exit_code=0,
                result=json.dumps({"id": "session-managed-example"}),
            )
        return SimpleNamespace(exit_code=0, result="ok")


class _FakeFs:
    def __init__(self) -> None:
        self.uploads: list[tuple[str, str, str]] = []

    def upload_file(self, local_path: str, remote_path: str) -> None:
        with open(local_path, encoding="utf-8") as uploaded:
            self.uploads.append((local_path, remote_path, uploaded.read()))


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()
        self.fs = _FakeFs()


def test_prepare_daytona_agentsh_session_uploads_policy_and_creates_session():
    sandbox = _FakeSandbox()
    assert _NIST_LINUX_80053_HIGH_AGENTSH_CONFIG is not None

    session = prepare_daytona_agentsh_session(
        sandbox,
        config=_NIST_LINUX_80053_HIGH_AGENTSH_CONFIG,
        run_id="terminalbench-agentsh-test",
    )

    assert session.session_id == "session-managed-example"
    assert session.config_id == "nist-linux-80053-high-agentsh-policy-v1"
    assert (
        session.remote_policy_dir
        == "/home/daytona/.boundarybench-agentsh/terminalbench-agentsh-test"
    )
    assert (
        session.remote_workspace
        == "/home/daytona/boundarybench-runs/terminalbench-agentsh-test"
    )

    uploads_by_remote = {
        remote: contents for _local, remote, contents in sandbox.fs.uploads
    }
    assert len(uploads_by_remote) == 2

    policy_text = next(
        text
        for remote, text in uploads_by_remote.items()
        if remote.endswith(f"{session.policy_name}.yaml")
    )
    assert "deny-configured-read-paths" in policy_text
    assert "deny-configured-read-path-write-guard" in policy_text
    assert "deny-configured-write-paths" in policy_text
    assert "'/etc/shadow'" in policy_text
    assert "'/root/.ssh/**'" in policy_text
    assert (
        "operations: ['read', 'open', 'stat', 'list', 'readlink', 'access']"
        in policy_text
    )
    assert (
        "operations: ['write', 'create', 'mkdir', 'symlink', 'chmod', 'chown', "
        "'rename', 'link', 'refer', 'delete', 'rmdir']"
    ) in policy_text

    config_text = uploads_by_remote[
        "/home/daytona/.boundarybench-agentsh/terminalbench-agentsh-test/"
        "boundarybench-agentsh-config.yaml"
    ]
    assert session.remote_policy_dir in config_text
    assert "/tmp/boundarybench-agentsh-policy-" not in config_text
    assert "proxy:\n  mode: 'disabled'" in config_text
    parsed_config = yaml.safe_load(config_text)
    assert parsed_config["sandbox"]["ptrace"]["trace"]["network"] is False

    commands = "\n".join(sandbox.process.commands)
    assert "mkdir -p" in commands
    assert "/usr/bin/agentsh policy --config" in commands
    assert "ensure_agentsh_server" not in commands
    assert "/usr/bin/agentsh server --config" in commands
    assert "/usr/bin/agentsh session create --json" in commands
    assert f"--workspace {session.remote_workspace}" in commands
    assert f"--policy {session.policy_name}" in commands

    metadata = session.to_metadata()
    assert metadata["session_id"] == "session-managed-example"
    assert metadata["policy_digest"] == session.policy_digest
    assert metadata["config_id"] == "nist-linux-80053-high-agentsh-policy-v1"


def test_prepare_daytona_agentsh_session_ensures_agentsh_binary_before_validation():
    sandbox = _FakeSandbox()
    assert _NIST_LINUX_80053_LOW_AGENTSH_CONFIG is not None

    prepare_daytona_agentsh_session(
        sandbox,
        config=_NIST_LINUX_80053_LOW_AGENTSH_CONFIG,
        run_id="terminalbench-agentsh-install-test",
    )

    ensure_index = next(
        index
        for index, command in enumerate(sandbox.process.commands)
        if "ensure-agentsh-binary" in command
    )
    validate_index = next(
        index
        for index, command in enumerate(sandbox.process.commands)
        if "/usr/bin/agentsh policy --config" in command
    )
    assert ensure_index < validate_index

    ensure_command = sandbox.process.commands[ensure_index]
    assert "cleanup_agentsh_downloads()" in ensure_command
    assert "trap cleanup_agentsh_downloads EXIT" in ensure_command
    assert 'rm -rf "$download_dir"' in ensure_command
