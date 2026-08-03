"""Tests for the in-sandbox Harbor Terminus-2 adapter."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from boundarybench.harness.adapter import HarnessAdapter, normalize_effort_level
from boundarybench.harness.registry import available_harnesses, get_harness_adapter
from boundarybench.harness.terminus_2 import (
    DAYTONA_TERMINUS_BIN,
    HARBOR_VERSION,
    PYTHON_VERSION,
    RESULT_PREFIX,
    ROOT_TERMINUS_BIN,
    TERMINUS_API_KEY_ENV,
    TERMINUS_REQUIREMENTS_LOCK_PATH,
    UV_VERSION,
    Terminus2Adapter,
    _result_object,
    _result_records,
    terminus_2_stream_diagnostics,
)


@pytest.fixture
def adapter() -> Terminus2Adapter:
    return Terminus2Adapter()


def _stdout(**overrides: object) -> str:
    result: dict[str, object] = {
        "type": "terminus_2.result",
        "status": "ok",
        "assistant_turns": 2,
        "tool_calls": 3,
        "final_message": "done",
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "cached_input_tokens": 25,
        },
    }
    result.update(overrides)
    return "harbor log noise\n" + RESULT_PREFIX + json.dumps(result)


def _session_artifacts() -> dict[str, object]:
    trajectory = {
        "steps": [
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:00Z",
                "message": "Analysis: inspect files\nPlan: run ls",
                "reasoning_content": "I should inspect the workspace.",
                "tool_calls": [
                    {
                        "tool_call_id": "call_1_1",
                        "function_name": "bash_command",
                        "arguments": {"keystrokes": "ls -la\n", "duration": 0.1},
                    }
                ],
                "observation": {"results": [{"content": "total 4\nfile.txt"}]},
            },
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:01Z",
                "message": "Analysis: verified\nPlan: finish",
                "tool_calls": [
                    {
                        "tool_call_id": "call_2_task_complete",
                        "function_name": "mark_task_complete",
                        "arguments": {},
                    }
                ],
                "observation": {"results": [{"content": "confirm"}]},
            },
            {
                "source": "agent",
                "timestamp": "2026-07-15T10:00:02Z",
                "message": "Analysis: done\nPlan: none",
                "tool_calls": [
                    {
                        "tool_call_id": "call_3_task_complete",
                        "function_name": "mark_task_complete",
                        "arguments": {},
                    }
                ],
                "observation": {"results": [{"content": "confirmed"}]},
            },
        ],
        "final_metrics": {
            "total_prompt_tokens": 100,
            "total_completion_tokens": 20,
            "total_cached_tokens": 25,
            "total_cost_usd": 0.001,
        },
    }
    return {
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


def _load_runner_module():
    pytest.importorskip("harbor")
    runtime_dir = (
        Path(__file__).parents[1]
        / "src/boundarybench/harness/runtime/harbor_terminus_2"
    )
    runner_path = runtime_dir / "bridge.py"
    spec = importlib.util.spec_from_file_location("terminus_2_runner_test", runner_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(runtime_dir))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(runtime_dir))
    return module


def test_registered_protocol_adapter(adapter: Terminus2Adapter):
    from boundarybench.harness import Terminus2Adapter as PublicAdapter

    assert isinstance(adapter, HarnessAdapter)
    assert PublicAdapter is Terminus2Adapter
    assert "terminus_2" in available_harnesses()
    assert isinstance(get_harness_adapter("terminus_2"), Terminus2Adapter)


def test_binary_and_home_paths_support_root_and_nonroot(adapter: Terminus2Adapter):
    assert adapter.agent_binary_path(run_as_root=False) == DAYTONA_TERMINUS_BIN
    assert adapter.agent_binary_path(run_as_root=True) == ROOT_TERMINUS_BIN
    assert adapter.home_runtime_subdirs == (".terminus-2",)
    assert adapter.session_artifact_dirs(run_as_root=False) == (
        "/home/daytona/.terminus-2/sessions",
    )
    assert adapter.session_artifact_dirs(run_as_root=True) == (
        "/root/.terminus-2/sessions",
    )


def test_harbor_pin_cannot_drift():
    """One Harbor version everywhere: pyproject extra, adapter constant,
    requirements.in, hashed lock, and (when installed) the controller package.
    """

    import importlib.metadata
    import tomllib

    root = Path(__file__).parents[1]
    pin = f"harbor=={HARBOR_VERSION}"

    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    harbor_extra = pyproject["project"]["optional-dependencies"]["harbor"]
    assert any(req.split(";")[0].strip() == pin for req in harbor_extra), (
        f"pyproject harbor extra must pin {pin}: {harbor_extra}"
    )

    runtime = root / "src/boundarybench/harness/runtime/harbor_terminus_2"
    requirements_in = (runtime / "requirements.in").read_text(encoding="utf-8")
    assert pin in requirements_in.split()
    lock_text = (runtime / "requirements.lock").read_text(encoding="utf-8")
    assert pin in lock_text.split()

    try:
        installed = importlib.metadata.version("harbor")
    except importlib.metadata.PackageNotFoundError:
        installed = None
    if installed is not None:
        assert installed == HARBOR_VERSION


def test_install_script_is_pinned_packaged_and_preboundary(adapter: Terminus2Adapter):
    script = adapter.runtime_layer_script(workdir="/workspace", run_as_root=False)
    assert f"HARBOR_VERSION={HARBOR_VERSION}" in script
    assert f"PYTHON_VERSION={PYTHON_VERSION}" in script
    assert f"UV_VERSION={UV_VERSION}" in script
    assert "${PYTHON_VERSION:-" not in script
    assert '"$uv_bin" python install "$PYTHON_VERSION"' in script
    assert "sha256sum -c -" in script
    assert "__UV_SHA256" not in script
    assert '"$uv_bin" pip sync --require-hashes' in script
    assert "install_tmux" in script
    assert "HARNESS_BOOTSTRAP_OK" in script
    assert "TERMINUS2_RESULT" in script
    assert "__TERMINUS_RUNNER_PY__" not in script
    assert "__TERMINUS_REQUIREMENTS_LOCK__" not in script
    assert "__TERMINUS_RESULT_PREFIX_PY__" not in script
    assert "terminus-2 2.0.0 (harbor 0.13.1)" in script
    assert "chown -R daytona:daytona" in script
    assert "sudo -H -u daytona" in script
    assert "--self-check" in script
    assets = adapter.runtime_layer_assets(run_as_root=False)
    assert set(assets) == {TERMINUS_REQUIREMENTS_LOCK_PATH}
    lock = assets[TERMINUS_REQUIREMENTS_LOCK_PATH].decode()
    assert "harbor==0.13.1" in lock
    assert "litellm==" in lock
    assert "--hash=sha256:" in lock
    assert len(script.encode()) < 128 * 1024


def test_agent_command_uses_file_transport_and_quotes_hostile_path(
    adapter: Terminus2Adapter,
):
    command = adapter.agent_command(
        model="deepseek/deepseek-v4-flash",
        prompt_path="/tmp/-prompt $(touch nope) ' quoted.txt",
        run_as_root=False,
        effort_level="high",
    )
    assert "--prompt-file '/tmp/-prompt $(touch nope) '" in command
    assert "--model deepseek/deepseek-v4-flash" in command
    assert "--effort high" in command
    assert "cat " not in command
    assert command.endswith("< /dev/null")


def test_model_validation_rejects_shell_syntax(adapter: Terminus2Adapter):
    with pytest.raises(ValueError, match="model id"):
        adapter.agent_command(
            model="model; touch /tmp/nope",
            prompt_path="/tmp/prompt",
            run_as_root=False,
        )


def test_effort_surface_matches_harbor_terminus(adapter: Terminus2Adapter):
    assert normalize_effort_level(adapter) == "high"
    for value in ("none", "minimal", "low", "medium", "high", "xhigh", "max"):
        assert normalize_effort_level(adapter, value) == value
    with pytest.raises(ValueError, match="unsupported effort"):
        normalize_effort_level(adapter, "turbo")


def test_key_uses_harness_alias_not_command_line(adapter: Terminus2Adapter):
    env = adapter.agent_env(provider_api_key="sk-or-secret", run_as_root=False)
    assert env == {
        TERMINUS_API_KEY_ENV: "sk-or-secret",
        "PYTHONUNBUFFERED": "1",
    }
    command = adapter.agent_command(
        model="deepseek/deepseek-v4-flash",
        prompt_path="/tmp/prompt",
        run_as_root=False,
    )
    assert "sk-or-secret" not in command
    assert TERMINUS_API_KEY_ENV not in command


def test_result_parser_tolerates_log_noise_and_uses_last_result():
    stdout = (
        RESULT_PREFIX
        + '{"status":"error"}\nnoise\n'
        + RESULT_PREFIX
        + '{"status":"ok","final_message":"yes"}'
    )
    assert _result_object(stdout) == {"status": "ok", "final_message": "yes"}


def test_result_parser_counts_each_malformed_sentinel_independently():
    stdout = (
        RESULT_PREFIX
        + "{bad json}\n"
        + RESULT_PREFIX
        + '{"status":"ok"}\n'
        + RESULT_PREFIX
        + "[]"
    )
    valid, malformed = _result_records(stdout)
    assert valid == [{"status": "ok"}]
    assert malformed == 2
    diagnostics = terminus_2_stream_diagnostics(stdout)
    assert diagnostics["agent_stdout_parse_error_count"] == 2
    assert diagnostics["agent_stdout_result_event_present"] is True


def test_controller_cleanup_kills_orphaned_tmux(adapter: Terminus2Adapter):
    assert adapter.post_agent_cleanup_command(run_as_root=False) == (
        "sudo -H -u daytona -- tmux kill-session -t terminus-2 >/dev/null 2>&1 || true"
    )
    assert adapter.post_agent_cleanup_command(run_as_root=True).startswith(
        "tmux kill-session -t terminus-2"
    )
    assert "kill-server" not in adapter.post_agent_cleanup_command(run_as_root=True)
    assert "pkill" not in adapter.post_agent_cleanup_command(run_as_root=False)


def test_runner_error_redacts_popped_key(monkeypatch, tmp_path, capsys):
    module = _load_runner_module()
    secret = "sk-or-v1-runner-secret-123456"
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("solve", encoding="utf-8")
    monkeypatch.setenv(module.API_KEY_ENV, secret)

    def fail_constructor(**kwargs):
        del kwargs
        raise RuntimeError(f"request rejected api_key={secret}")

    monkeypatch.setattr(module, "InSandboxTerminus2", fail_constructor)
    rc = asyncio.run(
        module._run(
            SimpleNamespace(
                model="deepseek/deepseek-v4-flash",
                prompt_file=str(prompt),
                logs_dir=str(tmp_path / "logs"),
                effort="default",
            )
        )
    )
    output = capsys.readouterr().out
    assert rc == 1
    assert secret not in output
    assert "[REDACTED]" in output


def test_runner_completion_pending_survives_parser_feedback(tmp_path):
    module = _load_runner_module()
    trajectory = {
        "steps": [
            {
                "source": "agent",
                "tool_calls": [{"function_name": "mark_task_complete"}],
            },
            {
                "source": "agent",
                "tool_calls": None,
                "observation": {
                    "results": [
                        {
                            "content": (
                                "Previous response had parsing errors:\nERROR: bad JSON"
                            )
                        }
                    ]
                },
            },
            {
                "source": "agent",
                "message": "done",
                "tool_calls": [{"function_name": "mark_task_complete"}],
            },
        ]
    }
    (tmp_path / "trajectory.json").write_text(json.dumps(trajectory), encoding="utf-8")
    summary = module._summary(tmp_path, module.AgentContext())
    assert summary["task_complete"] is True
    assert summary["final_message"] == "done"
    assert summary["tool_calls"] == 2
    assert summary["task_tool_calls"] == 0


def test_runner_restarts_dead_tmux_and_appends_pane_log(tmp_path):
    module = _load_runner_module()

    class Environment:
        default_user = None
        session_id = "test-session"

        def __init__(self):
            self.commands = []
            self.send_attempts = 0

        async def exec(self, command, **_kwargs):
            self.commands.append(command)
            if command.startswith("tmux send-keys"):
                self.send_attempts += 1
                if self.send_attempts == 1:
                    return module.ExecResult(
                        stdout="",
                        stderr="server exited unexpectedly\n",
                        return_code=1,
                    )
            if command.startswith("tmux has-session"):
                return module.ExecResult(stdout="", stderr="", return_code=1)
            return module.ExecResult(stdout="", stderr="", return_code=0)

    environment = Environment()
    pane = tmp_path / "terminus_2.pane"
    pane.write_text("before restart\n", encoding="utf-8")
    session = module.ResilientTmuxSession(
        session_name="terminus-2",
        environment=environment,
        logging_path=pane,
        local_asciinema_recording_path=None,
        remote_asciinema_recording_path=None,
    )

    asyncio.run(session.send_keys("echo recovered\n"))

    assert environment.send_attempts == 2
    assert session._restart_count == 1
    assert "before restart" in pane.read_text(encoding="utf-8")
    assert "tmux session restarted" in pane.read_text(encoding="utf-8")
    start_commands = [
        command for command in environment.commands if "tmux new-session" in command
    ]
    assert len(start_commands) == 1
    assert "cat >>" in start_commands[0]


def test_runner_preserves_initial_pane_truncation_and_guards_restart_command(
    tmp_path, monkeypatch
):
    module = _load_runner_module()
    session = module.ResilientTmuxSession(
        session_name="terminus-2",
        environment=object(),
        logging_path=tmp_path / "terminus_2.pane",
        local_asciinema_recording_path=None,
        remote_asciinema_recording_path=None,
    )

    assert "cat > " in session._tmux_start_session
    assert "cat >> " not in session._tmux_start_session

    session._restart_count = 1
    upstream_tmux_session = module.ResilientTmuxSession.__bases__[0]
    monkeypatch.setattr(
        upstream_tmux_session,
        "_tmux_start_session",
        property(lambda _self: "tmux new-session without-redirection"),
    )
    with pytest.raises(RuntimeError, match="expected pane-log redirection"):
        _ = session._tmux_start_session


def test_stdout_diagnostics_use_terminus_result_semantics():
    diagnostics = terminus_2_stream_diagnostics(_stdout())
    assert diagnostics["agent_stdout_result_event_present"] is True
    assert diagnostics["agent_stdout_result_event_usage_present"] is True
    assert diagnostics["agent_stdout_last_complete_event_type"] == "terminus_2.result"


def test_activity_and_provider_errors_avoid_false_positive(adapter: Terminus2Adapter):
    assert adapter.activity_summary(_stdout()) == {
        "assistant_turns": 2,
        "tool_calls": 3,
    }
    productive = _stdout(final_message="task text says unauthorized", status="ok")
    assert adapter.provider_auth_error(productive) is None
    failed = _stdout(status="error", error="HTTP 401 unauthorized", final_message="")
    assert adapter.provider_auth_error(failed) is not None


def test_parse_transcript_preserves_usage(adapter: Terminus2Adapter):
    messages, output = adapter.parse_transcript(
        prompt="solve",
        agent_stdout=_stdout(),
        model="deepseek/deepseek-v4-flash",
        pricing_model="deepseek/deepseek-v4-flash",
    )
    assert len(messages) == 2
    assert output.completion == "done"
    assert output.usage is not None
    assert output.usage.input_tokens == 100
    assert output.usage.output_tokens == 20
    assert output.usage.input_tokens_cache_read == 25
    assert output.usage.total_tokens == 120


def test_parse_transcript_keeps_runner_error_visible(adapter: Terminus2Adapter):
    messages, output = adapter.parse_transcript(
        prompt="solve",
        agent_stdout=_stdout(
            status="error",
            final_message="",
            error="CancelledError: provider stream closed",
        ),
        model="deepseek/deepseek-v4-flash",
        pricing_model="deepseek/deepseek-v4-flash",
    )

    assert [message.role for message in messages] == ["user", "assistant"]
    assert messages[-1].content == "CancelledError: provider stream closed"
    assert output.completion == "CancelledError: provider stream closed"


def test_parse_transcript_expands_atif_reasoning_tools_and_results(
    adapter: Terminus2Adapter,
):
    messages, output = adapter.parse_transcript(
        prompt="solve",
        agent_stdout=_stdout(task_complete=True),
        model="deepseek/deepseek-v4-flash",
        pricing_model="deepseek/deepseek-v4-flash",
        session_artifacts=_session_artifacts(),
    )

    assert [message.role for message in messages] == [
        "user",
        "assistant",
        "tool",
        "assistant",
        "tool",
        "assistant",
        "tool",
    ]
    first_assistant = messages[1]
    assert first_assistant.tool_calls is not None
    assert first_assistant.tool_calls[0].id == "call_1_1"
    assert first_assistant.tool_calls[0].arguments["keystrokes"] == "ls -la\n"
    assert "I should inspect the workspace." in str(first_assistant.content)
    assert messages[2].tool_call_id == "call_1_1"
    assert messages[2].content == "total 4\nfile.txt"
    assert output.completion == "done"
    assert output.usage is not None
    assert output.usage.total_cost == 0.001


def test_transcript_markdown_includes_policy_summary(adapter: Terminus2Adapter):
    markdown = adapter.transcript_markdown(
        task_id="task-1",
        prompt="solve it",
        model="deepseek/deepseek-v4-flash",
        reward=1,
        answer="ok",
        agent_stdout=_stdout()
        + "\nTERMINUS_OPENROUTER_API_KEY=sk-or-v1-secretvalue123456",
        timed_out=False,
        policy=None,
        pricing_model="deepseek/deepseek-v4-flash",
        benchmark_status=None,
        policy_events=[{"event_type": "policy_block"}],
    )
    assert "**Harness:** Terminus-2" in markdown
    assert "solve it" in markdown
    assert "## Policy blocks (1)" in markdown
    assert "sk-or-v1-secretvalue123456" not in markdown
    assert "[REDACTED]" in markdown


def test_transcript_markdown_expands_full_atif_trace(adapter: Terminus2Adapter):
    markdown = adapter.transcript_markdown(
        task_id="task-1",
        prompt="solve it",
        model="deepseek/deepseek-v4-flash",
        reward=1,
        answer="PASS",
        agent_stdout=_stdout(task_complete=True),
        timed_out=False,
        policy="control",
        pricing_model="deepseek/deepseek-v4-flash",
        benchmark_status={
            "task_outcome": "PASS",
            "failure_class": "none",
            "valid_for_analysis": True,
        },
        policy_events=[],
        session_artifacts=_session_artifacts(),
    )

    assert "# Terminal-Bench — task-1" in markdown
    assert "**🧠 reasoning**" in markdown
    assert "I should inspect the workspace." in markdown
    assert "**🔧 tool call → `bash_command`**" in markdown
    assert "ls -la" in markdown
    assert "total 4" in markdown
    assert "3 assistant turns, 3 tool calls" in markdown
    assert "source=terminus_2_atif_trajectory complete=true" in markdown
    assert "`trajectory.json` and `terminus_2.pane`" in markdown


@pytest.mark.parametrize("timestamp", [None, "2026-07-15T10:00:00Z"])
def test_parse_transcript_keeps_distinct_turns_without_unique_timestamps(
    adapter: Terminus2Adapter,
    timestamp: str | None,
):
    artifacts = _session_artifacts()
    trajectory = json.loads(artifacts["files"][0]["content"])
    for step in trajectory["steps"]:
        step["timestamp"] = timestamp
    artifacts["files"][0]["content"] = json.dumps(trajectory)

    messages, _ = adapter.parse_transcript(
        prompt="solve",
        agent_stdout=_stdout(task_complete=True),
        model="deepseek/deepseek-v4-flash",
        pricing_model="deepseek/deepseek-v4-flash",
        session_artifacts=artifacts,
    )

    assistant_messages = [message for message in messages if message.role == "assistant"]
    assert len(assistant_messages) == 3
    assert "inspect files" in str(assistant_messages[0].content)
    assert "verified" in str(assistant_messages[1].content)
    assert "done" in str(assistant_messages[2].content)


def test_runner_preserve_env_guard(monkeypatch):
    module = _load_runner_module()
    monkeypatch.delenv(module.PRESERVE_AGENT_SESSION_ENV, raising=False)
    assert module._preserve_agent_session() is False
    monkeypatch.setenv(module.PRESERVE_AGENT_SESSION_ENV, "1")
    assert module._preserve_agent_session() is True
    from boundarybench.terminalbench.daytona_run import (
        PRESERVE_AGENT_SESSION_ENV,
    )

    assert module.PRESERVE_AGENT_SESSION_ENV == PRESERVE_AGENT_SESSION_ENV


def test_runner_agent_receives_skills_dir(tmp_path):
    module = _load_runner_module()
    agent = module._build_agent(
        logs_dir=tmp_path,
        model_name="openrouter/deepseek/deepseek-v4-flash",
        effort=None,
        api_key="self-check-not-a-secret",
    )
    assert agent.skills_dir == module._skills_dir()
    assert agent.skills_dir.endswith(".terminus-2/skills")
