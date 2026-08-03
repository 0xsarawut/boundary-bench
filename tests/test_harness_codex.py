"""Tests for the Codex CLI harness adapter."""

from __future__ import annotations

import os
import shlex
import subprocess

import pytest

from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.codex import (
    CODEX_VERSION,
    DAYTONA_CODEX_BIN,
    OPENROUTER_OPENAI_BASE_URL,
    ROOT_CODEX_BIN,
    CodexAdapter,
    codex_stream_diagnostics,
    codex_stream_usage,
)
from boundarybench.harness.registry import available_harnesses, get_harness_adapter


class TestCodexAdapter:
    def setup_method(self):
        self.adapter = CodexAdapter()

    def test_registered_and_protocol(self):
        assert "codex" in available_harnesses()
        assert isinstance(get_harness_adapter("codex"), CodexAdapter)
        assert isinstance(self.adapter, HarnessAdapter)

    def test_identity(self):
        assert self.adapter.name == "codex"
        assert self.adapter.agent_metadata_name == "codex_openrouter"
        assert self.adapter.api_key_env_var == "OPENROUTER_API_KEY"
        assert self.adapter.health_egress_domains == ("chatgpt.com",)
        assert self.adapter.default_effort_level == "high"
        assert self.adapter.supported_effort_levels == (
            "low",
            "medium",
            "high",
            "xhigh",
        )

    def test_binary_paths(self):
        assert self.adapter.agent_binary_path(run_as_root=True) == ROOT_CODEX_BIN
        assert self.adapter.agent_binary_path(run_as_root=False) == DAYTONA_CODEX_BIN

    def test_session_artifact_dirs_point_at_codex_home(self):
        assert self.adapter.session_artifact_dirs(run_as_root=False) == (
            "/home/daytona/.codex/sessions",
        )
        assert self.adapter.session_artifact_dirs(run_as_root=True) == (
            "/root/.codex/sessions",
        )

    def test_agent_command_is_headless_json(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/prompt.txt",
            run_as_root=True,
        )
        assert ROOT_CODEX_BIN in cmd
        assert " exec " in cmd
        assert "--json" in cmd
        assert "--dangerously-bypass-approvals-and-sandbox" in cmd
        assert "--model" in cmd and "deepseek/deepseek-v4-flash" in cmd
        assert "model_reasoning_effort=\"high\"" in cmd
        assert "--enable unified_exec" in cmd
        assert "/tmp/prompt.txt" in cmd
        assert "$(cat" not in cmd
        assert "< /dev/null" not in cmd
        assert cmd.rstrip().endswith("- < /tmp/prompt.txt")
        stdin_sentinel = cmd.index(" - < /tmp/prompt.txt")
        for option in (
            "--color",
            "--skip-git-repo-check",
            "--json",
            "--model",
            "--config",
            "--enable",
            "--dangerously-bypass-approvals-and-sandbox",
        ):
            assert cmd.index(option) < stdin_sentinel

    def test_agent_command_transports_arbitrary_prompt_only_via_stdin(self, tmp_path):
        prompt_bytes = (
            b"- leading option-like line\n"
            b"second line with 'quotes' and $(shell syntax)\n"
            b"final line\n"
        )
        prompt_path = tmp_path / "prompt with spaces.txt"
        prompt_path.write_bytes(prompt_bytes)

        argv_path = tmp_path / "argv.bin"
        stdin_path = tmp_path / "stdin.bin"
        recorder_path = tmp_path / "record-codex"
        recorder_path.write_text(
            "#!/bin/sh\n"
            'printf \'%s\\0\' "$@" > "$RECORDER_ARGV"\n'
            'cat > "$RECORDER_STDIN"\n',
            encoding="utf-8",
        )
        recorder_path.chmod(0o755)

        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path=str(prompt_path),
            run_as_root=True,
        )
        assert cmd.startswith(f"{ROOT_CODEX_BIN} ")
        rendered = shlex.quote(str(recorder_path)) + cmd[len(ROOT_CODEX_BIN) :]
        env = os.environ.copy()
        env.update(
            RECORDER_ARGV=str(argv_path),
            RECORDER_STDIN=str(stdin_path),
        )

        subprocess.run(["/bin/sh", "-c", rendered], check=True, env=env)

        argv_bytes = argv_path.read_bytes()
        argv = argv_bytes.removesuffix(b"\0").split(b"\0")
        assert argv[-1] == b"-"
        assert prompt_bytes.rstrip(b"\n") not in argv
        assert stdin_path.read_bytes() == prompt_bytes

    def test_agent_command_accepts_explicit_effort(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/prompt.txt",
            run_as_root=True,
            effort_level="low",
        )

        assert "--config" in cmd
        assert "model_reasoning_effort=\"low\"" in cmd

    def test_agent_command_rejects_bad_model(self):
        with pytest.raises(ValueError):
            self.adapter.agent_command(
                model="bad model!", prompt_path="/tmp/p", run_as_root=True
            )

    def test_agent_command_rejects_unsupported_effort(self):
        with pytest.raises(ValueError, match="unsupported effort level"):
            self.adapter.agent_command(
                model="deepseek/deepseek-v4-flash",
                prompt_path="/tmp/p",
                run_as_root=True,
                effort_level="max",
            )

    def test_agent_env_uses_single_openrouter_key(self):
        env = self.adapter.agent_env(provider_api_key="sk-secret", run_as_root=True)
        assert env["CODEX_OPENROUTER_API_KEY"] == "sk-secret"
        assert "OPENROUTER_API_KEY" not in env
        assert "OPENAI_API_KEY" not in env
        assert env["CODEX_HOME"].endswith(".codex")

    def test_config_env_key_not_in_hardening_strip_set(self):
        from boundarybench.daytona.policy_axes import CANONICAL_INFRA_KEY_ENV_NAMES
        from boundarybench.terminalbench.policies import resolve_policy_for_run

        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)
        assert 'env_key = "CODEX_OPENROUTER_API_KEY"' in script
        assert "CODEX_OPENROUTER_API_KEY" not in CANONICAL_INFRA_KEY_ENV_NAMES
        for policy in ("low-nist", "moderate-nist", "high-nist"):
            strip = resolve_policy_for_run(policy).config.strip_env_vars
            assert "CODEX_OPENROUTER_API_KEY" not in strip, policy
            assert strip == (), policy

    def test_runtime_layer_script_installs_and_configs_openrouter(self):
        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)
        assert "HARNESS_INSTALL_OK" in script
        assert "codex-x86_64-unknown-linux-musl" not in script
        assert "api.github.com" not in script
        assert CODEX_VERSION in script
        assert "releases/download" in script
        assert OPENROUTER_OPENAI_BASE_URL in script
        assert 'wire_api = "responses"' in script
        assert "[features]" in script
        assert "multi_agent = false" in script
        assert ROOT_CODEX_BIN in script
        assert "ripgrep" in script

    def test_runtime_layer_script_cleans_download_staging_on_exit(self):
        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)

        assert "cleanup_codex_staging()" in script
        assert "trap cleanup_codex_staging EXIT" in script
        assert 'rm -f "$codex_archive"' in script
        assert 'rm -rf "$extract_dir"' in script

    def test_activity_summary_never_zero_on_output(self):
        assert self.adapter.activity_summary("some output")["assistant_turns"] == 1
        assert self.adapter.activity_summary("")["assistant_turns"] == 0

    def test_activity_summary_counts_json_events(self):
        stdout = (
            '{"type":"agent_message","message":"working"}\n'
            '{"type":"exec_command","command":"ls"}\n'
            '{"type":"agent_message","message":"done"}\n'
        )
        summary = self.adapter.activity_summary(stdout)
        assert summary["assistant_turns"] == 2
        assert summary["tool_calls"] == 1

    def test_blocked_surfaces_defer_to_policy_log(self):
        assert self.adapter.blocked_surfaces("anything", policy=None) == []

    def test_provider_auth_error_detects_and_ignores(self):
        assert self.adapter.provider_auth_error("all good") is None
        err = self.adapter.provider_auth_error("HTTP 401 Unauthorized from provider")
        assert err is not None
        assert err.marker
        assert self.adapter.provider_auth_error("configuring pam authentication") is None

    def test_provider_auth_error_ignores_productive_runs(self):
        stdout = (
            '{"type":"agent_message","message":"step 1"}\n'
            '{"type":"agent_message","message":"the server returned 401 unauthorized"}\n'
            '{"type":"agent_message","message":"fixed it"}\n'
        )
        assert self.adapter.provider_auth_error(stdout) is None

    def test_provider_auth_error_turn_gate_matches_claude_path(self):
        from boundarybench.terminalbench.provider_error_markers import (
            PROVIDER_ERROR_MAX_TURNS,
        )

        line = '{"type":"agent_message","message":"http 401 from provider"}\n'
        at_cap = line * PROVIDER_ERROR_MAX_TURNS
        past_cap = line * (PROVIDER_ERROR_MAX_TURNS + 1)
        assert self.adapter.provider_auth_error(at_cap) is not None
        assert self.adapter.provider_auth_error(past_cap) is None

    def test_parse_transcript_builds_minimal_messages(self):
        stdout = '{"type":"agent_message","message":"the answer is 42"}'
        messages, output = self.adapter.parse_transcript(
            prompt="solve it",
            agent_stdout=stdout,
            model="deepseek/deepseek-v4-flash",
            pricing_model="deepseek/deepseek-v4-flash",
        )
        assert len(messages) == 2
        assert "42" in output.completion

    def test_parse_transcript_handles_nested_event_shapes(self):
        for stdout in (
            '{"msg":{"type":"agent_message","message":"nested answer"}}',
            '{"type":"item.completed","item":{"type":"agent_message","text":"nested answer"}}',
        ):
            _, output = self.adapter.parse_transcript(
                prompt="p",
                agent_stdout=stdout,
                model="deepseek/deepseek-v4-flash",
                pricing_model="deepseek/deepseek-v4-flash",
            )
            assert output.completion == "nested answer", stdout

    def test_activity_summary_counts_command_starts_once(self):
        stdout = (
            '{"type":"exec_command_begin","command":"ls"}\n'
            '{"type":"exec_command_output_delta","delta":"a"}\n'
            '{"type":"exec_command_end","exit_code":0}\n'
        )
        assert self.adapter.activity_summary(stdout)["tool_calls"] == 1

    def test_activity_summary_counts_real_command_execution_shape(self):
        stdout = (
            '{"type":"item.started","item":{"id":"i1","type":"command_execution","command":"git status","status":"in_progress"}}\n'
            '{"type":"item.completed","item":{"id":"i1","type":"command_execution","command":"git status","status":"completed"}}\n'
            '{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"done"}}\n'
        )
        summary = self.adapter.activity_summary(stdout)
        assert summary["tool_calls"] == 1
        assert summary["assistant_turns"] == 1

    def test_parse_transcript_populates_usage_from_turn_completed(self):
        stdout = (
            '{"type":"turn.started"}\n'
            '{"type":"item.completed","item":{"type":"agent_message","text":"the answer is 42"}}\n'
            '{"type":"turn.completed","usage":{"input_tokens":1200,'
            '"cached_input_tokens":300,"output_tokens":450}}\n'
        )
        messages, output = self.adapter.parse_transcript(
            prompt="solve it",
            agent_stdout=stdout,
            model="deepseek/deepseek-v4-flash",
            pricing_model="deepseek/deepseek-v4-flash",
        )
        assert "42" in output.completion
        assert output.usage is not None
        assert output.usage.input_tokens == 1200
        assert output.usage.output_tokens == 450
        assert output.usage.input_tokens_cache_read == 300

    def test_parse_transcript_populates_usage_from_token_count(self):
        stdout = (
            '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
            '{"type":"token_count","info":{"total_token_usage":{"input_tokens":900,'
            '"cached_input_tokens":100,"output_tokens":200,'
            '"reasoning_output_tokens":50,"total_tokens":1100}}}\n'
        )
        _, output = self.adapter.parse_transcript(
            prompt="p",
            agent_stdout=stdout,
            model="deepseek/deepseek-v4-flash",
            pricing_model="deepseek/deepseek-v4-flash",
        )
        assert output.usage is not None
        assert output.usage.input_tokens == 900
        assert output.usage.output_tokens == 200
        assert output.usage.input_tokens_cache_read == 100

    def test_parse_transcript_no_usage_leaves_output_usage_none(self):
        stdout = '{"type":"agent_message","message":"the answer is 42"}'
        _, output = self.adapter.parse_transcript(
            prompt="solve it",
            agent_stdout=stdout,
            model="deepseek/deepseek-v4-flash",
            pricing_model="deepseek/deepseek-v4-flash",
        )
        assert "42" in output.completion
        assert output.usage is None

    def test_codex_stream_usage_normalizes_names(self):
        assert codex_stream_usage(
            '{"type":"turn.completed","usage":{"input_tokens":10,'
            '"cached_input_tokens":4,"output_tokens":6}}'
        ) == {"input": 10, "output": 6, "cache_read": 4, "cache_write": 0}
        assert codex_stream_usage("no json here") == {
            "input": 0,
            "output": 0,
            "cache_read": 0,
            "cache_write": 0,
        }

    def test_diagnostics_pass_stream_marks_result_event_present(self):
        stdout = (
            '{"type":"turn.started"}\n'
            '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
            '{"type":"turn.completed","usage":{"input_tokens":1200,"output_tokens":450}}\n'
        )
        diag = codex_stream_diagnostics(stdout)
        assert diag["agent_stdout_result_event_present"] is True
        assert diag["agent_stdout_final_result_event_present"] is True
        assert diag["agent_stdout_result_event_missing"] is False
        assert diag["agent_stdout_result_event_usage_present"] is True
        assert diag["agent_model_usage_present"] is True
        assert diag["agent_model_usage_source"] == "turn_events"
        assert diag["agent_model_usage_recovered"] is False

    def test_diagnostics_fail_stream_reports_missing_honestly(self):
        stdout = (
            '{"type":"turn.started"}\n'
            '{"type":"turn.failed","error":{"message":"stream disconnected"}}\n'
        )
        diag = codex_stream_diagnostics(stdout)
        assert diag["agent_stdout_result_event_present"] is False
        assert diag["agent_stdout_result_event_missing"] is True
        assert diag["agent_model_usage_present"] is False
        assert diag["agent_model_usage_source"] == "none"

    def test_diagnostics_token_count_usage_recovered_without_turn_completed(self):
        stdout = (
            '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
            '{"type":"token_count","info":{"total_token_usage":'
            '{"input_tokens":900,"output_tokens":200,"total_tokens":1100}}}\n'
        )
        diag = codex_stream_diagnostics(stdout)
        assert diag["agent_stdout_result_event_present"] is False
        assert diag["agent_stdout_result_event_missing"] is True
        assert diag["agent_model_usage_present"] is True
        assert diag["agent_model_usage_recovered"] is True

    def test_diagnostics_harness_agnostic_fields_match_line_scan(self):
        stdout = (
            "Warning: some prose line\n"
            '{"type":"turn.started"}\n'
            '{"type":"token_count","info":{"total_token_usage":{"input_tokens":1'
        )
        diag = codex_stream_diagnostics(stdout)
        assert diag["agent_stdout_non_json_line_count"] == 1
        assert diag["agent_stdout_parse_error_count"] == 1
        assert diag["agent_stdout_truncated_or_malformed"] is True
        assert diag["agent_stdout_last_complete_event_type"] == "turn.started"

    def test_transcript_markdown_includes_prompt_and_output(self):
        md = self.adapter.transcript_markdown(
            task_id="t1",
            prompt="do the thing",
            model="deepseek/deepseek-v4-flash",
            reward=1.0,
            answer="ok",
            agent_stdout="codex ran",
            timed_out=False,
            policy=None,
            pricing_model="deepseek/deepseek-v4-flash",
            benchmark_status=None,
            policy_events=[{"event_type": "policy_block"}],
        )
        assert "do the thing" in md
        assert "codex ran" in md
        assert "t1" in md
        assert "policy blocks: `1`" in md


class TestCodexHomeCarveoutsAndBootstrap:
    adapter = CodexAdapter()

    def test_home_runtime_subdirs_declares_codex_home(self):
        assert self.adapter.home_runtime_subdirs == (".codex",)

    def test_runtime_layer_script_bootstraps_pre_boundary(self):
        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=False)
        assert "HARNESS_BOOTSTRAP_OK" in script
        assert "run_as_daytona" in script
        assert "failed to initialize" in script
