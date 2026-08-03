"""Tests for the Grok Build CLI harness adapter."""

from __future__ import annotations

import pytest

from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.grok import (
    DAYTONA_GROK_BIN,
    DAYTONA_GROK_HOME,
    GROK_VERSION,
    ROOT_GROK_BIN,
    ROOT_GROK_HOME,
    GrokAdapter,
)
from boundarybench.harness.registry import available_harnesses, get_harness_adapter


class TestGrokAdapter:
    def setup_method(self):
        self.adapter = GrokAdapter()

    def test_registered_and_protocol(self):
        assert "grok" in available_harnesses()
        assert isinstance(get_harness_adapter("grok"), GrokAdapter)
        assert isinstance(self.adapter, HarnessAdapter)

    def test_identity(self):
        assert self.adapter.name == "grok"
        assert self.adapter.agent_metadata_name == "grok_openrouter"
        assert self.adapter.api_key_env_var == "OPENROUTER_API_KEY"
        assert self.adapter.health_egress_domains == ()

    def test_binary_paths(self):
        assert self.adapter.agent_binary_path(run_as_root=True) == ROOT_GROK_BIN
        assert self.adapter.agent_binary_path(run_as_root=False) == DAYTONA_GROK_BIN

    def test_session_artifact_dirs_capture_acp_updates(self):
        assert self.adapter.session_artifact_dirs(run_as_root=False) == (
            f"{DAYTONA_GROK_HOME}/sessions",
        )
        assert self.adapter.session_artifact_dirs(run_as_root=True) == (
            f"{ROOT_GROK_HOME}/sessions",
        )

    def test_agent_command_is_headless_json(self):
        cmd = self.adapter.agent_command(
            model="x-ai/grok-4.20",
            prompt_path="/tmp/prompt.txt",
            run_as_root=True,
        )
        assert ROOT_GROK_BIN in cmd
        assert "--prompt-file" in cmd
        assert "/tmp/prompt.txt" in cmd
        assert "--output-format json" in cmd
        assert "--always-approve" in cmd
        assert "--model x-ai/grok-4.20" in cmd
        assert cmd.rstrip().endswith("< /dev/null")
        from boundarybench.harness.openrouter import OPENROUTER_BASE_URL

        assert "config.toml" in cmd
        assert f"{OPENROUTER_BASE_URL}/v1" in cmd
        assert 'env_key = "GROK_OPENROUTER_API_KEY"' in cmd
        assert 'api_backend = "responses"' in cmd
        assert '[model."x-ai/grok-4.20"]' in cmd
        assert "GROK_MODELS_BASE_URL" not in cmd
        assert "XAI_API_KEY" not in cmd

    def test_agent_command_rejects_bad_model(self):
        with pytest.raises(ValueError):
            self.adapter.agent_command(
                model="bad model!", prompt_path="/tmp/p", run_as_root=True
            )

    def test_agent_env_uses_single_openrouter_key(self):
        env = self.adapter.agent_env(provider_api_key="sk-secret", run_as_root=True)
        assert env["GROK_OPENROUTER_API_KEY"] == "sk-secret"
        assert env["GROK_HOME"] == ROOT_GROK_HOME
        assert (
            self.adapter.agent_env(provider_api_key="k", run_as_root=False)["GROK_HOME"]
            == DAYTONA_GROK_HOME
        )
        assert "XAI_API_KEY" not in env
        assert "GROK_MODELS_BASE_URL" not in env
        assert "OPENROUTER_API_KEY" not in env
        assert "OPENAI_API_KEY" not in env

    def test_openrouter_key_env_not_in_hardening_strip_set(self):
        from boundarybench.daytona.policy_axes import CANONICAL_INFRA_KEY_ENV_NAMES
        from boundarybench.terminalbench.policies import resolve_policy_for_run

        assert "GROK_OPENROUTER_API_KEY" not in CANONICAL_INFRA_KEY_ENV_NAMES
        for policy in ("low-nist", "moderate-nist", "high-nist"):
            strip = resolve_policy_for_run(policy).config.strip_env_vars
            assert "GROK_OPENROUTER_API_KEY" not in strip, policy
            assert strip == (), policy

    def test_runtime_layer_script_installs_bare_binary(self):
        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)
        assert "HARNESS_INSTALL_OK" in script
        assert GROK_VERSION in script
        assert "grok-build-public-artifacts" in script
        assert "api.github.com" not in script
        assert ROOT_GROK_BIN in script
        assert "telemetry = false" in script

    def test_activity_summary_never_zero_on_output(self):
        stdout = '{"text":"hi","stopReason":"EndTurn"}'
        assert self.adapter.activity_summary(stdout)["assistant_turns"] == 1
        assert self.adapter.activity_summary("some output")["assistant_turns"] == 1
        assert self.adapter.activity_summary("")["assistant_turns"] == 0

    def test_activity_summary_no_tool_calls_in_json_mode(self):
        stdout = '{"text":"hi","stopReason":"EndTurn"}'
        assert self.adapter.activity_summary(stdout)["tool_calls"] == 0

    def test_blocked_surfaces_defer_to_policy_log(self):
        assert self.adapter.blocked_surfaces("anything", policy=None) == []

    def test_provider_auth_error_detects_and_ignores(self):
        assert (
            self.adapter.provider_auth_error(
                '{"text":"all good","stopReason":"EndTurn"}'
            )
            is None
        )
        err = self.adapter.provider_auth_error(
            '{"type":"error","message":"401 unauthorized while calling provider"}'
        )
        assert err is not None
        assert err.marker
        assert (
            self.adapter.provider_auth_error(
                '{"type":"error","message":"model not found"}'
            )
            is not None
        )
        assert self.adapter.provider_auth_error("configuring pam authentication") is None

    def test_provider_auth_error_ignores_productive_success(self):
        stdout = (
            '{"text":"the endpoint returned 401 unauthorized before my fix; '
            'it now works","stopReason":"EndTurn"}'
        )
        assert self.adapter.provider_auth_error(stdout) is None

    def test_parse_grok_json_tolerates_surrounding_noise(self):
        from boundarybench.harness.grok import _grok_final_text

        noisy = 'warn: something\n{"text":"answer","stopReason":"EndTurn"}\nbye'
        assert _grok_final_text(noisy) == "answer"

    def test_parse_transcript_builds_minimal_messages(self):
        stdout = '{"text":"the answer is 42","stopReason":"EndTurn"}'
        messages, output = self.adapter.parse_transcript(
            prompt="solve it",
            agent_stdout=stdout,
            model="x-ai/grok-4.20",
            pricing_model="x-ai/grok-4.20",
        )
        assert len(messages) == 2
        assert "42" in output.completion

    def test_transcript_markdown_includes_prompt_and_output(self):
        md = self.adapter.transcript_markdown(
            task_id="t1",
            prompt="do the thing",
            model="x-ai/grok-4.20",
            reward=1.0,
            answer="ok",
            agent_stdout='{"text":"grok ran","stopReason":"EndTurn"}',
            timed_out=False,
            policy=None,
            pricing_model="x-ai/grok-4.20",
            benchmark_status=None,
            policy_events=[{"event_type": "policy_block"}, {"event_type": "other"}],
        )
        assert "do the thing" in md
        assert "grok ran" in md
        assert "t1" in md
        assert "policy blocks: `1`" in md


def test_grok_home_runtime_subdirs():
    from boundarybench.harness.grok import GrokAdapter

    assert GrokAdapter().home_runtime_subdirs == (".grok",)
