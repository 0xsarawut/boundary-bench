"""Tests for the harness adapter protocol, registry, and Claude Code adapter."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess

import pytest

from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.claude_code import (
    CLAUDE_CODE_VERSION,
    DAYTONA_CLAUDE_BIN,
    ROOT_CLAUDE_BIN,
    ClaudeCodeAdapter,
)
from boundarybench.harness.secrets import provider_api_key_from_managed_env
from boundarybench.harness.registry import (
    DEFAULT_HARNESS,
    available_harnesses,
    get_harness_adapter,
)


class TestClaudeCodeAdapter:
    def setup_method(self):
        self.adapter = ClaudeCodeAdapter()

    def test_implements_harness_adapter_protocol(self):
        assert isinstance(self.adapter, HarnessAdapter)

    def test_name(self):
        assert self.adapter.name == "claude_code"

    def test_no_session_artifact_dirs(self):
        assert self.adapter.session_artifact_dirs(run_as_root=False) == ()
        assert self.adapter.session_artifact_dirs(run_as_root=True) == ()

    def test_agent_metadata_name(self):
        assert self.adapter.agent_metadata_name == "claude_code_openrouter"

    def test_health_egress_domains(self):
        assert self.adapter.health_egress_domains == ("api.anthropic.com",)

    def test_effort_defaults_and_validation(self):
        assert self.adapter.default_effort_level == "high"
        assert self.adapter.supported_effort_levels == (
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
        )

    def test_agent_binary_path_non_root(self):
        assert self.adapter.agent_binary_path(run_as_root=False) == DAYTONA_CLAUDE_BIN

    def test_agent_binary_path_root(self):
        assert self.adapter.agent_binary_path(run_as_root=True) == ROOT_CLAUDE_BIN

    def test_agent_command_non_root(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/prompt.txt",
            run_as_root=False,
        )
        assert DAYTONA_CLAUDE_BIN in cmd
        assert "--model" in cmd
        assert "deepseek/deepseek-v4-flash" in cmd
        assert "--permission-mode bypassPermissions" in cmd
        assert "--dangerously-skip-permissions" not in cmd
        assert "--effort high" in cmd
        assert "--output-format stream-json" in cmd
        assert "/tmp/prompt.txt" in cmd

    def test_agent_command_root(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/prompt.txt",
            run_as_root=True,
        )
        assert ROOT_CLAUDE_BIN in cmd
        assert "--dangerously-skip-permissions" in cmd
        assert "--permission-mode bypassPermissions" not in cmd

    def test_agent_command_validates_model_id(self):
        with pytest.raises(ValueError, match="OpenRouter model id must match"):
            self.adapter.agent_command(
                model="invalid model; rm -rf /",
                prompt_path="/tmp/prompt.txt",
                run_as_root=False,
            )

    def test_agent_command_golden_non_root(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/boundarybench-task-prompt.txt",
            run_as_root=False,
        )
        assert cmd == (
            "/home/daytona/.local/bin/claude "
            "--model deepseek/deepseek-v4-flash "
            "--permission-mode bypassPermissions "
            "--effort high "
            "--verbose --output-format stream-json "
            '-p -- "$(cat /tmp/boundarybench-task-prompt.txt)" '
            "< /dev/null"
        )

    def test_agent_command_golden_root(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/boundarybench-task-prompt.txt",
            run_as_root=True,
        )
        assert cmd == (
            "/root/.local/bin/claude "
            "--model deepseek/deepseek-v4-flash "
            "--dangerously-skip-permissions "
            "--effort high "
            "--verbose --output-format stream-json "
            '-p -- "$(cat /tmp/boundarybench-task-prompt.txt)" '
            "< /dev/null"
        )

    def test_agent_command_allows_explicit_effort(self):
        cmd = self.adapter.agent_command(
            model="deepseek/deepseek-v4-flash",
            prompt_path="/tmp/prompt.txt",
            run_as_root=False,
            effort_level="low",
        )

        assert "--effort low" in cmd

    def test_agent_command_rejects_unknown_effort(self):
        with pytest.raises(ValueError, match="unsupported effort level"):
            self.adapter.agent_command(
                model="deepseek/deepseek-v4-flash",
                prompt_path="/tmp/prompt.txt",
                run_as_root=False,
                effort_level="turbo",
            )

    def test_agent_env(self):
        env = self.adapter.agent_env(
            provider_api_key="sk-or-test-key",
            run_as_root=False,
        )
        from boundarybench.harness.openrouter import OPENROUTER_BASE_URL

        assert env["ANTHROPIC_BASE_URL"] == OPENROUTER_BASE_URL
        assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-test-key"
        assert len(env) == 2

    def test_agent_env_root_sets_sandbox_flag(self):
        env = self.adapter.agent_env(
            provider_api_key="sk-or-test-key",
            run_as_root=True,
        )
        assert env["IS_SANDBOX"] == "1"
        assert env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-test-key"
        assert len(env) == 3

    def test_api_key_env_var(self):
        assert self.adapter.api_key_env_var == "OPENROUTER_API_KEY"

    def test_provider_api_key_from_managed_env_reads_secret_env(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
        assert (
            provider_api_key_from_managed_env(self.adapter, purpose="tests")
            == "sk-or-test-key"
        )

    def test_provider_api_key_from_managed_env_missing_raises(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        with pytest.raises(
            RuntimeError, match="Cloud Run Secret Manager environment"
        ):
            provider_api_key_from_managed_env(self.adapter, purpose="tests")

    def test_runtime_layer_script_non_root(self):
        script = self.adapter.runtime_layer_script(
            workdir="/app",
            run_as_root=False,
        )
        assert "install_claude_for_daytona" in script
        assert "HARNESS_INSTALL_OK" in script
        assert "__CLAUDE_BIN__" not in script
        assert "__RUN_AGENT_AS_ROOT__" not in script
        assert "__CLAUDE_CODE_VERSION__" not in script
        assert CLAUDE_CODE_VERSION in script

    def test_runtime_layer_script_root(self):
        script = self.adapter.runtime_layer_script(
            workdir="/app",
            run_as_root=True,
        )
        assert "install_claude_for_root" in script
        assert "HARNESS_INSTALL_OK" in script
        assert "RUN_AGENT_AS_ROOT=1" in script
        assert "__CLAUDE_CODE_VERSION__" not in script
        assert CLAUDE_CODE_VERSION in script

    @pytest.mark.parametrize("run_as_root", [False, True])
    def test_runtime_layer_script_always_cleans_install_log(self, run_as_root):
        script = self.adapter.runtime_layer_script(
            workdir="/app",
            run_as_root=run_as_root,
        )

        assert "cleanup_claude_install_log()" in script
        assert "status=$?" in script
        assert "trap - EXIT" in script
        assert 'cat /tmp/claude-install.log 2>/dev/null || true' in script
        assert "cleanup_status=0" in script
        assert 'rm -f /tmp/claude-install.log || cleanup_status=$?' in script
        assert '[ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]' in script
        assert "status=$cleanup_status" in script
        assert 'exit "$status"' in script
        assert "trap cleanup_claude_install_log EXIT" in script

    @pytest.mark.parametrize("shell", ["bash", "dash"])
    def test_runtime_layer_script_failure_reports_and_removes_log(
        self, tmp_path, shell
    ):
        shell_path = shutil.which(shell)
        if shell_path is None:
            pytest.skip(f"{shell} is not installed")
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' '#!/bin/sh' "
            "'echo controlled-installer-failure >&2' 'exit 23'\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)
        bash_real = tmp_path / "bash.real"
        bash_real.write_text('#!/bin/sh\nexec /bin/sh "$@"\n', encoding="utf-8")
        bash_real.chmod(0o755)

        claude_bin = tmp_path / "claude"
        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)
        script = script.replace(
            f"CLAUDE_BIN={ROOT_CLAUDE_BIN}",
            f"CLAUDE_BIN={shlex.quote(str(claude_bin))}",
        ).replace("/bin/bash.real", shlex.quote(str(bash_real)))
        install_log = tmp_path / "claude-install.log"
        script = script.replace(
            "/tmp/claude-install.log", shlex.quote(str(install_log))
        )
        assert "/tmp/claude-install.log" not in script
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        try:
            completed = subprocess.run(
                [shell_path],
                input=script,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

            assert completed.returncode == 23
            assert "controlled-installer-failure" in completed.stdout
            assert not install_log.exists()
        finally:
            install_log.unlink(missing_ok=True)

    @pytest.mark.parametrize("shell", ["bash", "dash"])
    @pytest.mark.parametrize(
        ("prior_status", "expected_status"),
        [(0, 41), (23, 23)],
    )
    def test_runtime_layer_script_cleanup_failure_preserves_failure_precedence(
        self, tmp_path, shell, prior_status, expected_status
    ):
        shell_path = shutil.which(shell)
        if shell_path is None:
            pytest.skip(f"{shell} is not installed")
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        rm = fake_bin / "rm"
        rm.write_text("#!/bin/sh\nexit 41\n", encoding="utf-8")
        rm.chmod(0o755)

        claude_bin = tmp_path / "claude"
        bash_real = tmp_path / "bash.real"
        bash_real.write_text('#!/bin/sh\nexec /bin/sh "$@"\n', encoding="utf-8")
        bash_real.chmod(0o755)
        if prior_status == 0:
            claude_bin.write_text(
                "#!/bin/sh\necho '2.1.206 (controlled)'\n", encoding="utf-8"
            )
            claude_bin.chmod(0o755)
        else:
            curl = fake_bin / "curl"
            curl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '#!/bin/sh' "
                "'echo controlled-installer-failure >&2' 'exit 23'\n",
                encoding="utf-8",
            )
            curl.chmod(0o755)

        script = self.adapter.runtime_layer_script(workdir="/app", run_as_root=True)
        script = script.replace(
            f"CLAUDE_BIN={ROOT_CLAUDE_BIN}",
            f"CLAUDE_BIN={shlex.quote(str(claude_bin))}",
        ).replace("/bin/bash.real", shlex.quote(str(bash_real)))
        install_log = tmp_path / "claude-install.log"
        install_log.write_text("controlled cleanup diagnostic\n", encoding="utf-8")
        script = script.replace(
            "/tmp/claude-install.log", shlex.quote(str(install_log))
        )
        assert "/tmp/claude-install.log" not in script
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        try:
            completed = subprocess.run(
                [shell_path],
                input=script,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

            assert completed.returncode == expected_status
            assert install_log.exists()
            if prior_status == 0:
                assert "HARNESS_INSTALL_OK" in completed.stdout
            else:
                assert "controlled-installer-failure" in completed.stdout
                assert "HARNESS_INSTALL_OK" not in completed.stdout
        finally:
            install_log.unlink(missing_ok=True)

    @pytest.mark.parametrize("run_as_root", [False, True])
    def test_runtime_layer_script_pins_installer_version(self, run_as_root):
        script = self.adapter.runtime_layer_script(
            workdir="/app",
            run_as_root=run_as_root,
        )
        install_lines = [
            line for line in script.splitlines() if "install.sh" in line
        ]
        assert install_lines, "no install.sh invocation found in rendered script"
        for line in install_lines:
            assert (
                '-s -- "$CLAUDE_CODE_VERSION"' in line
                or "-s -- '$CLAUDE_CODE_VERSION'" in line
            ), f"unpinned Claude Code install: {line!r}"

    def test_runtime_layer_script_rejects_shell_unsafe_version(self, monkeypatch):
        import boundarybench.harness.claude_code as claude_code_module

        monkeypatch.setattr(
            claude_code_module, "CLAUDE_CODE_VERSION", "2.1.206 $(id)"
        )
        with pytest.raises(ValueError, match="CLAUDE_CODE_VERSION"):
            self.adapter.runtime_layer_script(workdir="/app", run_as_root=False)


class TestHarnessRegistry:
    def test_default_harness_is_terminus_2(self):
        assert DEFAULT_HARNESS == "terminus_2"

    def test_get_default_adapter(self):
        from boundarybench.harness.terminus_2 import Terminus2Adapter

        adapter = get_harness_adapter()
        assert adapter.name == "terminus_2"
        assert isinstance(adapter, Terminus2Adapter)

    def test_get_claude_code_adapter(self):
        adapter = get_harness_adapter("claude_code")
        assert adapter.name == "claude_code"

    def test_get_unknown_adapter_raises(self):
        with pytest.raises(ValueError, match="unknown harness"):
            get_harness_adapter("nonexistent_harness")

    def test_available_harnesses(self):
        harnesses = available_harnesses()
        assert "claude_code" in harnesses

    def test_none_returns_default(self):
        adapter = get_harness_adapter(None)
        assert adapter.name == "terminus_2"


class TestRuntimeLayerSplit:
    def test_sandbox_base_script_renders(self):
        from boundarybench.terminalbench.daytona_runtime_layer import (
            render_sandbox_setup_script,
        )

        adapter = ClaudeCodeAdapter()
        script = render_sandbox_setup_script(
            workdir="/app",
            run_agent_as_root=False,
            harness=adapter,
        )
        assert "SANDBOX_BASE_OK" in script
        assert "HARNESS_INSTALL_OK" in script
        assert "__WORKDIR__" not in script
        assert "__RUN_AGENT_AS_ROOT__" not in script

    def test_sandbox_base_script_root_mode(self):
        from boundarybench.terminalbench.daytona_runtime_layer import (
            render_sandbox_setup_script,
        )

        adapter = ClaudeCodeAdapter()
        script = render_sandbox_setup_script(
            workdir="/workspace",
            run_agent_as_root=True,
            harness=adapter,
        )
        assert "RUN_AGENT_AS_ROOT=1" in script
        assert "SANDBOX_BASE_OK" in script


class TestHarnessPackagePrimitives:
    def test_terminalbench_constants_reexport_harness_values(self):
        from boundarybench.harness import claude_code as harness_claude
        from boundarybench.harness.openrouter import OPENROUTER_BASE_URL
        from boundarybench.terminalbench import daytona_constants as tb

        assert tb.DAYTONA_CLAUDE_BIN is harness_claude.DAYTONA_CLAUDE_BIN
        assert tb.ROOT_CLAUDE_BIN is harness_claude.ROOT_CLAUDE_BIN
        assert tb.OPENROUTER_BASE_URL is OPENROUTER_BASE_URL
        assert tb.CLAUDE_BIN is harness_claude.DAYTONA_CLAUDE_BIN

    def test_validate_openrouter_model_id_importable_from_both_layers(self):
        from boundarybench.harness.openrouter import (
            validate_openrouter_model_id as harness_validate,
        )
        from boundarybench.terminalbench.daytona_run import (
            validate_openrouter_model_id as runner_validate,
        )

        assert runner_validate is harness_validate

    def test_install_script_is_read_lazily_not_at_import(self, monkeypatch):
        from boundarybench.harness import claude_code as harness_claude

        harness_claude._install_script.cache_clear()
        monkeypatch.setattr(
            harness_claude,
            "files",
            lambda *_: (_ for _ in ()).throw(FileNotFoundError("missing resource")),
        )
        adapter = harness_claude.ClaudeCodeAdapter()
        assert adapter.agent_binary_path(run_as_root=False)
        with pytest.raises(FileNotFoundError, match="missing resource"):
            adapter.runtime_layer_script(workdir="/app", run_as_root=False)
        harness_claude._install_script.cache_clear()


class TestHardeningClaims:
    def test_derive_hardening_policy(self):
        from boundarybench.harness.claims import HardeningClaims

        claims = HardeningClaims.derive(
            policy_applies_hardening=True, harness=ClaudeCodeAdapter()
        )
        assert claims.enforcement == "daytona_policy_hardening"
        assert claims.hardened_execution is True
        assert claims.harness == "claude_code"
        assert claims.to_metadata() == {
            "enforcement": "daytona_policy_hardening",
            "hardened_execution": True,
            "harness": "claude_code",
        }

    def test_derive_baseline_policy(self):
        from boundarybench.harness.claims import HardeningClaims

        claims = HardeningClaims.derive(
            policy_applies_hardening=False, harness=ClaudeCodeAdapter()
        )
        assert claims.enforcement == "daytona_baseline"
        assert claims.hardened_execution is False

    def test_inconsistent_claims_are_not_constructible(self):
        from boundarybench.harness.claims import HardeningClaims

        with pytest.raises(ValueError, match="inconsistent hardening claims"):
            HardeningClaims(
                enforcement="daytona_baseline",
                hardened_execution=True,
                harness="claude_code",
            )
        with pytest.raises(ValueError, match="inconsistent hardening claims"):
            HardeningClaims(
                enforcement="daytona_policy_hardening",
                hardened_execution=False,
                harness="claude_code",
            )

    def test_claims_require_harness_name(self):
        from boundarybench.harness.claims import HardeningClaims

        with pytest.raises(ValueError, match="harness name"):
            HardeningClaims(
                enforcement="daytona_baseline",
                hardened_execution=False,
                harness="",
            )


def test_claude_home_runtime_subdirs():
    from boundarybench.harness.claude_code import ClaudeCodeAdapter

    assert ClaudeCodeAdapter().home_runtime_subdirs == (".claude",)


def test_all_harnesses_default_to_high_effort():
    from boundarybench.harness.adapter import normalize_effort_level
    from boundarybench.harness.registry import (
        available_harnesses,
        get_harness_adapter,
    )

    for name in available_harnesses():
        adapter = get_harness_adapter(name)
        assert adapter.default_effort_level == "high", name
        assert normalize_effort_level(adapter) == "high", name
        assert normalize_effort_level(adapter, "default") == "high", name
        assert normalize_effort_level(adapter, "low") == "low", name


def test_grok_supports_graded_effort():
    from boundarybench.harness.grok import GrokAdapter

    adapter = GrokAdapter()
    assert adapter.default_effort_level == "high"
    assert set(adapter.supported_effort_levels) >= {"low", "medium", "high"}
    assert adapter.effort_level_applied is True
