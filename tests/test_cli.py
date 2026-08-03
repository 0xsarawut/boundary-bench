from __future__ import annotations

import tomllib
from pathlib import Path

from boundarybench import cli


def test_root_help(capsys):
    assert cli.main(["--help"]) == 0

    captured = capsys.readouterr()
    assert "boundarybench run" in captured.out
    assert "boundarybench list" in captured.out
    assert "boundarybench export-results" in captured.out
    assert "boundarybench policy validate" in captured.out
    assert "boundarybench enforcement-probe" in captured.out


def test_export_results_routes_to_dataframe_export(monkeypatch):
    called = {}

    def fake_main(args: list[str] | None = None) -> int:
        called["args"] = args
        return 37

    monkeypatch.setattr(
        "boundarybench.terminalbench.results_dataframe.main",
        fake_main,
    )

    assert (
        cli.main(
            [
                "export-results",
                "--input",
                "logs",
                "--output",
                "rows.csv",
            ]
        )
        == 37
    )
    assert called["args"] == ["--input", "logs", "--output", "rows.csv"]


def test_policy_validate_routes_to_catalog_cli(monkeypatch):
    called = {}

    def fake_main(args: list[str] | None = None) -> None:
        called["args"] = args

    monkeypatch.setattr(
        "boundarybench.policy_catalog.cli.validate_main",
        fake_main,
    )

    assert cli.main(["policy", "validate", "--pack-id", "all"]) == 0
    assert called["args"] == ["--pack-id", "all"]


def test_policy_compile_routes_to_catalog_cli(monkeypatch):
    called = {}

    def fake_main(args: list[str] | None = None) -> None:
        called["args"] = args

    monkeypatch.setattr(
        "boundarybench.policy_catalog.cli.compile_main",
        fake_main,
    )

    assert (
        cli.main(
            [
                "policy",
                "compile",
                "--pack-id",
                "boundary-contract-fixtures",
                "--policy-id",
                "contract-smoke-enterprise-shape",
                "--variant-id",
                "daytona-smoke-v1",
            ]
        )
        == 0
    )
    assert called["args"] == [
        "--pack-id",
        "boundary-contract-fixtures",
        "--policy-id",
        "contract-smoke-enterprise-shape",
        "--variant-id",
        "daytona-smoke-v1",
    ]


def test_unknown_command_exits_with_usage_error(capsys):
    assert cli.main(["missing"]) == 2

    captured = capsys.readouterr()
    assert "unknown command: missing" in captured.err


def test_list_shows_benchmark_policies_and_harnesses(capsys):
    assert cli.main(["list"]) == 0

    captured = capsys.readouterr()
    for policy in ("control", "non-root", "high-nist"):
        assert policy in captured.out
    for harness in ("claude-code", "codex", "terminus", "grok"):
        assert harness in captured.out
    # The names must be the ones `--harness` accepts, not the internal ids.
    assert "claude_code" not in captured.out
    assert "terminus_2" not in captured.out
    assert "terminus  (default)" in captured.out


def test_run_bare_refuses_full_benchmark_non_interactively(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)

    assert cli.main(["run"]) == 2

    captured = capsys.readouterr()
    assert "no task selection given" in captured.err
    assert "--all-tasks" in captured.err
    assert "--yes" in captured.err


def test_run_bare_prompts_then_runs_full_benchmark(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_yes_no", lambda *args, **kwargs: True)

    captured_task_kwargs = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured_task_kwargs.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(["run", "--log-dir", str(tmp_path / "logs"), "--display", "none"])
        == 0
    )

    assert captured_task_kwargs["all_tasks"] is True
    assert captured_task_kwargs["harness"] == "terminus_2"

    captured = capsys.readouterr()
    assert "full benchmark" in captured.out
    assert "89 task(s) selected" in captured.out


def test_run_bare_prompt_decline_aborts(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_yes_no", lambda *args, **kwargs: False)

    assert cli.main(["run"]) == 1

    captured = capsys.readouterr()
    assert "aborted" in captured.err


def test_run_bare_dry_run_skips_confirmation(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)

    assert cli.main(["run", "--dry-run"]) == 0

    captured = capsys.readouterr()
    assert "89 task(s) selected" in captured.out
    assert "dry run: no sandboxes provisioned" in captured.out


def test_run_rejects_task_with_all_tasks(capsys):
    assert cli.main(["run", "--task", "mailman", "--all-tasks"]) == 2

    captured = capsys.readouterr()
    assert "not both" in captured.err


def test_dotenv_is_loaded_without_overriding_existing_env(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text(
        "OPENROUTER_API_KEY=from-dotenv\nDAYTONA_API_KEY=dtn-from-dotenv\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-export")
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    cli._load_dotenv()

    import os

    assert os.environ["OPENROUTER_API_KEY"] == "from-export"
    assert os.environ["DAYTONA_API_KEY"] == "dtn-from-dotenv"


def test_run_uses_dotenv_credentials(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text(
        "OPENROUTER_API_KEY=sk-or-dotenv\nDAYTONA_API_KEY=dtn-dotenv\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )


def test_run_requires_credentials(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    assert cli.main(["run", "--task", "log-summary-date-ranges"]) == 2

    captured = capsys.readouterr()
    assert "OPENROUTER_API_KEY" in captured.err
    assert "DAYTONA_API_KEY" in captured.err


def test_run_rejects_unknown_policy(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--policy",
                "moderate-nist",
            ]
        )
        == 2
    )

    captured = capsys.readouterr()
    assert "unknown policy" in captured.err
    assert "--allow-any-policy" in captured.err


def test_run_rejects_unknown_harness(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--harness",
                "aider",
            ]
        )
        == 2
    )

    captured = capsys.readouterr()
    assert "unknown harness" in captured.err


def test_run_refuses_not_applicable_task_without_confirmation(
    monkeypatch, capsys
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)

    assert (
        cli.main(
            ["run", "--task", "mailman", "--policy", "high-nist"]
        )
        == 2
    )

    captured = capsys.readouterr()
    assert "not applicable under this hardening" in captured.out
    assert "mailman" in captured.out
    assert "--yes" in captured.err


def test_run_prompt_accepts_not_applicable_tasks(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_yes_no", lambda *args, **kwargs: True)

    captured_task_kwargs = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured_task_kwargs.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "mailman",
                "--policy",
                "high-nist",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    assert captured_task_kwargs["include_not_applicable"] is True


def test_run_prompt_decline_aborts(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_yes_no", lambda *args, **kwargs: False)

    assert cli.main(["run", "--task", "mailman", "--policy", "high-nist"]) == 1

    captured = capsys.readouterr()
    assert "aborted" in captured.err


def test_run_yes_flag_runs_not_applicable_tasks_without_prompting(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: False)

    captured_task_kwargs = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured_task_kwargs.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "mailman",
                "--policy",
                "high-nist",
                "--yes",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    assert captured_task_kwargs["include_not_applicable"] is True

    captured = capsys.readouterr()
    assert "warning: task(s) not applicable" in captured.out


def test_run_dry_run_resolves_without_launching(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    def _boom(**kwargs):
        raise AssertionError("the eval task must not be built on --dry-run")

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        _boom,
    )

    assert (
        cli.main(["run", "--all-tasks", "--policy", "high-nist", "--dry-run"]) == 0
    )

    captured = capsys.readouterr()
    assert "89 task(s) selected" in captured.out
    assert "dry run: no sandboxes provisioned" in captured.out
    assert "mailman" in captured.out
    # The preview names what would run: harness, model, and log destination.
    assert "harness: terminus" in captured.out
    assert "model: repo default" in captured.out
    assert "log dir: logs/boundarybench-" in captured.out
    # Naming the log dir must not bring it into existence.
    assert not (tmp_path / "logs").exists()


def test_run_dry_run_reports_harness_and_model_overrides(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--policy",
                "high-nist",
                "--harness",
                "codex",
                "--model",
                "openai/gpt-5.6-luna",
                "--log-dir",
                "logs/custom",
                "--dry-run",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "harness: codex" in captured.out
    assert "model: openai/gpt-5.6-luna" in captured.out
    assert "log dir: logs/custom" in captured.out
    assert not (tmp_path / "logs").exists()


def test_run_dry_run_reports_harness_alias_not_internal_id(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--harness",
                "claude",
                "--dry-run",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "harness: claude-code" in captured.out
    assert "claude_code" not in captured.out


def test_run_dry_run_honors_exclude_not_applicable(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    assert (
        cli.main(
            [
                "run",
                "--all-tasks",
                "--policy",
                "high-nist",
                "--exclude-not-applicable",
                "--dry-run",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "82 task(s) selected" in captured.out
    assert "excluding not-applicable task(s)" in captured.out


def test_run_all_tasks_runs_the_full_universe(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    captured_task_kwargs = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured_task_kwargs.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--all-tasks",
                "--policy",
                "high-nist",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    assert captured_task_kwargs["all_tasks"] is True
    assert "task_ids" not in captured_task_kwargs
    assert captured_task_kwargs["exclude_not_applicable"] is False

    captured = capsys.readouterr()
    assert "89 task(s) selected" in captured.out


def test_run_all_tasks_exclude_not_applicable_drops_conflicts(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    captured_task_kwargs = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured_task_kwargs.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--all-tasks",
                "--policy",
                "high-nist",
                "--exclude-not-applicable",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    assert captured_task_kwargs["exclude_not_applicable"] is True

    captured = capsys.readouterr()
    assert "excluding not-applicable task(s)" in captured.out
    assert "mailman" in captured.out
    assert "82 task(s) selected" in captured.out


def test_run_all_tasks_exclude_is_a_noop_under_control(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--all-tasks",
                "--policy",
                "control",
                "--exclude-not-applicable",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "excluding not-applicable" not in captured.out
    assert "89 task(s) selected" in captured.out


def test_run_notes_adapted_verifier_tasks(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "sqlite-with-gcov",
                "--policy",
                "control",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "adapted verifier" in captured.out
    assert "sqlite-with-gcov" in captured.out


def test_run_harden_compiles_custom_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    captured = {}

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: captured.update(kwargs) or "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--harden",
                "non-root,readonly-os",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )
    assert captured["harden"] == "non-root,readonly-os"
    assert "policy" not in captured


def test_run_rejects_policy_and_harden_together(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--policy",
                "high-nist",
                "--harden",
                "non-root",
            ]
        )
        == 2
    )
    assert "not both" in capsys.readouterr().err


def test_run_harden_rejects_unknown_surface(monkeypatch, capsys):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    assert (
        cli.main(
            ["run", "--task", "log-summary-date-ranges", "--harden", "be-secure"]
        )
        == 2
    )
    assert "unknown hardening surface" in capsys.readouterr().err


def test_build_policy_prints_command_and_does_not_run(monkeypatch, capsys):
    answers = iter(["y", "n", "y", "n", "n", "n"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))

    assert cli.main(["build-policy", "--task", "log-summary-date-ranges"]) == 0

    out = capsys.readouterr().out
    assert "boundarybench run --harden" in out
    assert "non-root" in out and "readonly-os" in out
    assert "Not running" in out


def test_list_shows_hardening_options(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "Build-your-own hardening options" in out
    assert "restrict-egress" in out


def test_list_shows_task_rosters(capsys):
    assert cli.main(["list"]) == 0

    captured = capsys.readouterr()
    assert "Adapted-verifier tasks" in captured.out
    assert "sqlite-with-gcov" in captured.out
    assert "Policy-inapplicable tasks" in captured.out
    assert "count-dataset-tokens" in captured.out


def test_run_maps_aliases_and_invokes_inspect_eval(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("DAYTONA_API_KEY", "dtn-test")

    captured_task_kwargs = {}
    captured_eval_kwargs = {}

    def fake_task(**kwargs):
        captured_task_kwargs.update(kwargs)
        return "task-object"

    class _FakeLog:
        status = "success"

    def fake_eval(task, **kwargs):
        captured_eval_kwargs["task"] = task
        captured_eval_kwargs.update(kwargs)
        return [_FakeLog()]

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        fake_task,
    )
    monkeypatch.setattr("inspect_ai.eval", fake_eval)

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--policy",
                "non-root",
                "--harness",
                "terminus",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    assert captured_task_kwargs["task_ids"] == "log-summary-date-ranges"
    assert captured_task_kwargs["policy"] == "non-root"
    assert captured_task_kwargs["harness"] == "terminus_2"
    assert captured_eval_kwargs["task"] == "task-object"
    assert captured_eval_kwargs["model"] == "mockllm/model"
    assert captured_eval_kwargs["display"] == "none"


def test_run_key_flags_populate_environment(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DAYTONA_API_KEY", raising=False)

    class _FakeLog:
        status = "success"

    monkeypatch.setattr(
        "boundarybench.terminalbench.daytona_eval.hardened_terminalbench_daytona",
        lambda **kwargs: "task-object",
    )
    monkeypatch.setattr("inspect_ai.eval", lambda task, **kwargs: [_FakeLog()])

    assert (
        cli.main(
            [
                "run",
                "--task",
                "log-summary-date-ranges",
                "--openrouter-api-key",
                "sk-or-flag",
                "--daytona-api-key",
                "dtn-flag",
                "--log-dir",
                str(tmp_path / "logs"),
                "--display",
                "none",
            ]
        )
        == 0
    )

    import os

    assert os.environ["OPENROUTER_API_KEY"] == "sk-or-flag"
    assert os.environ["DAYTONA_API_KEY"] == "dtn-flag"


def test_only_root_console_script_is_exposed():
    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text()
    )

    assert pyproject["project"]["scripts"] == {
        "boundarybench": "boundarybench.cli:main"
    }


def test_distribution_name_matches_import_package():
    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text()
    )

    assert pyproject["project"]["name"] == "boundarybench"
    assert pyproject["project"]["entry-points"]["inspect_ai"] == {
        "boundarybench": "boundarybench._registry"
    }


def test_tasks_register_with_boundarybench_namespace():
    from inspect_ai._util.package import get_installed_package_name

    import boundarybench.terminalbench.refsol_eval as refsol_module

    assert get_installed_package_name(refsol_module) == "boundarybench"
