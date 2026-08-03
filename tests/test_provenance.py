from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from boundarybench.provenance import (
    StaleBaseStatus,
    runner_fingerprint,
    runtime_provenance,
    stale_base_status,
)


def _write(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def _minimal_runner_tree(root):
    _write(root, "pyproject.toml", "[project]\nname='boundarybench'\n")
    _write(root, "uv.lock", "# lock\n")
    _write(root, "README.md", "# boundarybench\n")
    _write(root, "src/boundarybench/cli.py", "def main(): return 0\n")
    _write(root, "src/boundarybench/terminalbench/daytona_run.py", "RUN = True\n")
    _write(root, "src/boundarybench/terminalbench/scripts/runtime_layer.sh", "echo runtime\n")
    _write(root, "src/boundarybench/daytona/hardening_configs/default.json", "{}\n")


def test_runner_fingerprint_tracks_runner_build_and_task_inputs(tmp_path):
    _minimal_runner_tree(tmp_path)

    original = runner_fingerprint(tmp_path)
    _write(tmp_path, "docs/operator-runbook.md", "operator docs changed\n")
    docs_only = runner_fingerprint(tmp_path)
    _write(tmp_path, "src/boundarybench/terminalbench/daytona_run.py", "RUN = False\n")
    runtime_changed = runner_fingerprint(tmp_path)
    _write(tmp_path, "uv.lock", "# lock changed\n")
    lock_changed = runner_fingerprint(tmp_path)

    assert original.digest == docs_only.digest
    assert "docs/operator-runbook.md" not in docs_only.files
    assert runtime_changed.digest != original.digest
    assert lock_changed.digest != runtime_changed.digest
    assert "src/boundarybench/terminalbench/daytona_run.py" in original.files
    assert "uv.lock" in original.files


def test_fingerprint_cli_runs_without_installed_third_party_dependencies(tmp_path):
    _minimal_runner_tree(tmp_path)
    env = {
        **os.environ,
        "PYTHONPATH": str(Path.cwd() / "src"),
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-m",
            "boundarybench.provenance",
            "fingerprint",
            "--root",
            str(tmp_path),
        ],
        check=True,
        env=env,
        text=True,
        capture_output=True,
    )

    assert len(completed.stdout.strip()) == 64


def test_runtime_provenance_prefers_explicit_image_environment(monkeypatch):
    monkeypatch.setenv("BOUNDARYBENCH_IMAGE_DIGEST", "image@sha256:abc")
    monkeypatch.setenv("BOUNDARYBENCH_IMAGE_SOURCE_SHA", "source-sha")
    monkeypatch.setenv("BOUNDARYBENCH_BRANCH_SHA", "branch-sha")
    monkeypatch.setenv("BOUNDARYBENCH_BASE_MAIN_SHA", "base-sha")
    monkeypatch.setenv("BOUNDARYBENCH_BRANCH", "feature/fix")
    monkeypatch.setenv("BOUNDARYBENCH_DIRTY", "true")
    monkeypatch.setenv("BOUNDARYBENCH_IMAGE_BUILD_TIME", "2026-06-28T09:00:00Z")
    monkeypatch.setenv("BOUNDARYBENCH_RUNNER_FINGERPRINT", "f" * 64)

    payload = runtime_provenance()

    assert payload == {
        "image_digest": "image@sha256:abc",
        "image_source_sha": "source-sha",
        "branch_sha": "branch-sha",
        "base_main_sha": "base-sha",
        "branch_name": "feature/fix",
        "dirty": True,
        "build_time": "2026-06-28T09:00:00Z",
        "runner_fingerprint": "f" * 64,
    }


def test_stale_base_status_compares_merge_base_to_current_origin_main():
    calls = []

    def fake_git(args, cwd=None):
        calls.append(args)
        if args == ["merge-base", "HEAD", "origin/main"]:
            return "base-sha"
        if args == ["rev-parse", "origin/main"]:
            return "main-sha"
        if args == ["rev-parse", "HEAD"]:
            return "branch-sha"
        if args == ["branch", "--show-current"]:
            return "feature/fix"
        if args == ["status", "--short"]:
            return " M file.py"
        raise AssertionError(args)

    status = stale_base_status(run_git=fake_git)

    assert status == StaleBaseStatus(
        branch_sha="branch-sha",
        base_main_sha="base-sha",
        current_main_sha="main-sha",
        branch_name="feature/fix",
        dirty=True,
        stale=True,
        checked=True,
        error=None,
    )
    assert ["merge-base", "HEAD", "origin/main"] in calls


def test_stale_base_status_can_refresh_origin_main_before_comparison():
    calls = []

    def fake_git(args, cwd=None):
        calls.append(args)
        if args == ["fetch", "origin", "main", "--quiet"]:
            return None
        if args == ["merge-base", "HEAD", "origin/main"]:
            return "main-sha"
        if args == ["rev-parse", "origin/main"]:
            return "main-sha"
        if args == ["rev-parse", "HEAD"]:
            return "branch-sha"
        if args == ["branch", "--show-current"]:
            return "feature/fix"
        if args == ["status", "--short"]:
            return ""
        raise AssertionError(args)

    status = stale_base_status(run_git=fake_git, refresh=True)

    assert calls[0] == ["fetch", "origin", "main", "--quiet"]
    assert status.checked is True
    assert status.stale is False
