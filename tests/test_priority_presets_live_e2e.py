from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Sequence

import pytest


PRIORITY_PRESETS = (
    "control",
    "basic-only",
    "nist-linux-80053-low",
    "nist-linux-80053-medium",
    "nist-linux-80053-high",
)


pytestmark = pytest.mark.live_e2e


def test_priority_preset_runner_submits_presets_concurrently(tmp_path: Path) -> None:
    barrier = threading.Barrier(len(PRIORITY_PRESETS), timeout=2)
    submitted: list[str] = []
    lock = threading.Lock()

    def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if "submit" in command:
            spec_path = Path(command[command.index("--spec") + 1])
            policy = json.loads(spec_path.read_text())["policy"]
            with lock:
                submitted.append(policy)
            barrier.wait()
            return subprocess.CompletedProcess(
                command, 0, stdout="manager_execution=fake\n", stderr=""
            )
        if "verify-smoke" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="smoke_verification_ok task_outcome=PASS\n",
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")

    _run_priority_presets(
        tmp_path,
        presets=PRIORITY_PRESETS,
        task_id="log-summary-date-ranges",
        agent_model="deepseek/deepseek-v4-flash",
        timeout_seconds=1,
        poll_interval_seconds=1,
        run_suffix="20260705-000000",
        runner=fake_runner,
    )

    assert set(submitted) == set(PRIORITY_PRESETS)


def test_priority_presets_run_one_managed_terminalbench_task(tmp_path: Path) -> None:
    if os.environ.get("BOUNDARYBENCH_RUN_PRIORITY_PRESET_E2E") != "1":
        pytest.skip(
            "set BOUNDARYBENCH_RUN_PRIORITY_PRESET_E2E=1 to submit live "
            "managed Cloud Run/Daytona priority preset E2E runs"
        )
    _assert_live_e2e_credentials_ready()

    task_id = os.environ.get(
        "BOUNDARYBENCH_PRIORITY_PRESET_E2E_TASK_ID",
        "log-summary-date-ranges",
    )
    agent_model = os.environ.get(
        "BOUNDARYBENCH_PRIORITY_PRESET_E2E_MODEL",
        "deepseek/deepseek-v4-flash",
    )
    timeout_seconds = int(
        os.environ.get("BOUNDARYBENCH_PRIORITY_PRESET_E2E_TIMEOUT_SECONDS", "900")
    )
    poll_interval_seconds = int(
        os.environ.get("BOUNDARYBENCH_PRIORITY_PRESET_E2E_POLL_SECONDS", "20")
    )
    run_suffix = time.strftime("%Y%m%d-%H%M%S")

    _run_priority_presets(
        tmp_path,
        presets=PRIORITY_PRESETS,
        task_id=task_id,
        agent_model=agent_model,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
        run_suffix=run_suffix,
        runner=_run,
    )


def _write_spec(
    tmp_path: Path,
    *,
    run_id: str,
    policy: str,
    task_id: str,
    agent_model: str,
) -> Path:
    spec = {
        "benchmark_claim": "pipeline_smoke",
        "campaign": "priority-preset-live-e2e",
        "experiment_id": run_id,
        "log_prefix": f"boundarybench/runs/{run_id}",
        "metadata": {
            "evaluation_ready": False,
            "execution_path": "firestore_manager_queue",
            "priority_preset_e2e": True,
        },
        "model": f"openrouter/{agent_model}",
        "policy": policy,
        "schema_version": "boundarybench.experiment-spec.v1",
        "task": "boundarybench/hardened_terminalbench_daytona",
        "task_args": {
            "model": agent_model,
            "policy": policy,
            "task_ids": task_id,
        },
    }
    spec_path = tmp_path / f"{run_id}.json"
    spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    return spec_path


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            "command failed "
            f"(exit {result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _run_priority_presets(
    tmp_path: Path,
    *,
    presets: Sequence[str],
    task_id: str,
    agent_model: str,
    timeout_seconds: int,
    poll_interval_seconds: int,
    run_suffix: str,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
) -> None:
    preset_list = tuple(presets)
    with ThreadPoolExecutor(
        max_workers=len(preset_list),
        thread_name_prefix="priority-preset-e2e",
    ) as executor:
        futures = [
            executor.submit(
                _run_priority_preset,
                tmp_path,
                preset=preset,
                task_id=task_id,
                agent_model=agent_model,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                run_suffix=run_suffix,
                runner=runner,
            )
            for preset in preset_list
        ]
        for future in as_completed(futures):
            future.result()


def _run_priority_preset(
    tmp_path: Path,
    *,
    preset: str,
    task_id: str,
    agent_model: str,
    timeout_seconds: int,
    poll_interval_seconds: int,
    run_suffix: str,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]],
) -> None:
    run_id = f"priority-preset-e2e-{_slug(preset)}-{run_suffix}"
    spec_path = _write_spec(
        tmp_path,
        run_id=run_id,
        policy=preset,
        task_id=task_id,
        agent_model=agent_model,
    )
    submit = runner(
        [
            "uv",
            "run",
            "--extra",
            "gcp",
            "boundarybench",
            "submit",
            "--spec",
            str(spec_path),
            "--execute-manager",
            "--allow-stale-base",
        ]
    )
    assert "manager_execution=" in submit.stdout

    verify_cmd = [
        "uv",
        "run",
        "--extra",
        "gcp",
        "boundarybench",
        "verify-smoke",
        "--run-id",
        run_id,
        "--timeout-seconds",
        str(timeout_seconds),
        "--poll-interval-seconds",
        str(poll_interval_seconds),
    ]
    if preset != "control":
        verify_cmd.append("--require-policy-evidence")
    verify = runner(verify_cmd)
    assert "smoke_verification_ok" in verify.stdout
    assert "task_outcome=PASS" in verify.stdout


def _slug(value: str) -> str:
    return value.replace("-", "_")


def _assert_live_e2e_credentials_ready() -> None:
    checks = (
        (
            [
                "gcloud",
                "auth",
                "print-access-token",
                "--quiet",
            ],
            "gcloud CLI credentials are required to start the Cloud Run manager",
            "Run `gcloud auth login` and retry.",
        ),
        (
            [
                "gcloud",
                "auth",
                "application-default",
                "print-access-token",
                "--quiet",
            ],
            (
                "Application Default Credentials are required for local "
                "Firestore/BigQuery smoke verification"
            ),
            "Run `gcloud auth application-default login` and retry.",
        ),
    )
    for command, reason, remediation in checks:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            pytest.fail(
                f"{reason} before submitting live work.\n"
                f"{remediation}\n"
                f"command: {' '.join(command)}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
