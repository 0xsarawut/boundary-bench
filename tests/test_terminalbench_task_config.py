"""Tests for the task image WORKDIR resolver in task_config."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import boundarybench.terminalbench.task_config as task_config
from boundarybench.terminalbench.task_config import (
    DEFAULT_TASK_IMAGE_WORKDIR,
    resolve_harbor_verifier_environment,
    task_image_workdir,
    task_image_workdir_from_bundle,
)


def _write_dockerfile(tmp_path: Path, content: str) -> Path:
    env_dir = tmp_path / "environment"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "Dockerfile").write_text(content)
    return tmp_path


def test_missing_dockerfile_falls_back_to_app(tmp_path):
    assert DEFAULT_TASK_IMAGE_WORKDIR == "/app"
    assert task_image_workdir(tmp_path) == "/app"


def test_absolute_workdir_last_one_wins(tmp_path):
    _write_dockerfile(
        tmp_path, "FROM ubuntu:24.04\nWORKDIR /app\nWORKDIR /app/personal-site\n"
    )
    assert task_image_workdir(tmp_path) == "/app/personal-site"


def test_relative_workdir_chains_from_previous(tmp_path):
    _write_dockerfile(tmp_path, "WORKDIR /srv\nWORKDIR sub\n")
    assert task_image_workdir(tmp_path) == "/srv/sub"


@pytest.mark.parametrize(
    "dockerfile",
    [
        "WORKDIR /$APP_HOME\n",
        "WORKDIR /workspace\nWORKDIR build/$TARGET\n",
    ],
)
def test_workdir_with_unresolved_variable_fails_closed(tmp_path, dockerfile):
    _write_dockerfile(tmp_path, dockerfile)

    with pytest.raises(ValueError, match="unresolved variable"):
        task_image_workdir(tmp_path)


def test_from_bundle_uses_task_dir(tmp_path):
    _write_dockerfile(tmp_path, "WORKDIR /workspace\n")
    bundle = SimpleNamespace(task_dir=tmp_path)
    assert task_image_workdir_from_bundle(bundle) == "/workspace"


@pytest.mark.parametrize(
    ("workdir", "expected_workdir", "expected_workspace_root"),
    [
        ("/app", "/app", "/app"),
        ("/app/personal-site", "/app/personal-site", "/app"),
        ("/workspace", "/workspace", "/workspace"),
        ("/workspace/sub", "/workspace/sub", "/workspace"),
        ("/workspace//sub/.", "/workspace/sub", "/workspace"),
    ],
)
def test_resolve_terminalbench_workspace_maps_supported_workdirs(
    workdir, expected_workdir, expected_workspace_root
):
    resolution = task_config.resolve_terminalbench_workspace(workdir)

    assert resolution.workdir == expected_workdir
    assert resolution.workspace_root == expected_workspace_root


@pytest.mark.parametrize(
    ("workdir", "expected"),
    [
        ("app", "absolute"),
        ("/", "supported workspace root"),
        ("/app/../workspace", "traversal"),
        ("/srv", "supported workspace root"),
    ],
)
def test_resolve_terminalbench_workspace_rejects_unsupported_workdirs(
    workdir, expected
):
    with pytest.raises(ValueError, match=expected):
        task_config.resolve_terminalbench_workspace(workdir)


def test_terminalbench_workspace_from_bundle_resolves_image_workdir(tmp_path):
    _write_dockerfile(tmp_path, "WORKDIR /workspace\nWORKDIR sub\n")

    resolution = task_config.terminalbench_workspace_from_bundle(
        SimpleNamespace(task_dir=tmp_path)
    )

    assert resolution.workdir == "/workspace/sub"
    assert resolution.workspace_root == "/workspace"


@pytest.mark.parametrize("mode", ["shared", "separate"])
def test_resolve_harbor_verifier_environment_preserves_explicit_mode(mode):
    resolution = resolve_harbor_verifier_environment(
        {"verifier": {"environment_mode": mode}}
    )

    assert resolution.mode == mode
    assert resolution.source == "verifier.environment_mode"


def test_resolve_harbor_verifier_environment_defaults_to_shared_without_environment():
    resolution = resolve_harbor_verifier_environment({"verifier": {}})

    assert resolution.mode == "shared"
    assert resolution.source == "harbor_default"


def test_resolve_harbor_verifier_environment_infers_separate_from_environment():
    resolution = resolve_harbor_verifier_environment(
        {"verifier": {"environment": {"docker_image": "example:latest"}}}
    )

    assert resolution.mode == "separate"
    assert resolution.source == "verifier.environment"


@pytest.mark.parametrize(
    ("harbor_config", "expected"),
    [
        ({"verifier": {"environment_mode": "host"}}, "shared.*separate"),
        ({"verifier": {"environment_mode": 1}}, "shared.*separate"),
        ({"verifier": {"environment": "example:latest"}}, "valid dictionary"),
        (
            {
                "verifier": {
                    "environment_mode": "shared",
                    "environment": {"docker_image": "example:latest"},
                }
            },
            "incompatible",
        ),
    ],
)
def test_resolve_harbor_verifier_environment_rejects_malformed_or_unsupported_modes(
    harbor_config, expected
):
    with pytest.raises(ValueError, match=expected):
        resolve_harbor_verifier_environment(harbor_config)


def test_resolve_harbor_verifier_environment_rejects_multi_step_tasks():
    with pytest.raises(ValueError, match="multi-step"):
        resolve_harbor_verifier_environment(
            {
                "verifier": {},
                "steps": [{"name": "first"}],
            }
        )


PINNED_TERMINAL_BENCH_2_1_REF = (
    "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
)


def _declared_shared_default():
    return task_config.HarborVerifierEnvironmentResolution(
        mode="shared",
        source="harbor_default",
    )


@pytest.mark.parametrize(
    ("task_id", "expected_disposition", "expected_reason"),
    [
        ("pytorch-model-recovery", "reap", "reap_conflicting_agent_process"),
        ("pypi-server", "preserve", "verifier_requires_live_service"),
    ],
)
def test_pinned_process_policy_preserves_harbor_lifecycle(
    task_id, expected_disposition, expected_reason
):
    lifecycle = task_config.resolve_daytona_verifier_lifecycle(
        task_id=task_id,
        harbor_ref=PINNED_TERMINAL_BENCH_2_1_REF,
        declared=_declared_shared_default(),
    )
    process_disposition = task_config.resolve_agent_process_disposition(
        task_id=task_id,
        harbor_ref=PINNED_TERMINAL_BENCH_2_1_REF,
        declared=_declared_shared_default(),
    )

    assert lifecycle.declared_mode == "shared"
    assert lifecycle.declared_source == "harbor_default"
    assert lifecycle.effective_mode == "shared"
    assert lifecycle.effective_source == "harbor_default"
    assert lifecycle.handoff_paths == ()
    assert lifecycle.override_reason is None
    assert process_disposition.disposition == expected_disposition
    assert process_disposition.source == "boundarybench_ref_task_policy"
    assert process_disposition.reason == expected_reason


def test_process_policy_on_another_ref_preserves_harbor_shared_semantics():
    lifecycle = task_config.resolve_daytona_verifier_lifecycle(
        task_id="pypi-server",
        harbor_ref="sha256:another-terminal-bench-ref",
        declared=_declared_shared_default(),
    )
    process_disposition = task_config.resolve_agent_process_disposition(
        task_id="pypi-server",
        harbor_ref="sha256:another-terminal-bench-ref",
        declared=_declared_shared_default(),
    )

    assert lifecycle.effective_mode == "shared"
    assert lifecycle.effective_source == "harbor_default"
    assert process_disposition.disposition == "preserve"
    assert process_disposition.source == "safe_default"
    assert process_disposition.reason == "unlisted_tasks_preserve_harbor_semantics"


@pytest.mark.parametrize("task_id", ["pytorch-model-recovery", "pypi-server"])
@pytest.mark.parametrize(
    ("mode", "source"),
    [
        ("separate", "harbor_default"),
        ("shared", "verifier.environment_mode"),
    ],
)
def test_pinned_process_policy_fails_closed_on_harbor_declaration_drift(
    task_id, mode, source
):
    declared = task_config.HarborVerifierEnvironmentResolution(
        mode=mode,
        source=source,
    )

    with pytest.raises(ValueError, match="declaration drift"):
        task_config.resolve_agent_process_disposition(
            task_id=task_id,
            harbor_ref=PINNED_TERMINAL_BENCH_2_1_REF,
            declared=declared,
        )


def test_generic_daytona_lifecycle_preserves_harbor_separate_declaration():
    declared = task_config.HarborVerifierEnvironmentResolution(
        mode="separate",
        source="verifier.environment",
    )

    resolution = task_config.resolve_daytona_verifier_lifecycle(
        task_id="pytorch-model-recovery",
        harbor_ref=PINNED_TERMINAL_BENCH_2_1_REF,
        declared=declared,
    )

    assert resolution.effective_mode == "separate"
    assert resolution.effective_source == "verifier.environment"
    assert resolution.handoff_paths == ()
    assert resolution.override_reason is None


_PRESERVE_LIVE_SERVICE_TASK_IDS = (
    "pypi-server",
    "qemu-alpine-ssh",
    "hf-model-inference",
    "kv-store-grpc",
    "git-multibranch",
    "mailman",
    "nginx-request-logging",
    "qemu-startup",
    "install-windows-3.11",
    "configure-git-webserver",
)

_SELF_START_VERIFIER_TASK_IDS = (
    "headless-terminal",
    "torch-pipeline-parallelism",
    "torch-tensor-parallelism",
)


@pytest.mark.parametrize("task_id", _PRESERVE_LIVE_SERVICE_TASK_IDS)
def test_pinned_session_lifecycle_preserves_declared_live_service(task_id):
    resolution = task_config.resolve_agent_session_lifecycle(
        task_id=task_id,
        harbor_ref=task_config.TERMINAL_BENCH_REF,
    )

    assert resolution.lifecycle == "preserve_until_verified"
    assert resolution.source == "boundarybench_ref_task_policy"
    assert resolution.reason == "verifier_requires_live_service"
    assert resolution.service_evidence
    assert isinstance(resolution.service_evidence, str)


@pytest.mark.parametrize("task_id", _SELF_START_VERIFIER_TASK_IDS)
def test_pinned_session_lifecycle_deletes_when_verifier_self_starts(task_id):
    resolution = task_config.resolve_agent_session_lifecycle(
        task_id=task_id,
        harbor_ref=task_config.TERMINAL_BENCH_REF,
    )

    assert resolution.lifecycle == "delete_on_agent_exit"
    assert resolution.source == "boundarybench_ref_task_policy"
    assert resolution.reason == "verifier_self_starts_service_from_artifacts"
    assert resolution.service_evidence


def test_session_lifecycle_falls_back_to_safe_delete_default():
    unlisted_on_pinned_ref = task_config.resolve_agent_session_lifecycle(
        task_id="pytorch-model-recovery",
        harbor_ref=task_config.TERMINAL_BENCH_REF,
    )
    listed_on_other_ref = task_config.resolve_agent_session_lifecycle(
        task_id="pypi-server",
        harbor_ref="sha256:another-terminal-bench-ref",
    )

    for resolution in (unlisted_on_pinned_ref, listed_on_other_ref):
        assert resolution.lifecycle == "delete_on_agent_exit"
        assert resolution.source == "safe_default"
        assert resolution.reason == "unlisted_tasks_delete_agent_session_after_exit"
        assert resolution.service_evidence is None


def test_preserve_until_verified_tasks_never_reap_the_agent_process():
    for (harbor_ref, task_id), resolution in (
        task_config._AGENT_SESSION_LIFECYCLE_POLICIES.items()
    ):
        if resolution.lifecycle != "preserve_until_verified":
            continue
        disposition = task_config.resolve_agent_process_disposition(
            task_id=task_id,
            harbor_ref=harbor_ref,
            declared=task_config.HarborVerifierEnvironmentResolution(
                mode="shared",
                source="harbor_default",
            ),
        )
        assert disposition.disposition == "preserve", (harbor_ref, task_id)
