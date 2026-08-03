from __future__ import annotations

import boundarybench.enforcement as enforcement_exports
from boundarybench.enforcement import (
    EnforcementConfig,
    EnforcementEvent,
    PreflightCheck,
    PreflightResult,
    REQUIRED_AGENTSH_SEV1_CHECK_IDS,
    get_enforcement_config,
)


def test_agentsh_sev1_fixture_config_has_stable_required_check_ids():
    config = get_enforcement_config("agentsh_sev1_fixture")

    assert config.config_id == "agentsh_sev1_fixture"
    assert config.backend == "agentsh"
    assert config.task_id == "log-summary-date-ranges"
    assert config.severity == "sev1"
    assert [check.check_id for check in config.preflight_checks] == [
        *REQUIRED_AGENTSH_SEV1_CHECK_IDS,
        "agentsh_sev1_fixture.audit.ordering",
    ]
    env_check = next(
        check for check in config.preflight_checks if check.check_id.endswith(".env.proc_environ")
    )
    assert env_check.metadata["scope"] == "preflight_exec_only"
    assert env_check.metadata["agent_runtime_covered"] is False


def test_backend_neutral_models_serialize_metadata():
    check = PreflightCheck(
        check_id="agentsh_sev1_fixture.command_shim.curl_name",
        hardening_type="command_shim",
        command=("curl", "--version"),
        expect_exit_code=None,
        expect_success=False,
        description="curl should be denied by PATH shim",
        metadata={"vector": "name"},
    )
    config = EnforcementConfig(
        config_id="custom",
        backend="agentsh",
        severity="sev1",
        task_id="example-task",
        blocked_commands=("curl",),
        blocked_binary_paths=("/tmp/boundary-hardening-fixture/binary-denied/curl",),
        blocked_read_paths=("/tmp/secret",),
        blocked_write_paths=("/tmp/denied",),
        blocked_exec_paths=("/tmp/tool.sh",),
        blocked_env_vars=("SECRET",),
        require_non_root_user=True,
        network_policy="deny",
        capability_policy="drop",
        preflight_checks=(check,),
    )
    event = EnforcementEvent(
        event_type="preflight_result",
        backend="agentsh",
        config_id="custom",
        status="pass",
        message="ok",
        metadata={"check_id": check.check_id},
    )
    result = PreflightResult(
        check_id=check.check_id,
        hardening_type=check.hardening_type,
        expected_policy_result="deny",
        observed_runtime_result="blocked",
        backend="agentsh",
        status="pass",
        exit_code=126,
        stdout="",
        stderr="permission denied",
        backend_evidence={"path": "/tmp/shim/curl"},
    )

    assert config.to_metadata()["preflight_checks"][0]["metadata"]["vector"] == "name"
    assert event.to_metadata()["metadata"]["check_id"] == check.check_id
    result_metadata = result.to_metadata()
    assert result_metadata["agentsh_policy_result"] is None
    assert result_metadata["agentsh_event_seen"] is None
    assert result_metadata["agentsh_event_id"] is None


def test_unknown_static_config_is_rejected():
    try:
        get_enforcement_config("missing")
    except KeyError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("missing config should raise KeyError")


def test_enforcement_package_does_not_export_legacy_docker_backend():
    assert not hasattr(enforcement_exports, "DockerHardeningBackend")
    assert not hasattr(enforcement_exports, "EnforcementBackend")
