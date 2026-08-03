from __future__ import annotations

from boundarybench.enforcement import (
    PreflightResult,
    preflight_passed,
)


def test_preflight_result_metadata_preserves_future_agentsh_fields():
    result = PreflightResult(
        check_id="agentsh_sev1_fixture.user.sudo_absent",
        hardening_type="user",
        expected_policy_result="deny",
        observed_runtime_result="blocked",
        backend="agentsh",
        status="pass",
        exit_code=32,
        stdout="",
        stderr="permission denied",
        backend_evidence={"operation": "sudo_absent"},
        agentsh_policy_result=None,
        agentsh_event_seen=None,
        agentsh_event_id=None,
    )

    metadata = result.to_metadata()

    assert metadata["agentsh_policy_result"] is None
    assert metadata["agentsh_event_seen"] is None
    assert metadata["agentsh_event_id"] is None


def test_preflight_passed_requires_at_least_one_all_pass_result():
    pass_result = PreflightResult(
        check_id="agentsh_sev1_fixture.command_shim.curl_name",
        hardening_type="command_shim",
        expected_policy_result="deny",
        observed_runtime_result="blocked",
        backend="agentsh",
        status="pass",
        exit_code=127,
        stdout="",
        stderr="denied",
        backend_evidence={},
    )
    fail_result = PreflightResult(
        check_id="agentsh_sev1_fixture.network.direct_ip",
        hardening_type="network",
        expected_policy_result="deny",
        observed_runtime_result="allowed",
        backend="agentsh",
        status="fail",
        exit_code=0,
        stdout="connected",
        stderr="",
        backend_evidence={},
    )

    assert preflight_passed([]) is False
    assert preflight_passed([pass_result]) is True
    assert preflight_passed([pass_result, fail_result]) is False
