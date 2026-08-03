from __future__ import annotations

from dataclasses import replace

from boundarybench.daytona.hardening_config import DEFAULT_DAYTONA_HARDENING_CONFIG
from boundarybench.policy_surfaces.preflight import (
    PolicyPreflightSpec,
    build_policy_proof_plan_from_spec,
)


def test_policy_preflight_plan_is_built_from_shared_policy_spec():
    config = replace(
        DEFAULT_DAYTONA_HARDENING_CONFIG,
        name="shared-policy-test",
        denied_command_names=("curl",),
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=(),
        strip_env_vars=(),
    )

    plan = build_policy_proof_plan_from_spec(
        PolicyPreflightSpec(
            policy="shared-policy-test",
            overlays=("blocked-surfaces",),
            config=config,
            agent_user="daytona",
            run_agent_as_root=False,
        )
    )

    assert plan.policy == "shared-policy-test"
    assert [rule.rule_id for rule in plan.rules] == ["command-name:curl"]
    assert [probe.probe_id for probe in plan.probes] == ["command-name:curl:probe"]


def test_pip_child_network_probes_use_trusted_http_target():
    config = replace(
        DEFAULT_DAYTONA_HARDENING_CONFIG,
        name="pip-child-network-test",
        denied_command_names=(),
        denied_exec_paths=(),
        denied_path_exact=(),
        denied_path_prefixes=(),
        tee_denied_patterns=(),
        child_network_command_names=("pip", "pip3"),
        strip_env_vars=(),
    )

    plan = build_policy_proof_plan_from_spec(
        PolicyPreflightSpec(
            policy="pip-child-network-test",
            overlays=("child-network",),
            config=config,
            agent_user="daytona",
            run_agent_as_root=False,
        )
    )

    commands = {probe.rule_id: probe.command for probe in plan.probes}
    assert "--trusted-host 93.184.216.34" in commands["child-network:pip"]
    assert "--trusted-host 93.184.216.34" in commands["child-network:pip3"]
    assert "--retries 0" in commands["child-network:pip"]
