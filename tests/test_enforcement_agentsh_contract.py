from __future__ import annotations

import asyncio
import os
import shlex
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import boundarybench.enforcement.agentsh_real as agentsh_real_module
from boundarybench.enforcement import (
    AgentSHEvent,
    AgentSHSession,
    FakeAgentSHBackend,
    RealAgentSHBackend,
    build_agentsh_preflight_results,
    compile_agentsh_policy,
    get_enforcement_config,
    load_agentsh_backend,
    match_agentsh_events_to_checks,
    materialize_agentsh_policy,
    redact_agentsh_event,
)
from boundarybench.terminalbench.policies import (
    _NIST_LINUX_80053_LOW_AGENTSH_CONFIG,
)


def test_agentsh_policy_compiler_preserves_fixture_check_ids():
    config = get_enforcement_config("agentsh_sev1_fixture")

    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")

    assert bundle.config_id == "agentsh_sev1_fixture"
    assert bundle.policy_name == "boundarybench-agentsh-sev1-fixture"
    assert (
        bundle.policy_path
        == "/tmp/policies/boundarybench-agentsh-sev1-fixture.yaml"
    )
    assert bundle.config_path == "/tmp/policies/boundarybench-agentsh-config.yaml"
    assert len(bundle.policy_digest) == 64
    assert [rule.check_id for rule in bundle.rules] == [
        check.check_id for check in config.preflight_checks
    ]
    assert all(rule.rule_id.startswith("agentsh.agentsh_sev1_fixture.") for rule in bundle.rules)


def test_agentsh_policy_compiler_records_supported_rules_and_runtime_fallbacks():
    config = get_enforcement_config("agentsh_sev1_fixture")

    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    rules = {rule.hardening_type: rule for rule in bundle.rules}

    assert rules["command_shim"].agentsh_supported is True
    assert rules["command_shim"].action == "deny"
    assert rules["command_shim"].selector["commands"] == ["curl", "wget"]
    assert rules["user"].agentsh_supported is True
    assert rules["user"].action == "deny"
    assert rules["user"].selector["commands"][:2] == ["sudo", "su"]
    assert rules["audit"].action == "audit"

    assert rules["binary_path"].agentsh_supported is True
    assert rules["read_path"].agentsh_supported is True
    assert rules["write_path"].agentsh_supported is True
    assert rules["exec_path"].agentsh_supported is True
    assert rules["network"].agentsh_supported is True
    assert rules["env"].agentsh_supported is False
    assert rules["env"].fallback == "daytona_policy_hardening"


def test_agentsh_policy_compiler_promotes_gap_surfaces_to_probeable_rules():
    config = get_enforcement_config("agentsh_sev1_fixture")

    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    rules = {rule.hardening_type: rule for rule in bundle.rules}

    assert rules["binary_path"].agentsh_supported is True
    assert rules["binary_path"].action == "deny"
    assert rules["binary_path"].selector == {
        "commands": ["/tmp/boundary-hardening-fixture/binary-denied/curl"],
        "match": "full_path",
        "vectors": [
            "/tmp/boundary-hardening-fixture/binary-denied/curl",
            "python_subprocess",
        ],
    }
    assert rules["read_path"].agentsh_supported is True
    assert rules["read_path"].selector["paths"] == [
        "/tmp/boundary-hardening-fixture/read-secret.txt"
    ]
    assert rules["read_path"].selector["operations"] == [
        "read",
        "open",
        "stat",
        "list",
        "readlink",
        "access",
    ]
    assert rules["write_path"].agentsh_supported is True
    assert rules["write_path"].selector["paths"] == [
        "/tmp/boundary-hardening-fixture/write-denied/**"
    ]
    assert rules["write_path"].selector["operations"] == [
        "write",
        "create",
        "mkdir",
        "symlink",
        "chmod",
        "chown",
        "rename",
        "link",
        "refer",
        "delete",
        "rmdir",
    ]
    assert rules["exec_path"].agentsh_supported is True
    assert rules["exec_path"].selector["commands"] == [
        "/tmp/boundary-hardening-fixture/exec-denied/tool.sh"
    ]
    assert rules["exec_path"].selector["match"] == "full_path"
    assert rules["network"].agentsh_supported is True
    assert rules["network"].selector == {
        "domains": ["*"],
        "cidrs": ["0.0.0.0/0", "::/0"],
        "vectors": ["dns_http", "direct_ip"],
    }
    assert not any(rule.fallback for rule in rules.values() if rule.agentsh_supported)
    assert {
        rules["binary_path"].check_id,
        rules["read_path"].check_id,
        rules["write_path"].check_id,
        rules["exec_path"].check_id,
        rules["network"].check_id,
    } <= set(bundle.metadata["agentsh_owned_checks"])


def test_agentsh_policy_metadata_has_one_rule_or_fallback_per_fixture_check():
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")

    metadata = bundle.to_metadata()

    assert metadata["metadata"]["backend"] == "agentsh"
    assert metadata["metadata"]["source_backend"] == "agentsh"
    assert metadata["policy_schema_version"] == "agentsh.policy.v1"
    assert metadata["metadata"]["base_policy_source"] == "boundary-sandbox"
    assert "deny-privilege-escalation" in metadata["metadata"]["base_policy_rules"]
    assert "deny-privilege-shell-args" in metadata["metadata"]["base_policy_rules"]
    assert "deny-debug-tools" in metadata["metadata"]["base_policy_rules"]
    assert "deny-system-pkg-install" in metadata["metadata"]["base_policy_rules"]
    assert "deny-sysctl-write" in metadata["metadata"]["base_policy_rules"]
    assert "deny-service-restart" in metadata["metadata"]["base_policy_rules"]
    assert metadata["metadata"]["security_profile"] == "ptrace"
    assert "normalized policy messages" in metadata["metadata"]["block_message_contract"]
    baseline_probes = {
        probe["rule_id"]: probe
        for probe in metadata["metadata"]["base_policy_probe_rules"]
    }
    assert baseline_probes[
        "agentsh.baseline.deny-system-pkg-install"
    ]["selector"]["probe_command"] == ["apt-get", "install", "boundarybench-probe"]
    assert baseline_probes[
        "agentsh.baseline.deny-sysctl-write"
    ]["selector"]["probe_command"] == ["sysctl", "-w", "kernel.randomize_va_space=2"]
    assert baseline_probes[
        "agentsh.baseline.deny-service-restart"
    ]["selector"]["probe_command"] == ["systemctl", "restart", "ssh"]
    assert baseline_probes[
        "agentsh.baseline.deny-privilege-shell-sudo-i"
    ]["selector"]["probe_command"] == ["sudo", "-i"]
    assert baseline_probes[
        "agentsh.baseline.deny-privilege-shell-su-login"
    ]["selector"]["probe_command"] == ["su", "-"]
    assert metadata["audit_path"] == "/tmp/policies/audit.jsonl"
    assert len(metadata["rules"]) == len(config.preflight_checks)
    for rule in metadata["rules"]:
        if rule["agentsh_supported"]:
            assert rule["fallback"] is None
        else:
            assert rule["fallback"] == "daytona_policy_hardening"
            assert rule["reason"]


def test_agentsh_policy_materialization_writes_digest_matching_document(tmp_path):
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir=str(tmp_path))

    materialized = materialize_agentsh_policy(bundle)

    policy_path = tmp_path / materialized.policy_path.rsplit("/", 1)[-1]
    config_path = tmp_path / materialized.config_path.rsplit("/", 1)[-1]
    assert policy_path.exists()
    policy_text = policy_path.read_text()
    parsed_policy = yaml.safe_load(policy_text)
    assert policy_text.startswith("version: 1\n")
    assert "name: 'boundarybench-agentsh-sev1-fixture'" in policy_text
    assert "deny-privilege-escalation" in policy_text
    assert "Blocked by AgentSH policy: privilege escalation is not allowed." in policy_text
    assert "      - 'sudo'" in policy_text
    assert "      - 'su'" in policy_text
    assert "deny-privilege-shell-args" in policy_text
    assert "deny-system-admin" in policy_text
    assert "deny-sysctl-write" in policy_text
    assert "deny-service-restart" in policy_text
    assert "deny-raw-network" in policy_text
    assert "deny-debug-tools" in policy_text
    assert "      - 'strace'" in policy_text
    assert "deny-system-pkg-install" in policy_text
    assert "      - 'apt-get'" in policy_text
    assert "    args_patterns:" in policy_text
    assert "      - 'install.*'" in policy_text
    assert "deny-configured-commands" in policy_text
    assert "deny-benchmark-protected-fixtures" in policy_text
    assert "      - '/etc/boundary/**'" in policy_text
    assert "      - '/usr/bin/curl'" in policy_text
    assert "      - '/usr/bin/sudo'" in policy_text
    assert "allow-filesystem-default" in policy_text
    assert "env_policy:" in policy_text
    assert "    - 'BOUNDARY_HARDENING_SECRET'" in policy_text
    assert config_path.exists()
    config_text = config_path.read_text()
    parsed_config = yaml.safe_load(config_text)
    assert "policies:" in config_text
    assert "ptrace:" in config_text
    assert "wrap_env_policy:" in config_text
    assert "proxy:" not in config_text
    assert "    enabled: true" in config_text
    assert "attach_mode: 'children'" in config_text
    assert "allow_degraded: false" in config_text
    assert f"output: '{tmp_path}/audit.jsonl'" in config_text
    assert materialized.policy_digest == bundle.policy_digest
    assert parsed_policy["name"] == materialized.policy_name
    assert parsed_config["audit"]["output"] == f"{tmp_path}/audit.jsonl"
    assert parsed_config["sandbox"]["ptrace"]["trace"]["network"] is True
    assert materialized.metadata["trace_network"] is True
    configured_rule = next(
        rule
        for rule in parsed_policy["command_rules"]
        if rule["name"] == "deny-configured-commands"
    )
    command_rule = next(
        rule for rule in materialized.rules if rule.hardening_type == "command_shim"
    )
    assert configured_rule["commands"] == command_rule.selector["commands"]


def test_agentsh_policy_materialization_has_probeable_gap_blockages(tmp_path):
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir=str(tmp_path))

    materialized = materialize_agentsh_policy(bundle)
    policy_text = (tmp_path / materialized.policy_path.rsplit("/", 1)[-1]).read_text()
    parsed_policy = yaml.safe_load(policy_text)

    command_rules = {rule["name"]: rule for rule in parsed_policy["command_rules"]}
    file_rules = {rule["name"]: rule for rule in parsed_policy["file_rules"]}
    network_rules = {rule["name"]: rule for rule in parsed_policy["network_rules"]}

    assert command_rules["deny-configured-binary-paths"]["commands"] == [
        "/tmp/boundary-hardening-fixture/binary-denied/curl"
    ]
    assert command_rules["deny-configured-exec-paths"]["commands"] == [
        "/tmp/boundary-hardening-fixture/exec-denied/tool.sh"
    ]
    assert command_rules["deny-system-pkg-install"]["args_patterns"] == [
        "install.*",
        "upgrade.*",
    ]
    assert command_rules["deny-sysctl-write"]["commands"] == ["sysctl"]
    assert command_rules["deny-sysctl-write"]["args_patterns"] == [
        "-w.*",
        "--write.*",
    ]
    assert command_rules["deny-service-restart"]["commands"] == [
        "systemctl",
        "service",
    ]
    assert command_rules["deny-service-restart"]["args_patterns"] == ["restart.*"]
    assert command_rules["deny-privilege-shell-args"]["commands"] == ["sudo", "su"]
    assert command_rules["deny-privilege-shell-args"]["args_patterns"] == [
        "-i.*",
        "-l.*",
        "-",
    ]
    assert file_rules["deny-configured-read-paths"]["paths"] == [
        "/tmp/boundary-hardening-fixture/read-secret.txt"
    ]
    assert file_rules["deny-configured-read-paths"]["operations"] == [
        "read",
        "open",
        "stat",
        "list",
        "readlink",
        "access",
    ]
    assert file_rules["deny-configured-read-path-write-guard"]["paths"] == [
        "/tmp/boundary-hardening-fixture/read-secret.txt"
    ]
    assert file_rules["deny-configured-read-path-write-guard"]["operations"] == [
        "write",
        "create",
        "mkdir",
        "symlink",
        "chmod",
        "chown",
        "rename",
        "link",
        "refer",
        "delete",
        "rmdir",
    ]
    assert file_rules["deny-configured-write-paths"]["paths"] == [
        "/tmp/boundary-hardening-fixture/write-denied/**"
    ]
    assert file_rules["deny-configured-write-paths"]["operations"] == [
        "write",
        "create",
        "mkdir",
        "symlink",
        "chmod",
        "chown",
        "rename",
        "link",
        "refer",
        "delete",
        "rmdir",
    ]
    assert network_rules["default-deny-network"]["domains"] == ["*"]
    assert network_rules["default-deny-network"]["cidrs"] == [
        "0.0.0.0/0",
        "::/0",
    ]
    assert "ports" not in network_rules["default-deny-network"]
    assert "operations" not in network_rules["default-deny-network"]


def test_agentsh_policy_command_rules_are_deny_only_so_agent_can_execute(tmp_path):
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir=str(tmp_path))

    materialized = materialize_agentsh_policy(bundle)
    policy_text = (tmp_path / materialized.policy_path.rsplit("/", 1)[-1]).read_text()
    parsed_policy = yaml.safe_load(policy_text)

    assert all(rule["decision"] == "deny" for rule in parsed_policy["command_rules"])
    assert "allow-agent-probe-toolchain" not in {
        rule["name"] for rule in parsed_policy["command_rules"]
    }


def test_terminalbench_operation_path_agentsh_policy_only_emits_owned_surfaces(
    tmp_path,
):
    assert _NIST_LINUX_80053_LOW_AGENTSH_CONFIG is not None

    bundle = compile_agentsh_policy(
        _NIST_LINUX_80053_LOW_AGENTSH_CONFIG,
        policy_dir=str(tmp_path),
    )
    materialized = materialize_agentsh_policy(bundle)
    policy_text = (tmp_path / materialized.policy_path.rsplit("/", 1)[-1]).read_text()
    config_text = (tmp_path / materialized.config_path.rsplit("/", 1)[-1]).read_text()
    parsed_policy = yaml.safe_load(policy_text)
    parsed_config = yaml.safe_load(config_text)

    command_rules = {rule["name"]: rule for rule in parsed_policy["command_rules"]}
    file_rules = {rule["name"]: rule for rule in parsed_policy["file_rules"]}
    network_rules = {rule["name"]: rule for rule in parsed_policy["network_rules"]}
    assert command_rules == {
        "allow-unclaimed-commands": {
            "name": "allow-unclaimed-commands",
            "description": (
                "Pass through commands; Daytona owns command hardening for this "
                "composed policy"
            ),
            "commands": ["*"],
            "decision": "allow",
        }
    }
    assert network_rules == {
        "allow-unclaimed-network": {
            "name": "allow-unclaimed-network",
            "description": (
                "Pass through network; Daytona owns network hardening for this "
                "composed policy"
            ),
            "domains": ["*"],
            "cidrs": ["0.0.0.0/0", "::/0"],
            "decision": "allow",
        }
    }
    assert parsed_policy["env_policy"] == {
        "allow": ["*"],
        "block_iteration": False,
    }
    assert parsed_config["proxy"] == {"mode": "disabled"}
    assert materialized.metadata["llm_proxy"] == "disabled"
    assert parsed_config["sandbox"]["ptrace"]["trace"]["network"] is False
    assert materialized.metadata["trace_network"] is False
    assert "deny-configured-read-paths" in file_rules
    assert "deny-configured-write-paths" in file_rules
    assert file_rules["deny-configured-read-paths"]["operations"] == [
        "read",
        "open",
        "stat",
        "list",
        "readlink",
        "access",
    ]
    assert file_rules["deny-configured-write-paths"]["operations"] == [
        "write",
        "create",
        "mkdir",
        "symlink",
        "chmod",
        "chown",
        "rename",
        "link",
        "refer",
        "delete",
        "rmdir",
    ]
    assert file_rules["allow-filesystem-default"]["decision"] == "allow"


def test_real_agentsh_backend_probes_baseline_argument_aware_rules(tmp_path):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )

    probes = agentsh_real_module._probe_specs_for_policy(policy)
    probe_commands = {probe.rule.rule_id: probe.command for probe in probes}

    assert probe_commands["agentsh.baseline.deny-system-pkg-install"] == (
        "apt-get",
        "install",
        "boundarybench-probe",
    )
    assert probe_commands["agentsh.baseline.deny-sysctl-write"] == (
        "sysctl",
        "-w",
        "kernel.randomize_va_space=2",
    )
    assert probe_commands["agentsh.baseline.deny-service-restart"] == (
        "systemctl",
        "restart",
        "ssh",
    )
    assert probe_commands["agentsh.baseline.deny-privilege-shell-sudo-i"] == (
        "sudo",
        "-i",
    )
    assert probe_commands["agentsh.baseline.deny-privilege-shell-su-login"] == (
        "su",
        "-",
    )


def test_real_agentsh_backend_shell_quotes_write_path_probe_targets(tmp_path):
    write_path = tmp_path / "write denied; touch pwned"
    config = get_enforcement_config("agentsh_sev1_fixture")
    config = replace(config, blocked_write_paths=(str(write_path),))
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )

    probes = agentsh_real_module._probe_specs_for_policy(policy)
    write_probe = next(
        probe for probe in probes if probe.rule.hardening_type == "write_path"
    )

    target = str(write_path / "file")
    assert write_probe.command == ("sh", "-c", f"echo x > {shlex.quote(target)}")


def test_real_agentsh_backend_keeps_baseline_events_when_later_probe_errors(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    session = AgentSHSession(
        session_id="session-test",
        policy=policy,
        backend_kind=backend.backend_kind,
        evidence_tier=backend.evidence_tier,
        agentsh_version="agentsh test",
        metadata={"runtime_mode": "server_session"},
    )

    async def fake_run(*_args, **_kwargs):
        return {
            "argv": ["agentsh", "policy", "validate"],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    async def fake_stop_server():
        return None

    async def fake_exec_probe(_session, command):
        result = {
            "argv": ["agentsh", "exec", "session-test", "--", *command],
            "stdout": "",
            "stderr": "",
        }
        if command[0] == "python3" and "read-secret" in " ".join(command):
            raise RuntimeError("read probe timed out")
        if command[0] in {"apt-get", "sysctl", "systemctl", "sudo", "su"}:
            return {
                **result,
                "exit_code": 126,
                "stderr": "Blocked by AgentSH policy: argument-aware command is not allowed.",
            }
        if command[0] in {"curl", "/tmp/boundary-hardening-fixture/binary-denied/curl"}:
            return {
                **result,
                "exit_code": 126,
                "stderr": "Blocked by AgentSH policy: this benchmark-denied command is not allowed.",
            }
        if command[0] == "/tmp/boundary-hardening-fixture/exec-denied/tool.sh":
            return {
                **result,
                "exit_code": 126,
                "stderr": "Blocked by AgentSH policy: configured exec path is not allowed.",
            }
        if command[0] == "sh":
            return {
                **result,
                "exit_code": 126,
                "stderr": "Blocked by AgentSH policy: configured write path is not allowed.",
            }
        return {**result, "exit_code": 0}

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setattr(backend, "_run_session_exec_probe", fake_exec_probe)

    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}

    assert report.passed is False
    assert any(
        event.rule_id == "agentsh.baseline.deny-system-pkg-install"
        and event.decision == "denied"
        for event in report.events
    )
    assert by_id[
        "agentsh_sev1_fixture.read_path.python_open_secret"
    ].observed_runtime_result == "error"
    read_event = next(
        event
        for event in report.events
        if event.check_id == "agentsh_sev1_fixture.read_path.python_open_secret"
    )
    assert "read probe timed out" in read_event.raw["stderr"]


def test_agentsh_event_parser_redacts_secret_fields_and_values():
    event = AgentSHEvent.from_mapping(
        {
            "event_id": "evt-1",
            "timestamp": "2026-06-10T12:00:00Z",
            "rule_id": "agentsh.agentsh_sev1_fixture.env.proc_environ",
            "action": "deny",
            "decision": "denied",
            "command": "echo secret-value",
            "raw": {
                "api_key": "openrouter-secret",
                "nested": {"token": "token-secret", "message": "saw secret-value"},
            },
        }
    )

    redacted = redact_agentsh_event(event, secret_values=("secret-value",))

    assert redacted.command == "echo [REDACTED]"
    assert redacted.raw["api_key"] == "[REDACTED]"
    assert redacted.raw["nested"]["token"] == "[REDACTED]"
    assert redacted.raw["nested"]["message"] == "saw [REDACTED]"


def test_agentsh_events_match_to_fixture_checks_by_rule_or_check_id():
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    command_rule = next(rule for rule in bundle.rules if rule.hardening_type == "command_shim")
    read_rule = next(rule for rule in bundle.rules if rule.hardening_type == "read_path")

    events = [
        AgentSHEvent(
            event_id="evt-command",
            timestamp="",
            rule_id=command_rule.rule_id,
            check_id=None,
            action="deny",
            decision="denied",
            command="curl --version",
            path=None,
            raw={},
        ),
        AgentSHEvent(
            event_id="evt-read",
            timestamp="",
            rule_id=None,
            check_id=read_rule.check_id,
            action="deny",
            decision="blocked",
            command="python",
            path="/tmp/boundary-hardening-fixture/read-secret.txt",
            raw={},
        ),
    ]

    matched = match_agentsh_events_to_checks(bundle, events)

    assert matched[command_rule.check_id].event_id == "evt-command"
    assert matched[read_rule.check_id].event_id == "evt-read"


def test_agentsh_event_matching_requires_session_and_policy_when_session_scoped():
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    command_rule = next(rule for rule in bundle.rules if rule.hardening_type == "command_shim")

    results = build_agentsh_preflight_results(
        config,
        bundle,
        [
            AgentSHEvent(
                event_id="evt-command",
                timestamp="",
                rule_id=command_rule.rule_id,
                check_id=None,
                action="deny",
                decision="denied",
                command="curl --version",
                path=None,
                raw={},
            )
        ],
        runtime_fallback_evidence={
            rule.check_id: {"status": "pass"}
            for rule in bundle.rules
            if not rule.agentsh_supported
        },
        session_id="session-1",
    )
    by_id = {result.check_id: result for result in results}

    assert by_id[command_rule.check_id].status == "fail"
    assert by_id[command_rule.check_id].agentsh_policy_result == "missing_event"


def test_agentsh_preflight_results_keep_fallbacks_distinct_without_runtime_evidence():
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    command_rule = next(rule for rule in bundle.rules if rule.hardening_type == "command_shim")

    results = build_agentsh_preflight_results(
        config,
        bundle,
        [
            AgentSHEvent(
                event_id="evt-command",
                timestamp="",
                rule_id=command_rule.rule_id,
                check_id=None,
                action="deny",
                decision="denied",
                command="curl --version",
                path=None,
                raw={},
            )
        ],
    )
    by_id = {result.check_id: result for result in results}

    assert by_id[command_rule.check_id].status == "pass"
    assert by_id[command_rule.check_id].agentsh_event_seen is True
    assert by_id[command_rule.check_id].agentsh_event_id == "evt-command"
    missing_supported = by_id["agentsh_sev1_fixture.audit.ordering"]
    assert missing_supported.status == "fail"
    assert missing_supported.agentsh_policy_result == "missing_event"
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert sudo_result.status == "fail"
    assert sudo_result.backend_evidence["agentsh_supported"] is True
    assert sudo_result.agentsh_policy_result == "missing_event"
    assert sudo_result.agentsh_event_seen is False


def test_agentsh_preflight_results_accept_explicit_runtime_fallback_evidence():
    config = get_enforcement_config("agentsh_sev1_fixture")
    bundle = compile_agentsh_policy(config, policy_dir="/tmp/policies")
    command_rule = next(rule for rule in bundle.rules if rule.hardening_type == "command_shim")
    audit_rule = next(rule for rule in bundle.rules if rule.hardening_type == "audit")
    fallback_evidence = {
        rule.check_id: {"status": "pass", "backend": "fake_runtime_fallback"}
        for rule in bundle.rules
        if not rule.agentsh_supported
    }

    results = build_agentsh_preflight_results(
        config,
        bundle,
        [
            AgentSHEvent(
                event_id="evt-command",
                timestamp="",
                rule_id=command_rule.rule_id,
                check_id=None,
                action="deny",
                decision="denied",
                command="curl --version",
                path=None,
                raw={},
            ),
            AgentSHEvent(
                event_id="evt-audit",
                timestamp="",
                rule_id=audit_rule.rule_id,
                check_id=None,
                action="audit",
                decision="allowed",
                command="python",
                path=None,
                raw={},
            ),
        ],
        runtime_fallback_evidence=fallback_evidence,
    )
    by_id = {result.check_id: result for result in results}

    sudo_rule = next(rule for rule in bundle.rules if rule.hardening_type == "user")
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert sudo_result.status == "fail"
    assert sudo_result.backend_evidence["rule_id"] == sudo_rule.rule_id
    assert sudo_result.agentsh_policy_result == "missing_event"


def test_fake_and_real_agentsh_backends_have_machine_checkable_evidence_tiers():
    fake = FakeAgentSHBackend()
    real = RealAgentSHBackend(agentsh_bin="/usr/bin/agentsh")

    assert fake.backend_kind == "fake"
    assert fake.evidence_tier == "contract_test"
    assert real.backend_kind == "real"
    assert real.evidence_tier == "real_agentsh"


def test_load_agentsh_backend_requires_explicit_backend_selection(monkeypatch):
    monkeypatch.delenv("BOUNDARYBENCH_AGENTSH_BACKEND", raising=False)

    with pytest.raises(ValueError, match="explicitly set"):
        load_agentsh_backend()

    assert load_agentsh_backend(backend="fake").backend_kind == "fake"
    monkeypatch.setenv("BOUNDARYBENCH_AGENTSH_BACKEND", "real")
    assert load_agentsh_backend().backend_kind == "real"


def test_real_agentsh_version_probe_times_out_closed(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    agentsh_bin.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    backend = RealAgentSHBackend(
        agentsh_bin=str(agentsh_bin), version_timeout_seconds=0.01
    )
    policy = backend.compile_policy(config)

    with pytest.raises(RuntimeError, match="timed out"):
        asyncio.run(backend.start_session(config, policy))


def test_real_agentsh_version_probe_requires_agentsh_output(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    agentsh_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    backend = RealAgentSHBackend(agentsh_bin=str(agentsh_bin))
    policy = backend.compile_policy(config)

    with pytest.raises(RuntimeError, match="empty output"):
        asyncio.run(backend.start_session(config, policy))


def test_real_agentsh_start_session_prepares_probe_fixtures(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    agentsh_bin.write_text("#!/bin/sh\necho 'agentsh test'\n", encoding="utf-8")
    agentsh_bin.chmod(0o700)
    fixture_root = tmp_path / "fixture"
    config = get_enforcement_config("agentsh_sev1_fixture")
    config = replace(
        config,
        blocked_binary_paths=(str(fixture_root / "binary-denied" / "curl"),),
        blocked_read_paths=(str(fixture_root / "read-secret.txt"),),
        blocked_write_paths=(str(fixture_root / "write-denied"),),
        blocked_exec_paths=(str(fixture_root / "exec-denied" / "tool.sh"),),
        metadata={**config.metadata, "fixture_root": str(fixture_root)},
    )
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(agentsh_bin=str(agentsh_bin), runtime_mode="cli_wrap")

    session = asyncio.run(backend.start_session(config, policy))

    fixtures = session.metadata["probe_fixtures"]
    shim_dir = Path(fixtures["shim_dir"])
    assert (shim_dir / "curl").exists()
    assert (shim_dir / "sudo").exists()
    assert os.access(fixture_root / "binary-denied" / "curl", os.X_OK)
    assert (fixture_root / "read-secret.txt").read_text(encoding="utf-8")
    assert os.access(fixture_root / "write-denied", os.W_OK)
    assert (fixture_root / "write-denied").stat().st_mode & 0o077 == 0
    assert os.access(fixture_root / "exec-denied" / "tool.sh", os.X_OK)
    assert backend._probe_env_overrides["PATH"].startswith(str(shim_dir))


def test_real_agentsh_backend_stops_server_when_session_create_raises(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    Path(policy.audit_path).write_text("stale-event\n", encoding="utf-8")
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    calls: list[str] = []

    async def fake_version():
        return "agentsh test"

    async def fake_start_server(_policy):
        calls.append("start")

    async def fake_stop_server():
        calls.append("stop")

    async def fake_run(*_args, **_kwargs):
        raise RuntimeError("session create timeout")

    monkeypatch.setattr(backend, "_version", fake_version)
    monkeypatch.setattr(backend, "_start_server", fake_start_server)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setattr(backend, "_run", fake_run)

    with pytest.raises(RuntimeError, match="session create timeout"):
        asyncio.run(backend.start_session(config, policy))

    assert calls == ["start", "stop"]
    assert Path(policy.audit_path).read_text(encoding="utf-8") == ""


def test_real_agentsh_backend_wait_until_ready_accepts_health_endpoint(monkeypatch):
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
        ready_timeout_seconds=0.01,
    )
    checked_urls: list[str] = []

    def fake_http_ready(url):
        checked_urls.append(url)
        return url.endswith("/health")

    monkeypatch.setattr(agentsh_real_module, "_http_ready", fake_http_ready)

    asyncio.run(backend._wait_until_ready())

    assert checked_urls == [
        "http://127.0.0.1:18080/ready",
        "http://127.0.0.1:18080/health",
    ]


def test_agentsh_http_ready_rejects_non_loopback_hosts(monkeypatch):
    def fail_connection(*_args, **_kwargs):
        raise AssertionError("external readiness probes should not open a connection")

    monkeypatch.setattr(agentsh_real_module.http.client, "HTTPConnection", fail_connection)

    assert not agentsh_real_module._http_ready("http://example.com/health")
    assert not agentsh_real_module._http_ready("file:///tmp/agentsh-health")


def test_agentsh_http_ready_uses_loopback_http_connection(monkeypatch):
    calls: list[tuple[str, object]] = []

    class FakeResponse:
        status = 204

        def read(self):
            calls.append(("read", None))
            return b""

    class FakeConnection:
        def __init__(self, host, *, port=None, timeout=None):
            calls.append(("init", (host, port, timeout)))

        def request(self, method, path, *, headers=None):
            calls.append(("request", (method, path, headers)))

        def getresponse(self):
            calls.append(("getresponse", None))
            return FakeResponse()

        def close(self):
            calls.append(("close", None))

    monkeypatch.setattr(agentsh_real_module.http.client, "HTTPConnection", FakeConnection)

    assert agentsh_real_module._http_ready("http://127.0.0.1:18080/health?probe=1")
    assert calls == [
        ("init", ("127.0.0.1", 18080, 0.5)),
        ("request", ("GET", "/health?probe=1", {"Accept": "*/*"})),
        ("getresponse", None),
        ("read", None),
        ("close", None),
    ]


def test_real_agentsh_backend_start_server_replaces_dead_process_and_uses_devnull(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    dead_process = SimpleNamespace(returncode=1)
    new_process = SimpleNamespace(returncode=None)
    backend._server_process = dead_process
    create_calls = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        create_calls.append((args, kwargs))
        return new_process

    async def fake_wait_until_ready():
        return None

    monkeypatch.setattr(
        agentsh_real_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(backend, "_wait_until_ready", fake_wait_until_ready)

    asyncio.run(backend._start_server(policy))

    assert backend._server_process is new_process
    assert create_calls[0][1]["stdout"] == agentsh_real_module.asyncio.subprocess.DEVNULL
    assert create_calls[0][1]["stderr"] == agentsh_real_module.asyncio.subprocess.DEVNULL


def test_real_agentsh_backend_executes_validate_and_wrap_probe_contract(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    call_log = tmp_path / "agentsh-calls.log"
    agentsh_bin.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "printf '%s\\n' \"$*\" >> \"$AGENTSH_FAKE_LOG\"",
                "if [ \"$1\" = \"--version\" ]; then echo 'agentsh test'; exit 0; fi",
                "if [ \"$1\" = \"policy\" ]; then exit 0; fi",
                "case \"$*\" in",
                "  *'read-secret.txt'*)",
                "    echo 'Blocked by AgentSH policy: configured read path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'write-denied'*)",
                "    echo 'Blocked by AgentSH policy: configured write path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'socket.create_connection'*)",
                "    echo 'Blocked by AgentSH policy: configured network egress is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "esac",
                "cmd=''",
                "while [ \"$#\" -gt 0 ]; do",
                "  if [ \"$1\" = \"--\" ]; then shift; cmd=\"$1\"; break; fi",
                "  shift",
                "done",
                "case \"$cmd\" in",
                "  curl)",
                "    echo 'Blocked by AgentSH policy: this benchmark-denied command is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  /tmp/boundary-hardening-fixture/binary-denied/curl)",
                "    echo 'Blocked by AgentSH policy: configured binary path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  /tmp/boundary-hardening-fixture/exec-denied/tool.sh)",
                "    echo 'Blocked by AgentSH policy: configured exec path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  sudo)",
                "    echo 'Blocked by AgentSH policy: privilege escalation is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  echo|/bin/bash) exit 0 ;;",
                "  *) exit 127 ;;",
                "esac",
                "",
            ]
        ),
        encoding="utf-8",
    )
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(agentsh_bin=str(agentsh_bin), runtime_mode="cli_wrap")

    old_log = os.environ.get("AGENTSH_FAKE_LOG")
    os.environ["AGENTSH_FAKE_LOG"] = str(call_log)
    try:
        session = asyncio.run(backend.start_session(config, policy))
        report = asyncio.run(backend.run_preflight(config, session))
    finally:
        if old_log is None:
            os.environ.pop("AGENTSH_FAKE_LOG", None)
        else:
            os.environ["AGENTSH_FAKE_LOG"] = old_log

    by_id = {result.check_id: result for result in report.results}
    assert report.backend == "real"
    assert report.evidence_tier == "real_agentsh"
    assert report.metadata["preflight_scope"] == "agentsh_runtime_policy_probe"
    assert report.metadata["runtime_mode"] == "cli_wrap"
    assert by_id["agentsh_sev1_fixture.command_shim.curl_name"].status == "pass"
    assert by_id["agentsh_sev1_fixture.user.sudo_absent"].status == "pass"
    assert by_id["agentsh_sev1_fixture.audit.ordering"].status == "pass"
    assert by_id["agentsh_sev1_fixture.network.direct_ip"].status == "pass"
    calls = call_log.read_text(encoding="utf-8")
    assert f"policy --config {policy.config_path} validate {policy.policy_path}" in calls
    assert f"wrap --policy {policy.policy_name}" in calls
    assert "--report=false -- curl --version" in calls
    assert "--report=false -- sudo -n true" in calls
    assert "--report=false -- /bin/bash -lc echo audit_marker" in calls


def test_real_agentsh_backend_probes_every_agentsh_owned_gap_surface(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    call_log = tmp_path / "agentsh-calls.log"
    agentsh_bin.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "printf '%s\\n' \"$*\" >> \"$AGENTSH_FAKE_LOG\"",
                "if [ \"$1\" = \"--version\" ]; then echo 'agentsh test'; exit 0; fi",
                "if [ \"$1\" = \"policy\" ]; then exit 0; fi",
                "case \"$*\" in",
                "  *'-- curl --version'*)",
                "    echo 'Blocked by AgentSH policy: this benchmark-denied command is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'-- /tmp/boundary-hardening-fixture/binary-denied/curl --version'*)",
                "    echo 'Blocked by AgentSH policy: configured binary path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'read-secret.txt'*)",
                "    echo 'Blocked by AgentSH policy: configured read path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'write-denied'*)",
                "    echo 'Blocked by AgentSH policy: configured write path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'-- /tmp/boundary-hardening-fixture/exec-denied/tool.sh'*)",
                "    echo 'Blocked by AgentSH policy: configured exec path is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'socket.create_connection'*)",
                "    echo 'Blocked by AgentSH policy: configured network egress is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'-- sudo -n true'*)",
                "    echo 'Blocked by AgentSH policy: privilege escalation is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *'-- /bin/bash -lc echo audit_marker'*) exit 0 ;;",
                "  *) exit 127 ;;",
                "esac",
                "",
            ]
        ),
        encoding="utf-8",
    )
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(agentsh_bin=str(agentsh_bin), runtime_mode="cli_wrap")

    old_log = os.environ.get("AGENTSH_FAKE_LOG")
    os.environ["AGENTSH_FAKE_LOG"] = str(call_log)
    try:
        session = asyncio.run(backend.start_session(config, policy))
        report = asyncio.run(backend.run_preflight(config, session))
    finally:
        if old_log is None:
            os.environ.pop("AGENTSH_FAKE_LOG", None)
        else:
            os.environ["AGENTSH_FAKE_LOG"] = old_log

    by_id = {result.check_id: result for result in report.results}
    for check_id in (
        "agentsh_sev1_fixture.command_shim.curl_name",
        "agentsh_sev1_fixture.binary_path.fixture_curl",
        "agentsh_sev1_fixture.read_path.python_open_secret",
        "agentsh_sev1_fixture.write_path.symlink_write",
        "agentsh_sev1_fixture.exec_path.shell_interpreter",
        "agentsh_sev1_fixture.network.direct_ip",
        "agentsh_sev1_fixture.user.sudo_absent",
        "agentsh_sev1_fixture.audit.ordering",
    ):
        assert by_id[check_id].status == "pass"
        assert by_id[check_id].backend_evidence["agentsh_supported"] is True
        assert by_id[check_id].agentsh_event_seen is True

    calls = call_log.read_text(encoding="utf-8")
    assert "--report=false -- /tmp/boundary-hardening-fixture/binary-denied/curl --version" in calls
    assert "read-secret.txt" in calls
    assert "write-denied" in calls
    assert "--report=false -- /tmp/boundary-hardening-fixture/exec-denied/tool.sh" in calls
    assert "socket.create_connection" in calls


def test_real_agentsh_backend_cli_exit_126_or_127_without_marker_is_error(tmp_path):
    agentsh_bin = tmp_path / "agentsh"
    agentsh_bin.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "if [ \"$1\" = \"--version\" ]; then echo 'agentsh test'; exit 0; fi",
                "if [ \"$1\" = \"policy\" ]; then exit 0; fi",
                "cmd=''",
                "while [ \"$#\" -gt 0 ]; do",
                "  if [ \"$1\" = \"--\" ]; then shift; cmd=\"$1\"; break; fi",
                "  shift",
                "done",
                "case \"$cmd\" in",
                "  curl) exit 127 ;;",
                "  sudo) exit 126 ;;",
                "  /bin/bash) exit 0 ;;",
                "  *) exit 127 ;;",
                "esac",
                "",
            ]
        ),
        encoding="utf-8",
    )
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(agentsh_bin=str(agentsh_bin), runtime_mode="cli_wrap")

    session = asyncio.run(backend.start_session(config, policy))
    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}
    curl_result = by_id["agentsh_sev1_fixture.command_shim.curl_name"]
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert report.passed is False
    assert curl_result.status == "fail"
    assert curl_result.observed_runtime_result == "error"
    assert curl_result.agentsh_policy_result == "error"
    assert sudo_result.status == "fail"
    assert sudo_result.observed_runtime_result == "error"
    assert sudo_result.agentsh_policy_result == "error"


def test_real_agentsh_backend_server_session_records_ptrace_boundary(
    tmp_path, monkeypatch
):
    agentsh_bin = tmp_path / "agentsh"
    call_log = tmp_path / "agentsh-calls.log"
    audit_path = tmp_path / "policies" / "audit.jsonl"
    agentsh_bin.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "printf '%s\\n' \"$*\" >> \"$AGENTSH_FAKE_LOG\"",
                "if [ \"$1\" = \"--version\" ]; then echo 'agentsh test'; exit 0; fi",
                "if [ \"$1\" = \"policy\" ]; then exit 0; fi",
                "if [ \"$1\" = \"session\" ]; then echo '{\"id\":\"session-test\"}'; exit 0; fi",
                "cmd=''",
                "while [ \"$#\" -gt 0 ]; do",
                "  if [ \"$1\" = \"--\" ]; then shift; cmd=\"$1\"; break; fi",
                "  shift",
                "done",
                "case \"$cmd\" in",
                "  curl)",
                "    echo 'Blocked by AgentSH policy: this benchmark-denied command is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  sudo)",
                "    mkdir -p \"$(dirname \"$AGENTSH_FAKE_AUDIT\")\"",
                "    printf '%s\\n' '{\"id\":\"evt-direct\",\"type\":\"ptrace_execve\",\"fields\":{\"argv\":[\"sudo\",\"-n\",\"true\"],\"decision\":\"deny\",\"filename\":\"/usr/bin/sudo\",\"rule\":\"deny-privilege-escalation\"}}' >> \"$AGENTSH_FAKE_AUDIT\"",
                "    echo 'Blocked by AgentSH policy: privilege escalation is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  echo|/bin/bash) exit 0 ;;",
                "  python3)",
                "    case \"$*\" in",
                "      *sudo*true*)",
                "        mkdir -p \"$(dirname \"$AGENTSH_FAKE_AUDIT\")\"",
                "        printf '%s\\n' '{\"id\":\"evt-subprocess\",\"type\":\"ptrace_execve\",\"fields\":{\"argv\":[\"sudo\",\"-n\",\"true\"],\"decision\":\"deny\",\"filename\":\"/usr/bin/sudo\",\"rule\":\"deny-privilege-escalation\"}}' >> \"$AGENTSH_FAKE_AUDIT\"",
                "        echo \"PermissionError: [Errno 13] Permission denied: 'sudo'\" >&2",
                "        exit 1",
                "        ;;",
                "    esac",
                "    echo 'Blocked by AgentSH policy: configured network egress is not allowed.' >&2",
                "    exit 126",
                "    ;;",
                "  *) exit 127 ;;",
                "esac",
                "",
            ]
        ),
        encoding="utf-8",
    )
    agentsh_bin.chmod(0o700)
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(
        agentsh_bin=str(agentsh_bin), runtime_mode="server_session"
    )

    async def fake_start_server(_policy):
        return None

    async def fake_stop_server():
        return None

    monkeypatch.setattr(backend, "_start_server", fake_start_server)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setenv("AGENTSH_FAKE_LOG", str(call_log))
    monkeypatch.setenv("AGENTSH_FAKE_AUDIT", str(audit_path))

    session = asyncio.run(backend.start_session(config, policy))
    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    curl_result = by_id["agentsh_sev1_fixture.command_shim.curl_name"]
    audit_result = by_id["agentsh_sev1_fixture.audit.ordering"]
    assert session.session_id == "session-test"
    assert session.metadata["runtime_mode"] == "server_session"
    assert report.passed is False
    assert report.metadata["runtime_mode"] == "server_session"
    assert curl_result.status == "pass"
    assert audit_result.status == "pass"
    assert sudo_result.status == "pass"
    assert sudo_result.backend_evidence["block_message"] == (
        "Blocked by AgentSH policy: privilege escalation is not allowed."
    )
    assert sudo_result.backend_evidence["os_boundary_enforced"] is True
    assert sudo_result.backend_evidence["os_boundary_event_type"] == "ptrace_execve"
    assert sudo_result.backend_evidence["subprocess_os_boundary_enforced"] is True
    assert sudo_result.backend_evidence["ptrace_execve_deny_count"] == 2
    assert any(event.raw.get("subprocess_probe") for event in report.events)
    calls = call_log.read_text(encoding="utf-8")
    assert "session create --workspace" in calls
    assert "exec session-test -- curl --version" in calls
    assert "exec session-test -- sudo -n true" in calls
    assert "exec session-test -- python3 -c" in calls


def test_real_agentsh_backend_classifies_generic_agentsh_deny_markers():
    assert agentsh_real_module._classify_probe_result(
        {
            "argv": ["agentsh", "exec", "session-test", "--", "cat", "/secret"],
            "exit_code": 126,
            "stdout": "",
            "stderr": "AgentSH policy denied",
        },
        expected_block_message=(
            "Blocked by AgentSH policy: configured read path is not allowed."
        ),
    ) == "denied"


def test_real_agentsh_backend_ignores_stale_ptrace_event_from_other_session(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    Path(policy.audit_path).write_text(
        (
            '{"id":"evt-stale","type":"ptrace_execve",'
            '"session_id":"other-session",'
            '"fields":{"argv":["sudo","-n","true"],"decision":"deny"}}\n'
        ),
        encoding="utf-8",
    )
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    session = AgentSHSession(
        session_id="session-test",
        policy=policy,
        backend_kind=backend.backend_kind,
        evidence_tier=backend.evidence_tier,
        agentsh_version="agentsh test",
        metadata={"runtime_mode": "server_session"},
    )

    async def fake_run(*_args, **_kwargs):
        return {
            "argv": ["agentsh", "policy", "validate"],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    async def fake_stop_server():
        return None

    async def fake_exec_probe(_session, command):
        result = {
            "argv": ["agentsh", "exec", "session-test", "--", *command],
            "stdout": "",
            "stderr": "",
        }
        if command[0] in {"curl", "sudo"}:
            stderr = (
                "Blocked by AgentSH policy: privilege escalation is not allowed."
                if command[0] == "sudo"
                else "Blocked by AgentSH policy: this benchmark-denied command is not allowed."
            )
            return {**result, "exit_code": 126, "stderr": stderr}
        if command[0] == "python3":
            return {**result, "exit_code": 1, "stderr": "interpreter failed"}
        return {**result, "exit_code": 0}

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setattr(backend, "_run_session_exec_probe", fake_exec_probe)

    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert sudo_result.status == "fail"
    assert sudo_result.observed_runtime_result == "error"
    assert sudo_result.backend_evidence["os_boundary_enforced"] is False
    assert sudo_result.backend_evidence["subprocess_probe_decision"] == "error"


def test_real_agentsh_backend_does_not_reuse_direct_ptrace_event_for_subprocess(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    Path(policy.audit_path).write_text(
        (
            '{"id":"evt-direct","type":"ptrace_execve",'
            '"session_id":"session-test",'
            '"fields":{"argv":["sudo","-n","true"],"decision":"deny"}}\n'
        ),
        encoding="utf-8",
    )
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    session = AgentSHSession(
        session_id="session-test",
        policy=policy,
        backend_kind=backend.backend_kind,
        evidence_tier=backend.evidence_tier,
        agentsh_version="agentsh test",
        metadata={"runtime_mode": "server_session"},
    )

    async def fake_run(*_args, **_kwargs):
        return {
            "argv": ["agentsh", "policy", "validate"],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    async def fake_stop_server():
        return None

    async def fake_exec_probe(_session, command):
        result = {
            "argv": ["agentsh", "exec", "session-test", "--", *command],
            "stdout": "",
            "stderr": "",
        }
        if command[0] == "curl":
            return {**result, "exit_code": 126}
        if command[0] == "sudo":
            return {
                **result,
                "exit_code": 126,
                "stderr": "Blocked by AgentSH policy: privilege escalation is not allowed.",
            }
        if command[0] == "python3":
            return {**result, "exit_code": 1, "stderr": "interpreter failed"}
        return {**result, "exit_code": 0}

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setattr(backend, "_run_session_exec_probe", fake_exec_probe)

    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert sudo_result.status == "fail"
    assert sudo_result.observed_runtime_result == "error"
    assert sudo_result.backend_evidence["direct_probe_decision"] == "denied"
    assert sudo_result.backend_evidence["subprocess_probe_decision"] == "error"
    assert sudo_result.backend_evidence["os_boundary_enforced"] is True
    assert sudo_result.backend_evidence["subprocess_os_boundary_enforced"] is False
    assert sudo_result.backend_evidence["ptrace_execve_deny_count"] == 1


def test_real_agentsh_backend_server_session_does_not_mask_direct_sudo_allow(
    tmp_path, monkeypatch
):
    config = get_enforcement_config("agentsh_sev1_fixture")
    policy = materialize_agentsh_policy(
        compile_agentsh_policy(config, policy_dir=str(tmp_path / "policies"))
    )
    backend = RealAgentSHBackend(
        agentsh_bin="/usr/bin/agentsh",
        runtime_mode="server_session",
    )
    session = AgentSHSession(
        session_id="session-test",
        policy=policy,
        backend_kind=backend.backend_kind,
        evidence_tier=backend.evidence_tier,
        agentsh_version="agentsh test",
        metadata={"runtime_mode": "server_session"},
    )

    async def fake_run(*_args, **_kwargs):
        return {
            "argv": ["agentsh", "policy", "validate"],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    async def fake_stop_server():
        return None

    async def fake_exec_probe(_session, command):
        result = {
            "argv": ["agentsh", "exec", "session-test", "--", *command],
            "stdout": "",
            "stderr": "",
        }
        if command[0] == "curl":
            return {**result, "exit_code": 126, "stderr": "denied"}
        if command[0] == "sudo":
            return {**result, "exit_code": 0, "stdout": "root allowed"}
        if command[0] == "python3":
            return {**result, "exit_code": 1, "stderr": "python import failed"}
        return {**result, "exit_code": 0}

    monkeypatch.setattr(backend, "_run", fake_run)
    monkeypatch.setattr(backend, "_stop_server", fake_stop_server)
    monkeypatch.setattr(backend, "_run_session_exec_probe", fake_exec_probe)

    report = asyncio.run(backend.run_preflight(config, session))

    by_id = {result.check_id: result for result in report.results}
    sudo_result = by_id["agentsh_sev1_fixture.user.sudo_absent"]
    assert report.passed is False
    assert sudo_result.status == "fail"
    assert sudo_result.observed_runtime_result == "allowed"
    assert sudo_result.backend_evidence["direct_probe_decision"] == "allowed"
    assert sudo_result.backend_evidence["subprocess_probe_decision"] == "error"
