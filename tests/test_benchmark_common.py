from __future__ import annotations

from types import SimpleNamespace

import pytest

from boundarybench.benchmarks.common.policies import RUN_POLICIES, resolve_run_policy
from boundarybench.policy_catalog import compile_policy_variant
from boundarybench.benchmarks.common.status_taxonomy import (
    EvalArtifactStatus,
    FailureClass,
    JobStatus,
    TaskOutcome,
    attach_benchmark_status,
    build_benchmark_summary,
    benchmark_summary,
    classify_failure,
    classify_task_outcome,
    eval_artifact_status_from_completeness,
    print_benchmark_summary,
    sample_benchmark_status,
    valid_for_analysis,
)


def test_common_run_policy_resolves_nist_linux_80053_high_config():
    policy = resolve_run_policy("nist-linux-80053-high")

    assert policy.applies_hardening is True
    assert policy.hardening_config is not None
    assert policy.hardening_config.name == "gate-offline-tools-read-only"
    assert "apt-get" in policy.hardening_config.denied_command_names
    assert "/usr/bin/sudo" in policy.hardening_config.denied_exec_paths
    assert "OPENROUTER_API_KEY" in policy.hardening_config.strip_env_vars
    assert "python3" in policy.hardening_config.child_network_command_names
    assert "python3" not in policy.hardening_config.denied_command_names
    assert policy.hardening_config.seccomp_block_syscalls == (
        "personality",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
    )
    assert policy.hardening_config.read_only_root is True


def test_common_run_policy_registry_exposes_only_public_run_policies():
    assert set(RUN_POLICIES) == {
        "none",
        "basic-only",
        "nist-linux-80053-high",
        "nist-linux-80053-medium",
        "nist-linux-80053-low",
    }

    for removed_policy in ("enterprise-1", "default"):
        with pytest.raises(ValueError, match="unknown run policy"):
            resolve_run_policy(removed_policy)


def test_common_run_policy_resolves_five_priority_presets():
    control = resolve_run_policy("control")
    none = resolve_run_policy("none")
    basic = resolve_run_policy("basic-only")
    low = resolve_run_policy("nist-linux-80053-low")
    medium = resolve_run_policy("nist-linux-80053-medium")
    high = resolve_run_policy("nist-linux-80053-high")

    assert control.name == "none"
    assert none.name == "none"
    assert control.hardening_config is None
    assert basic.name == "basic-only"
    assert basic.hardening_config is not None
    assert basic.hardening_config.name == "basic-only"
    assert low.hardening_config is not None
    assert low.hardening_config.name == "gate-trusted-workspace-dev"
    assert medium.hardening_config is not None
    assert medium.hardening_config.name == "gate-trusted-change-controlled"
    assert high.hardening_config is not None
    assert high.hardening_config.name == "gate-offline-tools-read-only"


def test_common_run_policy_accepts_native_axis_presets_at_submit_gate():
    from boundarybench.daytona.policy_axes import (
        AXIS_PRESETS,
        build_daytona_config_from_axes,
    )

    hardened_presets = (
        "non-root",
        "low-nist",
        "moderate-nist",
        "high-nist",
        "high-nist",
        "netlock",
        "fslock",
    )
    for name in hardened_presets:
        policy = resolve_run_policy(name)
        assert policy.name == name
        assert policy.applies_hardening is True
        assert policy.hardening_config == build_daytona_config_from_axes(
            AXIS_PRESETS[name]
        )

    control = resolve_run_policy("control")
    assert control.name == "none"
    assert control.hardening_config is None

    with pytest.raises(ValueError):
        resolve_run_policy("n1-f1-p1")

    assert set(RUN_POLICIES) == {
        "none",
        "basic-only",
        "nist-linux-80053-high",
        "nist-linux-80053-medium",
        "nist-linux-80053-low",
    }


def test_common_nist_policies_preserve_catalog_runtime_contracts():
    policy_cases = (
        ("nist-linux-80053-low", "nist-linux-80053-low-daytona-v1"),
        ("nist-linux-80053-medium", "nist-linux-80053-medium-daytona-v1"),
        ("nist-linux-80053-high", "nist-linux-80053-high-daytona-v1"),
    )
    list_fields = (
        "denied_command_names",
        "denied_exec_paths",
        "denied_path_exact",
        "denied_path_prefixes",
        "child_network_command_names",
        "strip_env_vars",
        "egress_cidr_denylist",
        "egress_cidr_allowlist",
        "egress_cidr_command_names",
        "seccomp_block_syscalls",
        "egress_domain_allowlist",
    )
    intentional_missing = {
        "nist-linux-80053-medium": {
            "denied_command_names": {"curl", "rsync", "scp", "sftp", "ssh", "wget"},
            "denied_exec_paths": {
                "/usr/bin/curl",
                "/usr/bin/rsync",
                "/usr/bin/scp",
                "/usr/bin/sftp",
                "/usr/bin/ssh",
                "/usr/bin/wget",
            },
            "child_network_command_names": {
                "bash",
                "bash.real",
                "curl",
                "dash",
                "python",
                "python3",
                "rsync",
                "scp",
                "sftp",
                "sh",
                "ssh",
                "wget",
            },
        },
    }
    intentional_additions = {
        "nist-linux-80053-low": {
            "denied_path_prefixes": {
                "/etc/sudoers.d/",
                "/home/daytona/.ssh/",
                "/root/.ssh/",
            },
            "strip_env_vars": {"AWS_SESSION_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY"},
        },
        "nist-linux-80053-medium": {
            "denied_path_prefixes": {"/home/daytona/.ssh/"},
        },
        "nist-linux-80053-high": {
            "denied_path_prefixes": {"/home/daytona/.ssh/"},
        },
    }

    for policy_name, variant_id in policy_cases:
        policy = resolve_run_policy(policy_name)
        assert policy.hardening_config is not None
        runtime_config = policy.hardening_config.to_metadata()
        catalog_config = compile_policy_variant(
            pack_id="nist-linux-security",
            policy_id=policy_name,
            variant_id=variant_id,
        ).plan.hardening_config

        assert runtime_config["block_message"] == catalog_config["block_message"]
        assert runtime_config["egress_cidr_default_action"] == catalog_config[
            "egress_cidr_default_action"
        ]
        assert runtime_config["egress_domain_default_action"] == catalog_config[
            "egress_domain_default_action"
        ]
        for field in list_fields:
            catalog_values = set(catalog_config[field])
            runtime_values = set(runtime_config[field])
            allowed_missing = intentional_missing.get(policy_name, {}).get(field, set())
            missing = catalog_values - runtime_values
            assert missing == allowed_missing, (policy_name, field, missing)

            if field == "egress_domain_allowlist" and policy_name != (
                "nist-linux-80053-high"
            ):
                assert {"github.com", "registry.npmjs.org", "pypi.org"} <= (
                    runtime_values - catalog_values
                )
                continue

            allowed_additions = intentional_additions.get(policy_name, {}).get(
                field,
                set(),
            )
            additions = runtime_values - catalog_values
            assert additions == allowed_additions, (policy_name, field, additions)

        if policy_name == "nist-linux-80053-high":
            assert runtime_config["read_only_root"] is True
            assert {
                "/dev/null",
                "/dev/stderr",
                "/dev/stdin",
                "/dev/stdout",
                "/dev/tty",
            } <= set(runtime_config["writable_path_exact"])
            assert {
                "/dev/fd/",
                "/dev/shm/",
                "/proc/self/fd/",
                "/var/tmp/",
            } <= set(runtime_config["writable_path_prefixes"])
        else:
            assert runtime_config["read_only_root"] is False
            assert runtime_config["writable_path_exact"] == []
            assert runtime_config["writable_path_prefixes"] == []


def test_common_run_policy_resolves_nist_medium_and_low_seccomp_configs():
    cases = [
        (
            "nist-linux-80053-medium",
            "nist-linux-80053-medium-daytona-v1",
            ("personality", "ptrace"),
        ),
        ("nist-linux-80053-low", "nist-linux-80053-low-daytona-v1", ("personality",)),
    ]

    for policy_name, _variant_id, syscalls in cases:
        policy = resolve_run_policy(policy_name)

        assert policy.applies_hardening is True
        assert policy.hardening_config is not None
        if policy_name == "nist-linux-80053-medium":
            assert policy.hardening_config.name == "gate-trusted-change-controlled"
        else:
            assert policy.hardening_config.name == "gate-trusted-workspace-dev"
        assert policy.hardening_config.seccomp_block_syscalls == syscalls


def test_sample_status_maps_pass_to_analysis_valid_result():
    status = sample_benchmark_status({"answer": "PASS", "reward": 1.0})

    assert status == {
        "schema_version": "boundarybench.benchmark-status.v1",
        "job_status": "unknown",
        "eval_artifact_status": "unknown",
        "task_outcome": "PASS",
        "failure_class": "none",
        "valid_for_analysis": True,
    }


def test_sample_status_maps_verifier_fail_to_model_task_failure():
    status = sample_benchmark_status({"answer": "FAIL", "reward": 0.0})

    assert status["task_outcome"] == "FAIL"
    assert status["failure_class"] == "task_model"
    assert status["valid_for_analysis"] is True


def test_sample_status_maps_valid_refsol_fail_to_neutral_measurement_failure():
    status = sample_benchmark_status(
        {
            "execution_mode": "reference_solution",
            "answer": "FAIL",
            "reward": 0.0,
            "verifier": {"timed_out": False},
        }
    )

    assert status["task_outcome"] == "FAIL"
    assert status["failure_class"] == "reference_solution"
    assert status["valid_for_analysis"] is True


def test_sample_status_keeps_refsol_pass_unclassified():
    status = sample_benchmark_status(
        {
            "execution_mode": "reference_solution",
            "answer": "PASS",
            "reward": 1.0,
        }
    )

    assert status["failure_class"] == "none"
    assert status["valid_for_analysis"] is True


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "execution_mode": "reference_solution",
            "answer": "ERROR",
            "preflight_failed": True,
        },
        {
            "execution_mode": "reference_solution",
            "answer": "PASS",
            "preflight_failed": True,
        },
        {
            "execution_mode": "reference_solution",
            "answer": "FAIL",
            "post_agent_verifier_error": True,
        },
        {
            "execution_mode": "reference_solution",
            "answer": "ERROR",
            "error": "DaytonaNotFoundError: sandbox container not found",
        },
    ],
)
def test_sample_status_keeps_refsol_pipeline_errors_invalid(metadata):
    status = sample_benchmark_status(metadata)

    assert status["failure_class"] != "reference_solution"
    assert status["valid_for_analysis"] is False


@pytest.mark.parametrize(
    "metadata",
    [
        {"answer": "FAIL", "post_agent_verifier_error": True},
        {"answer": "FAIL", "verifier": {"timed_out": True}},
    ],
)
def test_sample_status_preserves_agent_fail_precedence(metadata):
    status = sample_benchmark_status(metadata)

    assert status["task_outcome"] == "FAIL"
    assert status["failure_class"] == "task_model"
    assert status["valid_for_analysis"] is True


def test_sample_status_preserves_agent_pass_precedence_over_preflight():
    status = sample_benchmark_status(
        {"answer": "PASS", "reward": 1.0, "preflight_failed": True}
    )

    assert status["task_outcome"] == "PASS"
    assert status["failure_class"] == "none"
    assert status["valid_for_analysis"] is True


def test_attach_benchmark_status_adds_shared_sample_and_agent_metadata():
    metadata = {"answer": "FAIL", "reward": 0.0}

    attach_benchmark_status(
        metadata,
        agent_name="claude_code_openrouter",
        model="openrouter/anthropic/claude-sonnet-4",
    )

    assert metadata["benchmark_status"]["task_outcome"] == "FAIL"
    assert metadata["benchmark_status"]["failure_class"] == "task_model"
    assert metadata["agent_entity"] == {
        "name": "claude_code_openrouter",
        "model": "openrouter/anthropic/claude-sonnet-4",
        "benchmark_status": metadata["benchmark_status"],
    }


def test_sample_status_excludes_provider_auth_quota_errors_from_analysis():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "HTTP 403 OpenRouter key limit exceeded",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "provider_auth"
    assert status["valid_for_analysis"] is False


def test_sample_status_keeps_structured_provider_error_a_provider_failure():
    status = sample_benchmark_status(
        {
            "answer": "PROVIDER_ERROR",
            "reward": 0.0,
            "error": "provider/auth error detected: key-limit",
            "provider_error": True,
            "transient_error": True,
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "provider_auth"
    assert status["valid_for_analysis"] is False


def test_sample_status_does_not_treat_filesystem_permission_as_provider_auth():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "PermissionError: [Errno 13] Permission denied: '/etc/shadow'",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "unknown"
    assert status["valid_for_analysis"] is False


def test_eval_artifact_status_is_derived_from_completeness_status():
    assert eval_artifact_status_from_completeness(None) == EvalArtifactStatus.MISSING
    assert (
        eval_artifact_status_from_completeness(
            SimpleNamespace(status="complete", completed_samples=2)
        )
        == EvalArtifactStatus.COMPLETE
    )
    assert (
        eval_artifact_status_from_completeness(
            SimpleNamespace(status="partial", completed_samples=1)
        )
        == EvalArtifactStatus.PARTIAL
    )
    assert (
        eval_artifact_status_from_completeness(
            SimpleNamespace(status="empty", completed_samples=0)
        )
        == EvalArtifactStatus.MISSING
    )
    assert (
        eval_artifact_status_from_completeness(
            SimpleNamespace(status="error", completed_samples=1)
        )
        == EvalArtifactStatus.PARTIAL
    )
    assert (
        eval_artifact_status_from_completeness(
            SimpleNamespace(status="error", completed_samples=0)
        )
        == EvalArtifactStatus.UNREADABLE
    )


def test_sample_status_classifies_daytona_lifecycle_errors_as_infra():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "DaytonaNotFoundError: sandbox container not found",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "infra_daytona"
    assert status["valid_for_analysis"] is False


@pytest.mark.parametrize(
    "error",
    [
        "Failed to get session command",
        "failed to execute command: ",
        "bearer token is invalid",
        "DaytonaTimeoutError: sandbox creation timed out",
        "no IP address found. Is the Sandbox started?",
    ],
)
def test_sample_status_classifies_known_daytona_session_signatures(error):
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": error,
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "infra_daytona"
    assert status["valid_for_analysis"] is False


def test_sample_status_keeps_disk_quota_as_infrastructure():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "tar: test_outputs.py: Cannot open: Disk quota exceeded",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "infra_resource"
    assert status["valid_for_analysis"] is False


@pytest.mark.parametrize(
    "error",
    [
        "DaytonaValidationError: Total disk limit exceeded",
        "DaytonaValidationError: Total memory limit exceeded",
        "failed to create Daytona sandbox: sandbox capacity exhausted",
        "failed to create Daytona sandbox: account storage capacity exceeded",
        "Daytona quota exceeded while creating sandbox",
    ],
)
def test_sample_status_classifies_daytona_account_capacity_as_infra_resource(error):
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": error,
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "infra_resource"
    assert status["valid_for_analysis"] is False


def test_daytona_capacity_classification_does_not_steal_provider_quota_errors():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "OpenRouter quota exceeded while calling provider",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "provider_rate_limit"
    assert status["valid_for_analysis"] is False


def test_sample_status_classifies_hardening_preflight_errors():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "AgentSH preflight failed before upstream solver",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "hardening_preflight"
    assert status["valid_for_analysis"] is False


def test_sample_status_classifies_failed_runtime_policy_probe_as_preflight():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": (
                "Daytona policy hardening runtime probe suite failed: "
                "1 required probe(s) failed"
            ),
            "runtime_policy_probe_report": {
                "passed": False,
                "required_failed_count": 1,
            },
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "hardening_preflight"
    assert status["valid_for_analysis"] is False


def test_sample_status_classifies_verifier_artifact_errors():
    status = sample_benchmark_status(
        {
            "answer": "ERROR",
            "reward": 0.0,
            "error": "missing expected artifact: result.json",
        }
    )

    assert status["task_outcome"] == "ERROR"
    assert status["failure_class"] == "artifact_missing"
    assert status["valid_for_analysis"] is False


def test_taxonomy_enums_expose_canonical_string_values():
    assert JobStatus.COMPLETED == "completed"
    assert JobStatus.TIMEOUT == "timeout"
    assert EvalArtifactStatus.COMPLETE == "complete"
    assert EvalArtifactStatus.UNREADABLE == "unreadable"
    assert TaskOutcome.PASS == "PASS"
    assert FailureClass.INFRA_DAYTONA == "infra_daytona"
    assert FailureClass.PROVIDER_RATE_LIMIT == "provider_rate_limit"
    assert FailureClass.REFERENCE_SOLUTION == "reference_solution"


def test_classify_task_outcome_is_backward_compatible_with_answer_values():
    assert classify_task_outcome(" pass ") == TaskOutcome.PASS
    assert classify_task_outcome("FAIL") == TaskOutcome.FAIL
    assert classify_task_outcome("ERROR") == TaskOutcome.ERROR
    assert classify_task_outcome("INVALID") == TaskOutcome.INVALID
    assert classify_task_outcome("surprise") == TaskOutcome.ERROR


def test_classify_failure_uses_structured_flags_before_text_markers():
    assert (
        classify_failure(TaskOutcome.ERROR, transient_error=True)
        == FailureClass.INFRA_DAYTONA
    )
    assert (
        classify_failure(TaskOutcome.ERROR, agent_timed_out=True)
        == FailureClass.INFRA_TIMEOUT
    )
    assert (
        classify_failure(TaskOutcome.ERROR, verifier_timed_out=True)
        == FailureClass.VERIFIER_TIMEOUT
    )
    assert (
        classify_failure(TaskOutcome.ERROR, verifier_error=True)
        == FailureClass.VERIFIER_ERROR
    )
    assert (
        classify_failure(TaskOutcome.ERROR, preflight_rejected=True)
        == FailureClass.HARDENING_PREFLIGHT
    )


def test_classify_failure_preserves_provider_precedence_over_verifier_flags():
    assert (
        classify_failure(
            TaskOutcome.ERROR,
            provider_error=True,
            verifier_error=True,
        )
        == FailureClass.PROVIDER_ERROR
    )


def test_valid_for_analysis_keeps_only_model_capability_signal():
    assert valid_for_analysis(TaskOutcome.PASS, FailureClass.NONE) is True
    assert valid_for_analysis(TaskOutcome.FAIL, FailureClass.TASK_MODEL) is True
    assert (
        valid_for_analysis(TaskOutcome.FAIL, FailureClass.REFERENCE_SOLUTION) is True
    )
    assert valid_for_analysis(TaskOutcome.ERROR, FailureClass.INFRA_DAYTONA) is False
    assert (
        valid_for_analysis(TaskOutcome.ERROR, FailureClass.PROVIDER_RATE_LIMIT) is False
    )


def test_benchmark_summary_counts_outcomes_and_failure_classes():
    statuses = [
        sample_benchmark_status({"answer": "PASS", "reward": 1.0}),
        sample_benchmark_status({"answer": "FAIL", "reward": 0.0}),
        sample_benchmark_status(
            {
                "answer": "ERROR",
                "reward": 0.0,
                "error": "HTTP 403 OpenRouter key limit exceeded",
            }
        ),
    ]

    summary = benchmark_summary(
        statuses,
        job_status=JobStatus.COMPLETED,
        eval_artifact_status=EvalArtifactStatus.COMPLETE,
    )

    assert summary["total_tasks"] == 3
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["errors"] == 1
    assert summary["invalid"] == 0
    assert summary["valid_sample_count"] == 2
    assert summary["invalid_sample_count"] == 1
    assert summary["has_analysis_signal"] is True
    assert summary["all_samples_valid_for_analysis"] is False
    assert summary["valid_for_analysis"] is False
    assert summary["success_rate"] == 0.5
    assert summary["failure_class_counts"] == {
        "none": 1,
        "provider_auth": 1,
        "task_model": 1,
    }


def test_benchmark_summary_requires_successful_job_and_eval_artifact():
    statuses = [sample_benchmark_status({"answer": "PASS", "reward": 1.0})]

    summary = benchmark_summary(
        statuses,
        job_status=JobStatus.FAILED,
        eval_artifact_status=EvalArtifactStatus.COMPLETE,
    )

    assert summary["valid_sample_count"] == 1
    assert summary["has_analysis_signal"] is False
    assert summary["all_samples_valid_for_analysis"] is True
    assert summary["valid_for_analysis"] is False


def test_benchmark_summary_supports_partial_artifacts_with_analysis_signal():
    statuses = [
        sample_benchmark_status({"answer": "FAIL", "reward": 0.0}),
        sample_benchmark_status(
            {
                "answer": "ERROR",
                "reward": 0.0,
                "error": "DaytonaNotFoundError: sandbox missing",
            }
        ),
    ]

    summary = benchmark_summary(
        statuses,
        job_status=JobStatus.COMPLETED,
        eval_artifact_status=EvalArtifactStatus.PARTIAL,
    )

    assert summary["has_analysis_signal"] is True
    assert summary["all_samples_valid_for_analysis"] is False
    assert summary["valid_for_analysis"] is False
    assert summary["success_rate"] == 0.0


def test_build_benchmark_summary_returns_dataclass_with_metadata_serializer():
    summary = build_benchmark_summary(
        job_status=JobStatus.COMPLETED,
        eval_artifact_status=EvalArtifactStatus.PARTIAL,
        task_results=[
            (TaskOutcome.PASS, FailureClass.NONE),
            (TaskOutcome.FAIL, FailureClass.TASK_MODEL),
            (TaskOutcome.ERROR, FailureClass.INFRA_DAYTONA),
        ],
    )

    assert summary.success_rate == 0.5
    assert summary.has_analysis_signal is True
    assert summary.all_samples_valid_for_analysis is False
    assert summary.valid_for_analysis is False
    assert summary.failure_class_counts["infra_daytona"] == 1
    assert summary.to_metadata()["eval_artifact_status"] == "partial"
    assert summary.to_metadata()["success_rate"] == 0.5


def test_print_benchmark_summary_includes_scan_friendly_operator_counts(capsys):
    samples = [
        SimpleNamespace(
            metadata={
                "terminalbench_daytona": {
                    "benchmark_status": sample_benchmark_status(
                        {"answer": "PASS", "reward": 1.0}
                    )
                }
            }
        ),
        SimpleNamespace(
            metadata={
                "terminalbench_daytona": {
                    "benchmark_status": sample_benchmark_status(
                        {"answer": "FAIL", "reward": 0.0}
                    )
                }
            }
        ),
        SimpleNamespace(
            metadata={
                "terminalbench_daytona": {
                    "benchmark_status": sample_benchmark_status(
                        {
                            "answer": "ERROR",
                            "reward": 0.0,
                            "error": "DaytonaNotFoundError: sandbox container not found",
                        }
                    )
                }
            }
        ),
        SimpleNamespace(
            metadata={
                "terminalbench_daytona": {
                    "benchmark_status": sample_benchmark_status(
                        {"answer": "INVALID", "reward": 0.0}
                    )
                }
            }
        ),
    ]

    ok = print_benchmark_summary(
        log_prefix="terminalbench-batch",
        samples=samples,
        metadata_key="terminalbench_daytona",
        job_status=JobStatus.COMPLETED,
        eval_artifact_status=EvalArtifactStatus.COMPLETE,
    )

    assert ok is True
    output = capsys.readouterr().out
    assert "benchmark_summary=" in output
    assert "benchmark_summary_counts " in output
    assert "job_status=completed" in output
    assert "eval_artifact_status=complete" in output
    assert "valid_for_analysis=false" in output
    assert "valid_samples=2 invalid_samples=2" in output
    assert "task_outcomes PASS=1 FAIL=1 ERROR=1 INVALID=1" in output
    assert "failure_classes " in output
    assert "infra_daytona=1" in output
    assert "hardening_preflight=1" in output


