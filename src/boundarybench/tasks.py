from __future__ import annotations

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset

from boundarybench.task_runtime.scorers import (
    hardening_aware_harbor_scorer,
    hardening_preflight_scorer,
)
from boundarybench.task_runtime.smoke import (
    _smoke_samples,
    local_fake_runner,
    smoke_scorer,
)
from boundarybench.task_runtime.composition import (
    _copy_task,
    _mode_metadata,
    _tag_task,
)
from boundarybench.task_runtime.solvers import agentsh_solver
from boundarybench.terminalbench import (
    DEFAULT_TERMINAL_BENCH_2_1_REF,
    DEFAULT_TERMINAL_BENCH_TASK_ID,
    build_terminalbench_control_task,
)


@task
def hardened_agents(
    enforcement: str = "local_fake",
    max_samples: int | None = None,
    local_fake_delay_seconds: float = 0.0,
    dataset: str = "terminal-bench-2.1",
    task_id: str | None = DEFAULT_TERMINAL_BENCH_TASK_ID,
    harbor_ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    sandbox_env_name: str = "docker",
    overwrite_cache: bool = False,
    override_cpus: int | None = None,
    override_memory_mb: int | None = None,
    override_gpus: int | None = None,
    hardening_config: str | None = None,
    preflight_only: bool = False,
) -> Task:
    """Build the BoundaryBench hardened-agents Inspect task.

    `local_fake` keeps a local smoke path. `none` delegates an un-hardened
    Terminal-Bench task to Harbor. `agentsh` keeps the AgentSH preflight path.
    Current hardened live benchmark runs use `hardened_terminalbench_daytona`
    with `policy=low-nist` (the N×F×P roster preset; see
    `docs/policy-axes.md`).
    """
    requested_enforcement = enforcement

    if enforcement != "local_fake" and float(local_fake_delay_seconds) != 0.0:
        raise ValueError(
            "local_fake_delay_seconds is supported only with enforcement=local_fake"
        )

    if enforcement == "local_fake":
        samples = _smoke_samples()
        if max_samples is not None:
            samples = samples[: int(max_samples)]

        return Task(
            dataset=MemoryDataset(samples),
            solver=local_fake_runner(
                enforcement=enforcement,
                local_fake_delay_seconds=local_fake_delay_seconds,
            ),
            scorer=smoke_scorer(),
        )

    if enforcement == "none":
        if preflight_only:
            raise ValueError("preflight_only is supported only with agentsh")
        control_task = _build_terminalbench_task(
            dataset=dataset,
            task_id=task_id,
            max_samples=max_samples,
            harbor_ref=harbor_ref,
            sandbox_env_name=sandbox_env_name,
            overwrite_cache=overwrite_cache,
            override_cpus=override_cpus,
            override_memory_mb=override_memory_mb,
            override_gpus=override_gpus,
        )
        return _tag_task(
            control_task,
            enforcement=enforcement,
            dataset=dataset,
            task_id=task_id,
            hardening_config=hardening_config,
            preflight_only=preflight_only,
            requested_enforcement=requested_enforcement,
        )

    if enforcement == "agentsh":
        return _agentsh_task(
            dataset=dataset,
            task_id=task_id,
            max_samples=max_samples,
            harbor_ref=harbor_ref,
            sandbox_env_name=sandbox_env_name,
            overwrite_cache=overwrite_cache,
            override_cpus=override_cpus,
            override_memory_mb=override_memory_mb,
            override_gpus=override_gpus,
            hardening_config=hardening_config,
            preflight_only=preflight_only,
        )

    raise ValueError(
        "Unsupported enforcement. Expected one of: local_fake, none, agentsh."
    )


def _agentsh_task(
    *,
    dataset: str,
    task_id: str | None,
    max_samples: int | None,
    harbor_ref: str,
    sandbox_env_name: str,
    overwrite_cache: bool,
    override_cpus: int | None,
    override_memory_mb: int | None,
    override_gpus: int | None,
    hardening_config: str | None,
    preflight_only: bool,
) -> Task:
    harbor_task = _build_terminalbench_task(
        dataset=dataset,
        task_id=task_id,
        max_samples=max_samples,
        harbor_ref=harbor_ref,
        sandbox_env_name=sandbox_env_name,
        overwrite_cache=overwrite_cache,
        override_cpus=override_cpus,
        override_memory_mb=override_memory_mb,
        override_gpus=override_gpus,
    )
    config_id = hardening_config or "agentsh_sev1_fixture"
    scorer_for_mode = _scorer_for_hardened_mode(
        harbor_task.scorer,
        preflight_only=preflight_only,
    )
    return _copy_task(
        harbor_task,
        solver=agentsh_solver(
            upstream_solver=harbor_task.solver,
            hardening_config=config_id,
            task_id=task_id,
            preflight_only=preflight_only,
        ),
        scorer=scorer_for_mode,
        metadata=_mode_metadata(
            harbor_task.metadata,
            enforcement="agentsh",
            dataset=dataset,
            task_id=task_id,
            hardening_config=config_id,
            preflight_only=preflight_only,
            agentsh_policy_hardening={
                "requested": True,
                "backend": "agentsh",
                "preflight_only": preflight_only,
                "hardening_config": config_id,
            },
        ),
    )


def _build_terminalbench_task(
    *,
    dataset: str,
    task_id: str | None,
    max_samples: int | None,
    harbor_ref: str,
    sandbox_env_name: str,
    overwrite_cache: bool,
    override_cpus: int | None,
    override_memory_mb: int | None,
    override_gpus: int | None,
) -> Task:
    return build_terminalbench_control_task(
        dataset=dataset,
        task_id=task_id,
        max_samples=max_samples,
        ref=harbor_ref,
        sandbox_env_name=sandbox_env_name,
        overwrite_cache=overwrite_cache,
        override_cpus=override_cpus,
        override_memory_mb=override_memory_mb,
        override_gpus=override_gpus,
    )


def _scorer_for_hardened_mode(harbor_scorer, *, preflight_only: bool):
    if preflight_only:
        return hardening_preflight_scorer()
    return hardening_aware_harbor_scorer(harbor_scorer)
