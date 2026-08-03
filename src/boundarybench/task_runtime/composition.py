from __future__ import annotations

from typing import Any

from inspect_ai import Task
from inspect_ai.solver import Solver


def _tag_task(
    inspect_task: Task,
    *,
    enforcement: str,
    dataset: str,
    task_id: str | None,
    hardening_config: str | None,
    preflight_only: bool,
    requested_enforcement: str | None = None,
) -> Task:
    inspect_task.metadata = _mode_metadata(
        inspect_task.metadata,
        enforcement=enforcement,
        dataset=dataset,
        task_id=task_id,
        hardening_config=hardening_config,
        preflight_only=preflight_only,
        requested_enforcement=requested_enforcement,
    )
    return inspect_task


def _mode_metadata(
    existing: dict[str, Any] | None,
    *,
    enforcement: str,
    dataset: str,
    task_id: str | None,
    hardening_config: str | None,
    preflight_only: bool,
    requested_enforcement: str | None = None,
    agentsh_policy_hardening: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = dict(existing or {})
    if enforcement == "agentsh":
        metadata.update(
            {
                "enforcement": enforcement,
                "severity": "sev1",
                "control_mode": False,
                "hardened_execution": True,
                "hardening_config": hardening_config,
                "preflight_only": preflight_only,
            }
        )
    metadata["boundarybench"] = {
        "enforcement": enforcement,
        "requested_enforcement": requested_enforcement or enforcement,
        "dataset": dataset,
        "task_id": task_id,
        "hardening_config": hardening_config,
        "preflight_only": preflight_only,
    }
    if agentsh_policy_hardening is not None:
        metadata["boundarybench"]["agentsh_policy_hardening"] = (
            agentsh_policy_hardening
        )
    return metadata


def _copy_task(
    source: Task,
    *,
    solver: Solver,
    scorer: Any,
    metadata: dict[str, Any],
) -> Task:
    return Task(
        dataset=source.dataset,
        setup=source.setup,
        solver=solver,
        cleanup=source.cleanup,
        scorer=scorer,
        metrics=source.metrics,
        model=source.model,
        config=source.config,
        model_roles=source.model_roles,
        sandbox=source.sandbox,
        checkpoint=source.checkpoint,
        approval=source.approval,
        epochs=source.epochs,
        fail_on_error=source.fail_on_error,
        continue_on_fail=source.continue_on_fail,
        score_on_error=source.score_on_error,
        message_limit=source.message_limit,
        token_limit=source.token_limit,
        time_limit=source.time_limit,
        working_limit=source.working_limit,
        cost_limit=source.cost_limit,
        early_stopping=source.early_stopping,
        display_name=source.display_name,
        name=source.name,
        version=source.version,
        metadata=metadata,
        tags=source.tags,
        viewer=source.viewer,
    )
