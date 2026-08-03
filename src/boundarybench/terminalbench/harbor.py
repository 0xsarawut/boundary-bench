from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from inspect_ai import Task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import Score, Scorer, Target, scorer
from inspect_ai.solver import TaskState

DEFAULT_TERMINAL_BENCH_2_1_REF = (
    "sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
)
DEFAULT_TERMINAL_BENCH_TASK_ID = "log-summary-date-ranges"
TERMINAL_BENCH_2_1_DATASET = "terminal-bench-2.1"
TERMINAL_BENCH_2_1_PACKAGE = "terminal-bench/terminal-bench-2-1"


@dataclass(frozen=True)
class TerminalBenchControlConfig:
    """Configuration for un-hardened Terminal-Bench control runs."""

    dataset: str
    task_id: str | None
    max_samples: int | None
    ref: str
    sandbox_env_name: str
    overwrite_cache: bool
    override_cpus: int | None
    override_memory_mb: int | None
    override_gpus: int | None


def build_terminalbench_control_task(
    *,
    dataset: str = TERMINAL_BENCH_2_1_DATASET,
    task_id: str | None = DEFAULT_TERMINAL_BENCH_TASK_ID,
    max_samples: int | None = 1,
    ref: str = DEFAULT_TERMINAL_BENCH_2_1_REF,
    sandbox_env_name: str = "docker",
    overwrite_cache: bool = False,
    override_cpus: int | None = None,
    override_memory_mb: int | None = None,
    override_gpus: int | None = None,
) -> Task:
    """Build the Terminal-Bench control task through inspect-harbor.

    `boundarybench` intentionally delegates task setup, sandbox
    construction, verifier execution, and reward parsing to `inspect-harbor`.
    This wrapper only selects the Terminal-Bench slice and annotates the
    resulting Inspect log with BoundaryBench control metadata.
    """

    normalized_dataset = _normalize_dataset(dataset)
    if normalized_dataset != TERMINAL_BENCH_2_1_DATASET:
        raise ValueError(
            "enforcement=none supports only dataset=terminal-bench-2.1"
        )

    config = TerminalBenchControlConfig(
        dataset=normalized_dataset,
        task_id=task_id,
        max_samples=max_samples,
        ref=ref,
        sandbox_env_name=sandbox_env_name,
        overwrite_cache=overwrite_cache,
        override_cpus=override_cpus,
        override_memory_mb=override_memory_mb,
        override_gpus=override_gpus,
    )

    harbor_task = _build_terminal_bench_2_1_task(config)
    _annotate_task(harbor_task, config)
    harbor_task.scorer = [
        terminalbench_control_scorer(
            _single_upstream_scorer(harbor_task.scorer), config
        )
    ]
    return harbor_task


def _build_terminal_bench_2_1_task(config: TerminalBenchControlConfig) -> Task:
    """Build a Terminal-Bench 2.1 task through inspect-harbor's public task API."""

    try:
        from inspect_harbor import terminal_bench_2_1
    except ImportError as exc:  # pragma: no cover - exercised by packaging
        raise RuntimeError(
            "enforcement=none Terminal-Bench runs require the inspect-harbor package. "
            "Install with `uv sync --all-extras` or `uv sync --extra dev`."
        ) from exc

    task = _call_terminal_bench_2_1(terminal_bench_2_1, config)
    task.dataset = MemoryDataset(_select_samples(task.dataset or [], config))
    return task


def _call_terminal_bench_2_1(terminal_bench_2_1: Any, config: TerminalBenchControlConfig) -> Task:
    dataset_task_names = (
        [_qualify_terminal_bench_task_name(config.task_id)]
        if config.task_id is not None
        else None
    )
    if dataset_task_names is not None:
        return _build_terminal_bench_2_1_package_slice(config, dataset_task_names)

    kwargs = {
        "ref": config.ref,
        "dataset_task_names": dataset_task_names,
        "n_tasks": config.max_samples if config.task_id is None else None,
        "overwrite_cache": config.overwrite_cache,
        "sandbox_env_name": config.sandbox_env_name,
        "override_cpus": config.override_cpus,
        "override_memory_mb": config.override_memory_mb,
        "override_gpus": config.override_gpus,
    }
    return terminal_bench_2_1(**kwargs)


def _build_terminal_bench_2_1_package_slice(
    config: TerminalBenchControlConfig,
    dataset_task_names: list[str],
) -> Task:
    """Build one Terminal-Bench package slice without downloading the full package.

    The public ``terminal_bench_2_1`` wrapper and public ``harbor`` export
    currently route through Harbor's mixed-source validation before package
    filtering, so ``dataset_task_names`` is rejected when combined with
    package arguments even though the package loader supports it. Calling the
    package slice loader directly keeps Harbor's sample conversion and scorer
    semantics while avoiding a brittle whole-package fallback in Cloud Run.
    """

    from inspect_harbor._harbor.task import (  # type: ignore[import-untyped]
        CompactionEdit,
        _build_harbor_tasks,
        _disambiguate_sample_ids,
        _load_from_package,
        bash,
        harbor_scorer,
        harbor_task_to_sample,
        python,
        react,
        update_plan,
    )

    task_paths = _load_from_package(
        TERMINAL_BENCH_2_1_PACKAGE,
        config.ref,
        dataset_task_names,
        None,
        config.max_samples,
        config.overwrite_cache,
    )
    harbor_task_objects = _build_harbor_tasks(task_paths)
    sample_ids = _disambiguate_sample_ids(harbor_task_objects)
    samples = [
        harbor_task_to_sample(
            harbor_task,
            sandbox_env_name=config.sandbox_env_name,
            override_cpus=config.override_cpus,
            override_memory_mb=config.override_memory_mb,
            override_gpus=config.override_gpus,
            sample_id=sample_id,
        )
        for harbor_task, sample_id in zip(harbor_task_objects, sample_ids, strict=True)
    ]

    return Task(
        dataset=samples,
        solver=react(
            tools=[bash(timeout=300), python(timeout=300), update_plan()],
            compaction=CompactionEdit(),
        ),
        scorer=harbor_scorer(),
    )


def _annotate_task(task: Task, config: TerminalBenchControlConfig) -> None:
    """Add control-run metadata while preserving Harbor sample fields."""

    control_metadata = {
        "enforcement": "none",
        "severity": "sev0",
        "control_mode": True,
        "hardened_execution": False,
        "dataset": config.dataset,
        "dataset_version": config.dataset,
        "harbor_package_name": TERMINAL_BENCH_2_1_PACKAGE,
        "harbor_package_ref": config.ref,
        "terminal_bench_task_id": config.task_id,
        "official_verifier_source": "inspect-harbor harbor_scorer",
        "custom_verifier": False,
    }

    task.metadata = {**(task.metadata or {}), **control_metadata}

    for sample in task.dataset or []:
        sample.metadata = sample.metadata or {}
        harbor_task_name = sample.metadata.get("task_name") or sample.id
        sample_task_id = _unqualify_terminal_bench_task_name(str(harbor_task_name))
        sample.metadata.update(
            {
                **control_metadata,
                "terminal_bench_task_id": sample_task_id,
                "harbor_task_name": harbor_task_name,
                "real_terminal_bench_task": True,
            }
        )


@scorer(metrics=[])
def terminalbench_control_scorer(
    upstream_scorer: Scorer, config: TerminalBenchControlConfig
):
    """Wrap inspect-harbor's scorer with control-run metadata preservation."""

    async def score(state: TaskState, target: Target) -> Score:
        upstream_score = await upstream_scorer(state, target)
        verifier_output = _parse_verifier_output(upstream_score.explanation)
        reward = upstream_score.value
        metadata = {
            **(upstream_score.metadata or {}),
            "enforcement": "none",
            "severity": "sev0",
            "control_mode": True,
            "hardened_execution": False,
            "dataset": config.dataset,
            "dataset_version": config.dataset,
            "harbor_package_name": TERMINAL_BENCH_2_1_PACKAGE,
            "harbor_package_ref": config.ref,
            "terminal_bench_task_id": (state.metadata or {}).get(
                "terminal_bench_task_id"
            )
            or state.sample_id,
            "official_verifier_source": "inspect-harbor harbor_scorer",
            "official_verifier_result": {
                "answer": upstream_score.answer,
                "reward": reward,
                "passed": upstream_score.answer == "PASS",
            },
            "official_verifier_output": verifier_output,
            "custom_verifier": False,
            "fake_result_json_scoring": False,
        }
        return Score(
            value=reward,
            answer=upstream_score.answer,
            explanation=upstream_score.explanation,
            metadata=metadata,
        )

    return score


def _parse_verifier_output(explanation: str | None) -> dict[str, Any]:
    """Extract Harbor scorer verifier output from its explanation string."""

    text = explanation or ""
    exit_code: int | None = None
    stdout = ""
    stderr = ""

    if text.startswith("Test exit code:"):
        first_line, _, rest = text.partition("\n")
        raw_exit_code = first_line.removeprefix("Test exit code:").strip()
        try:
            exit_code = int(raw_exit_code)
        except ValueError:
            exit_code = None
        stdout_marker = "\nstdout:\n"
        stderr_marker = "\n\nstderr:\n"
        if stdout_marker in rest:
            _, _, after_stdout = rest.partition(stdout_marker)
            stdout, _, stderr = after_stdout.partition(stderr_marker)

    return {
        "status": "ran",
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "raw": text,
    }


def _normalize_dataset(dataset: str) -> str:
    normalized = dataset.strip().lower().replace("_", "-")
    aliases = {
        "terminal-bench-2.1": TERMINAL_BENCH_2_1_DATASET,
        "terminal-bench-2-1": TERMINAL_BENCH_2_1_DATASET,
        "terminal-bench/terminal-bench-2-1": TERMINAL_BENCH_2_1_DATASET,
    }
    return aliases.get(normalized, normalized)


def _select_samples(samples: Any, config: TerminalBenchControlConfig) -> list[Sample]:
    selected = list(samples)
    if config.task_id is not None:
        qualified_task_id = _qualify_terminal_bench_task_name(config.task_id)
        selected = [
            sample
            for sample in selected
            if sample.id == qualified_task_id
            or (sample.metadata or {}).get("task_name") == qualified_task_id
        ]
        if not selected:
            raise ValueError(
                "Terminal-Bench task_id not found in terminal-bench-2.1: "
                f"{config.task_id}"
            )

    if config.max_samples is not None:
        selected = selected[: int(config.max_samples)]
    return selected


def _single_upstream_scorer(scorer_or_scorers: Any) -> Scorer:
    scorers = (
        scorer_or_scorers
        if isinstance(scorer_or_scorers, list)
        else [scorer_or_scorers]
    )
    if len(scorers) != 1:
        raise ValueError(
            "enforcement=none Terminal-Bench runs expect exactly one upstream "
            "Harbor scorer"
        )
    return scorers[0]


def _qualify_terminal_bench_task_name(task_id: str) -> str:
    return task_id if "/" in task_id else f"terminal-bench/{task_id}"


def _unqualify_terminal_bench_task_name(task_name: str) -> str:
    return (
        task_name.split("/", 1)[1]
        if task_name.startswith("terminal-bench/")
        else task_name
    )
