"""Task-level result qualifiers: verifier provenance and policy applicability.

Two fixed, reviewable rosters qualify how a task's result must be read. They
are stamped into every sample's metadata and surfaced by `export-results` and
`analyze` so aggregate numbers can be computed with honest denominators.

1. **Adapted-verifier tasks** — tasks whose shipped Harbor verifier is
   under-specified for hardened runs (it inspects only the conventional
   root-owned location, so a legitimate non-root solution scores as failing).
   These carry an additive corrected verifier in ``adapted_verifiers/<task>/``,
   applied uniformly across every policy preset including control. The roster
   is derived from that directory so code and assets cannot drift.

2. **Policy-inapplicable tasks** — tasks whose own instruction mandates a
   resource or location the hardened policies deny (e.g. "install to
   /usr/local/bin", "install into the system-wide Python environment", or a
   dataset reachable only through a non-allowlisted host). No admissible
   trajectory exists without editing the task itself, so under any policy
   other than ``control`` these tasks are *not applicable* rather than
   ordinarily failed. Of the 89 terminal-bench-2.1 tasks, 7 are in this
   roster.

The module also freezes the full 89-task universe
(``ALL_TERMINAL_BENCH_2_1_TASK_IDS``) so ``--all-tasks`` can expand it without
touching the network; the dataset ref is pinned, and a contract test guards the
roster against the solvability-evidence CSV in ``data/task-evidence/``.
"""

from __future__ import annotations

from pathlib import Path

_ADAPTED_VERIFIERS_DIR = Path(__file__).resolve().parent / "adapted_verifiers"

CONTROL_EQUIVALENT_POLICIES = frozenset({"control", "n0-f0-p0", "none", ""})

APPLICABLE = "applicable"
NOT_APPLICABLE = "not_applicable"

VERIFIER_SOURCE_OFFICIAL = "official"
VERIFIER_SOURCE_ADAPTED = "adapted"

POLICY_INAPPLICABLE_TASKS: dict[str, str] = {
    "build-pmars": (
        "task instructs installing a binary to /usr/local/bin; "
        "root-owned tree is denied under every non-control policy"
    ),
    "build-pov-ray": (
        "task instructs installing a binary to /usr/local/bin; "
        "root-owned tree is denied under every non-control policy"
    ),
    "build-cython-ext": (
        "task instructs installing Python packages into the system-wide "
        "environment; denied under every non-control policy"
    ),
    "kv-store-grpc": (
        "task instructs installing Python packages into the system-wide "
        "environment; denied under every non-control policy"
    ),
    "nginx-request-logging": (
        "task requires configuration and logs under /etc and /var; "
        "root-owned trees are denied under every non-control policy"
    ),
    "mailman": (
        "task requires configuration and logs under /etc and /var; "
        "root-owned trees are denied under every non-control policy"
    ),
    "count-dataset-tokens": (
        "task requires a dataset reachable only through a non-allowlisted "
        "host; additionally excluded on benchmark-integrity grounds (the "
        "official verifier accepts the expected constant without the "
        "required computation)"
    ),
}


ALL_TERMINAL_BENCH_2_1_TASK_IDS: tuple[str, ...] = (
    "adaptive-rejection-sampler",
    "bn-fit-modify",
    "break-filter-js-from-html",
    "build-cython-ext",
    "build-pmars",
    "build-pov-ray",
    "caffe-cifar-10",
    "cancel-async-tasks",
    "chess-best-move",
    "circuit-fibsqrt",
    "cobol-modernization",
    "code-from-image",
    "compile-compcert",
    "configure-git-webserver",
    "constraints-scheduling",
    "count-dataset-tokens",
    "crack-7z-hash",
    "custom-memory-heap-crash",
    "db-wal-recovery",
    "distribution-search",
    "dna-assembly",
    "dna-insert",
    "extract-elf",
    "extract-moves-from-video",
    "feal-differential-cryptanalysis",
    "feal-linear-cryptanalysis",
    "filter-js-from-html",
    "financial-document-processor",
    "fix-code-vulnerability",
    "fix-git",
    "fix-ocaml-gc",
    "gcode-to-text",
    "git-leak-recovery",
    "git-multibranch",
    "gpt2-codegolf",
    "headless-terminal",
    "hf-model-inference",
    "install-windows-3.11",
    "kv-store-grpc",
    "large-scale-text-editing",
    "largest-eigenval",
    "llm-inference-batching-scheduler",
    "log-summary-date-ranges",
    "mailman",
    "make-doom-for-mips",
    "make-mips-interpreter",
    "mcmc-sampling-stan",
    "merge-diff-arc-agi-task",
    "model-extraction-relu-logits",
    "modernize-scientific-stack",
    "mteb-leaderboard",
    "mteb-retrieve",
    "multi-source-data-merger",
    "nginx-request-logging",
    "openssl-selfsigned-cert",
    "overfull-hbox",
    "password-recovery",
    "path-tracing",
    "path-tracing-reverse",
    "polyglot-c-py",
    "polyglot-rust-c",
    "portfolio-optimization",
    "protein-assembly",
    "prove-plus-comm",
    "pypi-server",
    "pytorch-model-cli",
    "pytorch-model-recovery",
    "qemu-alpine-ssh",
    "qemu-startup",
    "query-optimize",
    "raman-fitting",
    "regex-chess",
    "regex-log",
    "reshard-c4-data",
    "rstan-to-pystan",
    "sam-cell-seg",
    "sanitize-git-repo",
    "schemelike-metacircular-eval",
    "sparql-university",
    "sqlite-db-truncate",
    "sqlite-with-gcov",
    "torch-pipeline-parallelism",
    "torch-tensor-parallelism",
    "train-fasttext",
    "tune-mjcf",
    "video-processing",
    "vulnerable-secret",
    "winning-avg-corewars",
    "write-compressor",
)


def all_task_ids() -> tuple[str, ...]:
    """Every task id in the pinned terminal-bench-2.1 universe."""

    return ALL_TERMINAL_BENCH_2_1_TASK_IDS


def adapted_verifier_task_ids() -> tuple[str, ...]:
    """Task ids carrying an additive corrected verifier, from the asset dir."""

    if not _ADAPTED_VERIFIERS_DIR.is_dir():
        return ()
    return tuple(
        sorted(
            entry.name
            for entry in _ADAPTED_VERIFIERS_DIR.iterdir()
            if entry.is_dir() and not entry.name.startswith((".", "_"))
        )
    )


def verifier_source(task_id: str) -> str:
    return (
        VERIFIER_SOURCE_ADAPTED
        if task_id in adapted_verifier_task_ids()
        else VERIFIER_SOURCE_OFFICIAL
    )


def policy_applicability(task_id: str, policy: str) -> str:
    """Whether a task's result is meaningful under the given policy.

    ``not_applicable`` means the task's own instruction requires something the
    policy denies; such runs must not count as ordinary failures in aggregate
    results.
    """

    normalized = (policy or "").strip().lower()
    if normalized in CONTROL_EQUIVALENT_POLICIES:
        return APPLICABLE
    if task_id in POLICY_INAPPLICABLE_TASKS:
        return NOT_APPLICABLE
    return APPLICABLE


def policy_applicability_reason(task_id: str, policy: str) -> str:
    if policy_applicability(task_id, policy) == NOT_APPLICABLE:
        return POLICY_INAPPLICABLE_TASKS[task_id]
    return ""


def applicability_metadata(task_id: str, policy: str) -> dict[str, str]:
    """The per-sample metadata fields stamped by the eval tasks."""

    source = verifier_source(task_id)
    return {
        "verifier_source": source,
        "official_verifier_source": (
            "inspect-harbor harbor verifier (Daytona)"
            if source == VERIFIER_SOURCE_OFFICIAL
            else (
                "inspect-harbor harbor verifier (Daytona) with additive "
                "adapted-verifier correction (adapted_verifiers/"
                f"{task_id}/), applied uniformly across every policy preset"
            )
        ),
        "policy_applicability": policy_applicability(task_id, policy),
        "policy_applicability_reason": policy_applicability_reason(task_id, policy),
    }
