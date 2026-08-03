"""BoundaryBench command-line interface.

The headline command is `boundarybench run`: execute one or more Terminal-Bench
tasks in hardened Daytona sandboxes with a chosen agent harness and policy
preset, scored by Harbor's official verifier.

Users provide:
  - an OpenRouter API key (model inference for the agent harness)
  - a Daytona API key (sandbox execution)
  - one or more Terminal-Bench task ids
  - a benchmark policy: control | non-root | high-nist
  - a harness: claude-code | codex | terminus | grok
"""

from __future__ import annotations

import os
import sys


USAGE = """usage: boundarybench <command> ...

Commands:
  boundarybench run                  Run Terminal-Bench task(s) under a hardened
                                   policy in a Daytona sandbox
  boundarybench build-policy         Build your own hardening interactively, then
                                   run it
  boundarybench list                 List benchmark policies and harnesses
  boundarybench export-results       Export .eval logs to CSV
  boundarybench analyze              Analyze policy blockages in .eval logs
  boundarybench policy validate      Validate policy catalog packs
  boundarybench policy compile       Compile a policy variant
  boundarybench enforcement-probe    Probe one preset's native walls live
                                   (no task/agent/verifier)

Run `boundarybench <command> --help` for command-specific options.
"""

BENCHMARK_POLICIES = ("control", "non-root", "high-nist")

_POLICY_ALIASES = {
    "control": "control",
    "non-root": "non-root",
    "nonroot": "non-root",
    "non_root": "non-root",
    "high-nist": "high-nist",
    "high_nist": "high-nist",
}

_HARNESS_ALIASES = {
    "claude-code": "claude_code",
    "claude_code": "claude_code",
    "claude": "claude_code",
    "codex": "codex",
    "terminus": "terminus_2",
    "terminus-2": "terminus_2",
    "terminus_2": "terminus_2",
    "terminus2": "terminus_2",
    "grok": "grok",
}


def _harness_display_name(internal: str) -> str:
    """Return the spelling users type for an internal harness id.

    The first alias listed for each internal id in ``_HARNESS_ALIASES`` is the
    documented one, so a new harness stays aligned as long as its preferred
    spelling is listed first.
    """

    for alias, resolved in _HARNESS_ALIASES.items():
        if resolved == internal:
            return alias
    return internal


def _load_dotenv() -> None:
    """Load a ``.env`` from the working directory into the environment.

    Values already present in the environment (explicit ``export``s or
    ``--*-api-key`` flags) are never overridden, so precedence is
    flags > exported vars > .env. Missing file or missing python-dotenv is a
    no-op — nothing here is required for the CLI to run.
    """

    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:  # pragma: no cover - python-dotenv ships with inspect-ai
        return
    path = find_dotenv(usecwd=True)
    if path:
        load_dotenv(path, override=False)


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(USAGE.rstrip())
        return 0

    command = args.pop(0)
    if command == "run":
        return _run(args)
    if command == "build-policy":
        return _build_policy(args)
    if command == "list":
        return _list()
    if command == "export-results":
        from boundarybench.terminalbench import results_dataframe

        return results_dataframe.main(args)
    if command == "analyze":
        from boundarybench.analysis import cli as analysis_cli

        return analysis_cli.main(args)
    if command == "policy":
        return _policy(args)
    if command == "enforcement-probe":
        from boundarybench.terminalbench import enforcement_matrix

        return enforcement_matrix.main(args)
    return _error(f"unknown command: {command}")


def _run(args: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="boundarybench run",
        description=(
            "Run Terminal-Bench task(s) in hardened Daytona sandboxes and score "
            "them with Harbor's official verifier."
        ),
    )
    parser.add_argument(
        "--task",
        default=None,
        help="Terminal-Bench 2.1 task id, or comma-separated list of ids",
    )
    parser.add_argument(
        "--all-tasks",
        action="store_true",
        help="Run the full terminal-bench-2.1 universe (all 89 tasks)",
    )
    parser.add_argument(
        "--policy",
        default="control",
        help=(
            "Benchmark policy tier: "
            + " | ".join(BENCHMARK_POLICIES)
            + " (default: control)"
        ),
    )
    parser.add_argument(
        "--harness",
        default="terminus",
        help="Agent harness: claude-code | codex | terminus | grok (default: terminus)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="OpenRouter model id the harness uses (default: repo default model)",
    )
    parser.add_argument(
        "--effort",
        default=None,
        help="Harness reasoning-effort level (harness-specific; default: harness default)",
    )
    parser.add_argument(
        "--openrouter-api-key",
        default=None,
        help="OpenRouter API key (default: OPENROUTER_API_KEY env var)",
    )
    parser.add_argument(
        "--daytona-api-key",
        default=None,
        help="Daytona API key (default: DAYTONA_API_KEY env var)",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="Inspect .eval log directory (default: logs/boundarybench-<timestamp>)",
    )
    parser.add_argument(
        "--block-message",
        default=None,
        help="Override the policy-denial message shown to the agent",
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="Terminal-Bench dataset ref (default: pinned terminal-bench-2.1 ref)",
    )
    parser.add_argument(
        "--display",
        default="rich",
        help="Inspect display mode: rich | plain | none (default: rich)",
    )
    parser.add_argument(
        "--allow-any-policy",
        action="store_true",
        help=(
            "Accept any N x F x P preset name understood by the underlying task, "
            "not just the published benchmark tiers"
        ),
    )
    parser.add_argument(
        "--harden",
        default=None,
        help=(
            "Build a custom policy from a comma-separated list of hardening "
            "options instead of --policy (see `boundarybench build-policy` and "
            "`boundarybench list`). Example: non-root,readonly-os,restrict-egress"
        ),
    )
    parser.add_argument(
        "--egress-mode",
        default=None,
        help=(
            "With restrict-egress: trusted (curated allowlist) | task-only | "
            "custom (bring your own; see --egress-allow). Default: trusted"
        ),
    )
    parser.add_argument(
        "--egress-allow",
        default=None,
        help="Comma-separated domain allowlist when --egress-mode custom",
    )
    parser.add_argument(
        "--exclude-not-applicable",
        action="store_true",
        help=(
            "Drop tasks whose own instruction conflicts with the selected "
            "policy from the selection instead of running or refusing them"
        ),
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help=(
            "Assume yes for confirmation prompts, e.g. running tasks that "
            "are not applicable under the selected policy"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Resolve the run (policy, harness, task selection) and exit "
            "before provisioning sandboxes or calling models"
        ),
    )
    opts = parser.parse_args(args)

    if opts.all_tasks and opts.task:
        return _error("use either --task or --all-tasks, not both", prefix="run")
    run_all = opts.all_tasks or not opts.task

    if opts.openrouter_api_key:
        os.environ["OPENROUTER_API_KEY"] = opts.openrouter_api_key
    if opts.daytona_api_key:
        os.environ["DAYTONA_API_KEY"] = opts.daytona_api_key

    missing = [
        name
        for name in ("OPENROUTER_API_KEY", "DAYTONA_API_KEY")
        if not os.environ.get(name)
    ]
    if missing and not opts.dry_run:
        return _error(
            "missing credentials: "
            + ", ".join(missing)
            + " (set the env var(s) or pass --openrouter-api-key / --daytona-api-key)",
            prefix="run",
        )

    task_kwargs: dict[str, object] = {}
    if opts.harden is not None:
        if opts.policy != "control":
            return _error(
                "use either --policy or --harden, not both",
                prefix="run",
            )
        from boundarybench.terminalbench.custom_policy import (
            CustomPolicyError,
            compile_custom_policy,
        )

        try:
            compiled = compile_custom_policy(
                opts.harden,
                egress_mode=opts.egress_mode,
                egress_domains=opts.egress_allow,
            )
        except CustomPolicyError as exc:
            return _error(str(exc), prefix="run")
        effective_policy = compiled.policy_id
        task_kwargs["harden"] = opts.harden
        if opts.egress_mode is not None:
            task_kwargs["egress_mode"] = opts.egress_mode
        if opts.egress_allow is not None:
            task_kwargs["egress_allow"] = opts.egress_allow
    else:
        policy_input = opts.policy.strip().lower()
        if opts.allow_any_policy:
            effective_policy = policy_input
        else:
            resolved = _POLICY_ALIASES.get(policy_input)
            if resolved is None:
                return _error(
                    f"unknown policy {opts.policy!r}; choose one of: "
                    + ", ".join(BENCHMARK_POLICIES)
                    + " (or pass --allow-any-policy for research presets, or "
                    "--harden to build your own)",
                    prefix="run",
                )
            effective_policy = resolved
        task_kwargs["policy"] = effective_policy

    harness = _HARNESS_ALIASES.get(opts.harness.strip().lower())
    if harness is None:
        return _error(
            f"unknown harness {opts.harness!r}; choose one of: "
            "claude-code, codex, terminus, grok",
            prefix="run",
        )

    task_kwargs.update(
        {
            "harness": harness,
            "exclude_not_applicable": opts.exclude_not_applicable,
        }
    )
    if run_all:
        task_kwargs["all_tasks"] = True
    else:
        task_kwargs["task_ids"] = opts.task
    if opts.model is not None:
        task_kwargs["model"] = opts.model
    if opts.effort is not None:
        task_kwargs["effort"] = opts.effort
    if opts.block_message is not None:
        task_kwargs["block_message"] = opts.block_message
    if opts.ref is not None:
        task_kwargs["ref"] = opts.ref

    if run_all:
        from boundarybench.terminalbench import task_applicability

        selected_tasks = list(task_applicability.all_task_ids())
    else:
        selected_tasks = [tid.strip() for tid in opts.task.split(",") if tid.strip()]

    if run_all and not opts.all_tasks and not opts.yes and not opts.dry_run:
        if not _stdin_is_tty():
            return _error(
                "no task selection given; pass --task or --all-tasks (or "
                "--yes to run the full benchmark non-interactively)",
                prefix="run",
            )
        print(
            "boundarybench run: no --task given; this runs the full "
            f"benchmark: {len(selected_tasks)} task(s) under policy "
            f"{effective_policy} with harness {opts.harness}"
        )
        if not _prompt_yes_no("Continue?", default=True):
            print("boundarybench run: aborted", file=sys.stderr)
            return 1

    return _launch_eval(
        selected_tasks=selected_tasks,
        effective_policy=effective_policy,
        task_kwargs=task_kwargs,
        exclude_not_applicable=opts.exclude_not_applicable,
        all_tasks=run_all,
        assume_yes=opts.yes,
        dry_run=opts.dry_run,
        log_dir=opts.log_dir,
        display=opts.display,
    )


def _launch_eval(
    *,
    selected_tasks: list[str],
    effective_policy: str,
    task_kwargs: dict[str, object],
    exclude_not_applicable: bool = False,
    all_tasks: bool = False,
    assume_yes: bool = False,
    dry_run: bool = False,
    log_dir: str | None,
    display: str,
) -> int:
    """Shared applicability pre-check + eval launch for `run` and `build-policy`."""

    from boundarybench.terminalbench import task_applicability

    conflicted = [
        tid
        for tid in selected_tasks
        if task_applicability.policy_applicability(tid, effective_policy)
        == task_applicability.NOT_APPLICABLE
    ]
    if exclude_not_applicable and conflicted:
        selected_tasks = [tid for tid in selected_tasks if tid not in set(conflicted)]
        print(
            "boundarybench run: excluding not-applicable task(s) under this "
            "hardening: " + ", ".join(conflicted)
        )
        if not selected_tasks:
            return _error(
                "no tasks left after --exclude-not-applicable",
                prefix="run",
            )
    elif conflicted and not all_tasks:
        reasons = "\n".join(
            f"  {tid}: "
            f"{task_applicability.policy_applicability_reason(tid, effective_policy)}"
            for tid in conflicted
        )
        print(
            "boundarybench run: warning: task(s) not applicable under this "
            f"hardening:\n{reasons}\n"
            "These tasks conflict with the hardening by their own instruction "
            "and cannot pass; results are stamped not_applicable and excluded "
            "from success rates."
        )
        if not assume_yes:
            if not _stdin_is_tty():
                return _error(
                    "refusing to run not-applicable task(s) without "
                    "confirmation; pass --yes to run them anyway, or "
                    "--exclude-not-applicable to drop them",
                    prefix="run",
                )
            if not _prompt_yes_no("Run them anyway?", default=False):
                print("boundarybench run: aborted", file=sys.stderr)
                return 1
        task_kwargs["include_not_applicable"] = True
    print(
        f"boundarybench run: {len(selected_tasks)} task(s) selected under "
        f"policy {effective_policy}"
    )
    adapted = [
        tid
        for tid in selected_tasks
        if task_applicability.verifier_source(tid)
        == task_applicability.VERIFIER_SOURCE_ADAPTED
    ]
    if adapted:
        print(
            "boundarybench run: note: scored by an additive adapted verifier "
            "(applied uniformly across every policy): " + ", ".join(adapted)
        )

    from datetime import datetime, timezone

    # Path assembly only; the directory is created by the evaluator below, so a
    # dry run can report the destination without touching the filesystem.
    resolved_log_dir = log_dir or os.path.join(
        "logs",
        "boundarybench-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
    )

    if dry_run:
        harness = str(task_kwargs.get("harness") or "")
        print("boundarybench run: tasks: " + ", ".join(selected_tasks))
        print(
            "boundarybench run: harness: "
            + (_harness_display_name(harness) if harness else "<unset>")
        )
        print(
            "boundarybench run: model: "
            + str(task_kwargs.get("model") or "repo default")
        )
        print("boundarybench run: log dir: " + resolved_log_dir)
        print(
            "boundarybench run: dry run: no sandboxes provisioned, no model "
            "calls made"
        )
        return 0

    from inspect_ai import eval as inspect_eval

    from boundarybench.terminalbench.daytona_eval import hardened_terminalbench_daytona

    logs = inspect_eval(
        hardened_terminalbench_daytona(**task_kwargs),
        model="mockllm/model",
        log_dir=resolved_log_dir,
        display=display,
    )

    failed = [log for log in logs if log.status != "success"]
    print(f"\nboundarybench: eval logs written to {resolved_log_dir}")
    if failed:
        for log in failed:
            print(f"boundarybench: eval ended with status={log.status}", file=sys.stderr)
        return 1
    return 0


def _stdin_is_tty() -> bool:
    return sys.stdin.isatty()


def _prompt_yes_no(question: str, *, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in {"y", "yes"}


def _build_policy(args: list[str]) -> int:
    """Interactive picker: choose hardening in plain language, then run it."""

    import argparse

    parser = argparse.ArgumentParser(
        prog="boundarybench build-policy",
        description=(
            "Build your own hardening by answering a few questions, then run "
            "it on a task."
        ),
    )
    parser.add_argument("--task", default=None, help="Skip the task prompt")
    parser.add_argument("--harness", default=None, help="Skip the harness prompt")
    opts = parser.parse_args(args)

    from boundarybench.terminalbench.custom_policy import (
        EGRESS_CUSTOM,
        EGRESS_TASK_ONLY,
        EGRESS_TRUSTED,
        SURFACES,
        compile_custom_policy,
    )

    print("Build your own hardening — answer y/n for each option.\n")
    chosen: list[str] = []
    for surface in SURFACES:
        if _prompt_yes_no(f"  {surface.label}?"):
            chosen.append(surface.key)

    if not chosen:
        print("\nNo hardening selected — that's the 'control' baseline.")

    egress_mode: str | None = None
    egress_domains: str | None = None
    if "restrict-egress" in chosen:
        print("\n  Network allowlist:")
        print("    1) Curated developer allowlist (default)")
        print("    2) Only what the task needs")
        print("    3) Bring your own list of domains")
        try:
            choice = input("  Choose 1/2/3 [1]: ").strip()
        except EOFError:
            choice = ""
        if choice == "2":
            egress_mode = EGRESS_TASK_ONLY
        elif choice == "3":
            egress_mode = EGRESS_CUSTOM
            try:
                egress_domains = input(
                    "  Domains (comma-separated, e.g. pypi.org,files.pythonhosted.org): "
                ).strip()
            except EOFError:
                egress_domains = ""
        else:
            egress_mode = EGRESS_TRUSTED

    from boundarybench.terminalbench.custom_policy import CustomPolicyError

    try:
        compiled = compile_custom_policy(
            ",".join(chosen), egress_mode=egress_mode, egress_domains=egress_domains
        )
    except CustomPolicyError as exc:
        return _error(str(exc), prefix="build-policy")

    _print_policy_summary(compiled)

    command = _harden_command(compiled, task=opts.task, harness=opts.harness)
    print("\nReproducible command:\n")
    print("  " + command + "\n")

    if not _prompt_yes_no("Run it now?", default=False):
        print("Not running. Copy the command above to run later.")
        return 0

    task = opts.task
    if not task:
        try:
            task = input("Task id(s), comma-separated: ").strip()
        except EOFError:
            task = ""
    if not task:
        return _error("no task id given", prefix="build-policy")

    harness = opts.harness
    if not harness:
        try:
            harness = input("Harness [terminus]: ").strip() or "terminus"
        except EOFError:
            harness = "claude-code"

    missing = [
        name
        for name in ("OPENROUTER_API_KEY", "DAYTONA_API_KEY")
        if not os.environ.get(name)
    ]
    if missing:
        return _error(
            "missing credentials: " + ", ".join(missing) + " (set the env var(s))",
            prefix="build-policy",
        )

    resolved_harness = _HARNESS_ALIASES.get(harness.strip().lower())
    if resolved_harness is None:
        return _error(
            f"unknown harness {harness!r}; choose one of: "
            "claude-code, codex, terminus, grok",
            prefix="build-policy",
        )

    task_kwargs: dict[str, object] = {
        "task_ids": task,
        "harness": resolved_harness,
        "harden": ",".join(compiled.surfaces),
    }
    if compiled.egress_mode is not None:
        task_kwargs["egress_mode"] = compiled.egress_mode
    if egress_domains:
        task_kwargs["egress_allow"] = egress_domains

    selected_tasks = [tid.strip() for tid in task.split(",") if tid.strip()]
    return _launch_eval(
        selected_tasks=selected_tasks,
        effective_policy=compiled.policy_id,
        task_kwargs=task_kwargs,
        log_dir=None,
        display="rich",
    )


def _print_policy_summary(compiled: object) -> None:
    from boundarybench.terminalbench.custom_policy import SURFACES_BY_KEY

    if not getattr(compiled, "surfaces", ()):
        print("\nThis is the control baseline — no hardening applied.")
        return
    if compiled.added_for_coherence:  # type: ignore[attr-defined]
        added = ", ".join(
            SURFACES_BY_KEY[k].label for k in compiled.added_for_coherence  # type: ignore[attr-defined]
        )
        print(f"\n(Also enabled, required by your choices: {added}.)")
    print("\nThis hardening will:")
    for key in compiled.surfaces:  # type: ignore[attr-defined]
        print(f"  • {SURFACES_BY_KEY[key].blocks}")
    if compiled.egress_mode == "custom":  # type: ignore[attr-defined]
        extras = [
            d
            for d in compiled.egress_allowlist  # type: ignore[attr-defined]
            if d not in ("api.openrouter.ai", "openrouter.ai", "*.openrouter.ai")
        ]
        print(
            "  • network allowlist: your "
            f"{len(extras)} domain(s) plus the model endpoint"
        )


def _harden_command(compiled: object, *, task: str | None, harness: str | None) -> str:
    parts = ["boundarybench run"]
    surfaces = getattr(compiled, "surfaces", ())
    if surfaces:
        parts.append("--harden " + ",".join(surfaces))
    if compiled.egress_mode and compiled.egress_mode != "trusted":  # type: ignore[attr-defined]
        parts.append("--egress-mode " + compiled.egress_mode)  # type: ignore[attr-defined]
    if compiled.egress_mode == "custom":  # type: ignore[attr-defined]
        extras = [
            d
            for d in compiled.egress_allowlist  # type: ignore[attr-defined]
            if d not in ("api.openrouter.ai", "openrouter.ai", "*.openrouter.ai")
        ]
        if extras:
            parts.append("--egress-allow " + ",".join(extras))
    parts.append("--task " + (task or "<task-id>"))
    parts.append("--harness " + (harness or "claude-code"))
    return " ".join(parts)


def _list() -> int:
    from boundarybench.harness.registry import DEFAULT_HARNESS, available_harnesses
    from boundarybench.terminalbench import task_applicability
    from boundarybench.terminalbench.custom_policy import SURFACES
    from boundarybench.terminalbench.policies import POLICIES

    print("Benchmark policies (published tiers):")
    for name in BENCHMARK_POLICIES:
        print(f"  {name}")
    print("\nAll resolvable presets (research; use `run --allow-any-policy`):")
    for name in sorted(POLICIES):
        print(f"  {name}")
    print(
        "\nBuild-your-own hardening options "
        "(`build-policy`, or `run --harden a,b,c`):"
    )
    for surface in SURFACES:
        print(f"  {surface.key:<16} {surface.label}")
    print("\nHarnesses:")
    default_harness = _harness_display_name(DEFAULT_HARNESS)
    for name in available_harnesses():
        display = _harness_display_name(name)
        print(f"  {display}" + ("  (default)" if display == default_harness else ""))
    print(
        "\nAdapted-verifier tasks (additive corrected verifier, "
        "applied under every policy):"
    )
    for name in task_applicability.adapted_verifier_task_ids():
        print(f"  {name}")
    print(
        "\nPolicy-inapplicable tasks (control only; under hardened policies "
        "`run` asks for confirmation, or drops them with "
        "--exclude-not-applicable):"
    )
    for name in sorted(task_applicability.POLICY_INAPPLICABLE_TASKS):
        print(f"  {name}")
    return 0


def _policy(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print(
            "usage: boundarybench policy <command> ...\n\n"
            "Commands:\n"
            "  validate    Validate canonical policy catalog packs\n"
            "  compile     Compile a policy variant to the target contract payload",
        )
        return 0

    subcommand = args.pop(0)
    if subcommand == "validate":
        from boundarybench.policy_catalog.cli import validate_main

        validate_main(args)
        return 0
    if subcommand == "compile":
        from boundarybench.policy_catalog.cli import compile_main

        compile_main(args)
        return 0
    return _error(f"unknown policy command: {subcommand}", prefix="policy")


def _error(message: str, *, prefix: str | None = None) -> int:
    command = f" {prefix}" if prefix else ""
    print(f"boundarybench{command}: error: {message}", file=sys.stderr)
    print("Run `boundarybench --help` for usage.", file=sys.stderr)
    return 2


def _exit() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    _exit()
