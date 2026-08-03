"""Probe-only native-enforcement matrix check for one hardening preset.

This is the LIGHT E2E path. For a single preset it provisions one fresh Daytona
sandbox, installs that preset's Linux-native hardening, runs the runtime policy
probe suite, and asserts that the EXACT set of native enforcement walls expected
for the preset was actually proven live -- without running any Terminal-Bench
task, agent, or verifier. A representative task is loaded only to source the
sandbox image + resources; the task itself is never executed.

The value over the in-eval probe gate (``ensure_runtime_policy_probe_suite_passed``)
is the STRICT wall-set contract in ``EXPECTED_NATIVE_WALLS``. The suite gate only
fails when a *generated* required probe fails, so a wall whose probe was never
generated -- or that silently degraded to ``not_applicable`` -- sails past the
gate unnoticed. The wall-set check catches exactly that: it asserts the native
surfaces proven equal the exact expected set, in both directions (a missing wall
AND an unexpected extra wall both fail).

The contract table is deliberately an INDEPENDENT hand-maintained mapping so a
dropped wall is caught; ``tests/test_enforcement_matrix.py`` separately asserts
the table matches what ``select_runtime_policy_probes`` actually emits, so the
two can never silently drift.
"""

from __future__ import annotations

import argparse
import sys

from boundarybench.daytona.runtime_policy_probes import (
    RUNTIME_POLICY_PROBE_WORKSPACE,
    DaytonaRuntimeProbeSuiteError,
    RuntimePolicyProbeReport,
    ensure_runtime_policy_probe_suite_passed,
    run_runtime_policy_probe_suite_in_sandbox,
)
from boundarybench.terminalbench.policies import resolve_policy


DEFAULT_ENFORCEMENT_PROBE_TASK = "log-summary-date-ranges"

NATIVE_ENFORCEMENT_SOURCE_PREFIX = "native_"


class EnforcementMatrixError(RuntimeError):
    """A preset's live native enforcement did not match its expected wall-set."""


EXPECTED_NATIVE_WALLS: dict[str, frozenset[str]] = {
    "control": frozenset(),
    "non-root": frozenset({"root_password_lock"}),
    "low-nist": frozenset(
        {
            "native_egress_reject",
            "read_only_root_filesystem",
            "root_password_lock",
        }
    ),
    "moderate-nist": frozenset(
        {
            "native_egress_reject",
            "read_only_root_filesystem",
            "root_password_lock",
        }
    ),
    "high-nist": frozenset(
        {
            "native_egress_reject",
            "read_only_root_filesystem",
            "read_only_home",
            "root_password_lock",
            "setuid_bit_strip",
            "capability_bounding_drop",
        }
    ),
    "netlock": frozenset(
        {
            "native_egress_reject",
            "root_password_lock",
        }
    ),
    "fslock": frozenset(
        {
            "read_only_root_filesystem",
            "read_only_home",
            "root_password_lock",
        }
    ),
}


def expected_native_walls(policy_name: str) -> frozenset[str]:
    """Return the exact native wall-set contract for ``policy_name``."""

    try:
        return EXPECTED_NATIVE_WALLS[policy_name]
    except KeyError:
        known = ", ".join(sorted(EXPECTED_NATIVE_WALLS))
        raise EnforcementMatrixError(
            f"no native wall-set contract for policy {policy_name!r}; "
            f"known presets: {known}"
        ) from None


def native_walls_proven(report: RuntimePolicyProbeReport) -> set[str]:
    """Native enforcement surfaces this report actively PROVED.

    A surface counts as proven when at least one probe attributed to a native
    enforcement source (``enforcement_source`` starting with ``native_``) passed.
    """

    return {
        result.surface
        for result in report.results
        if result.enforcement_source.startswith(NATIVE_ENFORCEMENT_SOURCE_PREFIX)
        and result.status == "pass"
    }


def assert_enforcement_matrix(
    policy_name: str, report: RuntimePolicyProbeReport
) -> None:
    """Assert every native wall of ``policy_name`` was enforced live.

    Raises ``DaytonaRuntimeProbeSuiteError`` if any required probe failed, or
    ``EnforcementMatrixError`` if the set of native surfaces proven does not
    equal the exact expected wall-set for the preset.
    """

    expected = expected_native_walls(policy_name)

    ensure_runtime_policy_probe_suite_passed(report)

    native_results = [
        result
        for result in report.results
        if result.enforcement_source.startswith(NATIVE_ENFORCEMENT_SOURCE_PREFIX)
    ]

    degraded = sorted(
        {result.surface for result in native_results if result.status != "pass"}
    )
    if degraded:
        raise EnforcementMatrixError(
            f"[{policy_name}] native wall probe(s) did not pass "
            f"(status != 'pass', not enforced): {degraded}"
        )

    proven = native_walls_proven(report)
    if proven != expected:
        missing = sorted(expected - proven)
        extra = sorted(proven - expected)
        raise EnforcementMatrixError(
            f"[{policy_name}] native wall-set mismatch: "
            f"missing={missing} extra={extra} "
            f"(proven={sorted(proven)}, expected={sorted(expected)})"
        )


def run_enforcement_probe(
    policy_name: str,
    *,
    task_image_from: str = DEFAULT_ENFORCEMENT_PROBE_TASK,
    ref: str | None = None,
) -> RuntimePolicyProbeReport:
    """Provision one sandbox, harden it, probe it, and assert the wall-set.

    Returns the probe report on full success. Raises ``ValueError`` for an
    unknown preset, ``EnforcementMatrixError`` for a wall-set mismatch, or
    ``DaytonaRuntimeProbeSuiteError`` if a required probe failed. The sandbox is
    always deleted before returning.
    """

    selected = resolve_policy(policy_name)
    if selected.enforcement_mode != "native":
        raise EnforcementMatrixError(
            f"[{selected.name}] enforcement_mode must be 'native' for the "
            f"enforcement matrix; got {selected.enforcement_mode!r}"
        )

    from daytona_sdk import Daytona

    from boundarybench.harness.registry import (
        DEFAULT_HARNESS,
        get_harness_adapter,
    )
    from boundarybench.terminalbench.daytona import (
        load_terminalbench_daytona_bundle,
    )
    from boundarybench.terminalbench.daytona_run import (
        daytona_task_resources,
        provision_hardened_task_sandbox,
        task_docker_image,
    )
    from boundarybench.terminalbench.harbor import (
        DEFAULT_TERMINAL_BENCH_2_1_REF,
    )

    harbor_ref = ref or DEFAULT_TERMINAL_BENCH_2_1_REF
    print(
        f"[enforcement-probe] policy={selected.name} "
        f"sourcing image from task {task_image_from!r} (task is NOT run)",
        flush=True,
    )
    bundle = load_terminalbench_daytona_bundle(
        task_id=task_image_from, harbor_ref=harbor_ref
    )
    image = task_docker_image(bundle)
    resources = daytona_task_resources(bundle)

    hardening_config = selected.config
    harness_adapter = get_harness_adapter(DEFAULT_HARNESS)

    daytona = Daytona()
    sandbox = None
    try:
        print(f"[enforcement-probe] provisioning sandbox image={image}", flush=True)
        sandbox, hardening = provision_hardened_task_sandbox(
            daytona,
            image=image,
            resources=resources,
            hardening_config=hardening_config,
            run_agent_as_root=selected.run_agent_as_root,
            install_policy_hardening=(
                bool(selected.overlays) or selected.enforcement_mode == "native"
            ),
            install_landlock_mac_runner=selected.full_mac_enforcement,
            enforcement_mode=selected.enforcement_mode,
            harness=harness_adapter,
        )
        if hardening is None:
            raise EnforcementMatrixError(
                f"[{selected.name}] hardening was not installed; "
                "cannot prove native walls"
            )
        print("[enforcement-probe] running runtime policy probe suite", flush=True)
        report = run_runtime_policy_probe_suite_in_sandbox(
            sandbox,
            daytona_policy_hardening=hardening,
            policy_id=selected.name,
            policy_name=selected.name,
            overlays=selected.overlays,
            agent_user=selected.agent_user,
            workspace=RUNTIME_POLICY_PROBE_WORKSPACE,
            isolate_network=selected.isolate_network,
            block_network=selected.block_network,
            block_child_shell_network=selected.block_child_shell_network,
            unsupported_surfaces=selected.unsupported_surfaces,
            probe_scope=selected.runtime_probe_scope,
            full_mac_enforcement=selected.full_mac_enforcement,
            enforcement_mode=selected.enforcement_mode,
        )
        assert_enforcement_matrix(selected.name, report)
        return report
    finally:
        if sandbox is not None:
            try:
                daytona.delete(sandbox)
            except Exception as exc:  # noqa: BLE001 - cleanup must not mask result
                print(
                    f"[enforcement-probe] WARN sandbox delete failed: {exc!r}",
                    flush=True,
                )


def run_enforcement_matrix_all(
    *,
    task_image_from: str = DEFAULT_ENFORCEMENT_PROBE_TASK,
    ref: str | None = None,
) -> int:
    """Run EVERY preset's enforcement probe and aggregate the results.

    Returns 0 iff every preset's exact wall-set was proven live, else 1. The
    presets run SEQUENTIALLY: each probe provisions + hardens + probes + deletes
    its own Daytona sandbox in ~30-40s, so eight in series is only a few minutes
    (well within the CI timeout), and sequential execution avoids sharing an
    async event loop / Daytona client across threads -- a concurrent run produced
    a spurious TaskGroup failure on one preset. Each preset is isolated: one
    failing (with its traceback printed) does not abort the rest.
    """

    import traceback

    presets = tuple(EXPECTED_NATIVE_WALLS)
    results: dict[str, tuple[bool, BaseException | None]] = {}
    for policy in presets:
        print(f"::group::{policy}", flush=True)
        try:
            run_enforcement_probe(policy, task_image_from=task_image_from, ref=ref)
            results[policy] = (True, None)
        except Exception as exc:  # noqa: BLE001 - record + keep going
            results[policy] = (False, exc)
            traceback.print_exc()
        finally:
            print("::endgroup::", flush=True)

    overall = 0
    print("=== enforcement-matrix summary ===", flush=True)
    for policy in presets:
        ok, exc = results[policy]
        if ok:
            print(f"  PASS {policy}")
        else:
            overall = 1
            print(f"  FAIL {policy}: {type(exc).__name__}: {exc}")
    return overall


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundarybench enforcement-probe",
        description=(
            "Provision one fresh Daytona sandbox, install a preset's native "
            "hardening, run the runtime policy probe suite, and assert the exact "
            "expected set of native enforcement walls was proven live. Runs NO "
            "Terminal-Bench task, agent, or verifier."
        ),
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--policy",
        help=(
            "Native hardening preset to probe: one of "
            + ", ".join(sorted(EXPECTED_NATIVE_WALLS))
            + "."
        ),
    )
    target.add_argument(
        "--all",
        action="store_true",
        help="Probe ALL presets concurrently and fail if any wall-set is wrong.",
    )
    parser.add_argument(
        "--task-image-from",
        default=DEFAULT_ENFORCEMENT_PROBE_TASK,
        help=(
            "Terminal-Bench task whose image + resources provision the sandbox "
            "(the task itself is never run). Default: %(default)s."
        ),
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="Harbor ref for the task image lookup (default: the pinned TB 2.1 ref).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.all:
        return run_enforcement_matrix_all(
            task_image_from=args.task_image_from, ref=args.ref
        )
    policy_name = args.policy
    try:
        report = run_enforcement_probe(
            policy_name, task_image_from=args.task_image_from, ref=args.ref
        )
    except (EnforcementMatrixError, DaytonaRuntimeProbeSuiteError) as exc:
        print(f"enforcement-probe: FAIL [{policy_name}]: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"enforcement-probe: error: {exc}", file=sys.stderr)
        return 2
    proven = sorted(native_walls_proven(report))
    print(
        f"enforcement-probe: PASS [{policy_name}] "
        f"native walls proven ({len(proven)}): {proven if proven else '(none)'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
