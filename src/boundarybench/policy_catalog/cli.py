from __future__ import annotations

import argparse
import json

from boundarybench.policy_catalog.catalog import (
    compile_policy_variant,
    list_policy_pack_ids,
    load_policy_pack,
    validate_policy_pack,
)


def validate_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validate canonical policy catalog packs.")
    parser.add_argument("--pack-id", default="all")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    pack_ids = (
        list_policy_pack_ids()
        if args.pack_id in {"", "all", "*"}
        else [str(args.pack_id)]
    )
    reports = []
    for pack_id in pack_ids:
        try:
            pack = load_policy_pack(pack_id, validate=False)
        except (KeyError, ValueError) as exc:
            parser.exit(1, f"error: {exc}\n")
        reports.append(validate_policy_pack(pack))

    if args.json:
        print(json.dumps([report.to_dict() for report in reports], indent=2))
    else:
        for report in reports:
            status = "passed" if report.passed else "failed"
            print(f"{report.pack_id}: {status}")
            for issue in report.issues:
                print(f"  {issue.severity}: {issue.path}: {issue.message}")

    if any(not report.passed for report in reports):
        raise SystemExit(1)


def compile_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Compile a canonical policy variant to the target contract payload."
    )
    parser.add_argument("--pack-id", required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--variant-id", required=True)
    parser.add_argument("--target", default="daytona-hardening-v1")
    args = parser.parse_args(argv)

    try:
        result = compile_policy_variant(
            pack_id=args.pack_id,
            policy_id=args.policy_id,
            variant_id=args.variant_id,
            target=args.target,
        )
    except (KeyError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(json.dumps(result.to_dict(), indent=2))
