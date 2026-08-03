from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


FINGERPRINT_SCHEMA = "boundarybench.runner-fingerprint.v1"

RUNNER_INPUT_PATTERNS = (
    "pyproject.toml",
    "uv.lock",
    "README.md",
    "src/boundarybench/**/*.py",
    "src/boundarybench/**/*.json",
    "src/boundarybench/**/*.sh",
)


@dataclass(frozen=True)
class RunnerFingerprint:
    digest: str
    files: list[str]
    schema_version: str = FINGERPRINT_SCHEMA

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class StaleBaseStatus:
    branch_sha: str | None = None
    base_main_sha: str | None = None
    current_main_sha: str | None = None
    branch_name: str | None = None
    dirty: bool = False
    stale: bool = False
    checked: bool = False
    error: str | None = None

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)


GitRunner = Callable[[list[str], str | Path | None], str | None]


def runner_fingerprint(root: str | Path = ".") -> RunnerFingerprint:
    base = Path(root).resolve()
    files = _runner_input_files(base)
    digest = hashlib.sha256()
    digest.update(f"{FINGERPRINT_SCHEMA}\n".encode())
    for rel_path in files:
        full_path = base / rel_path
        digest.update(rel_path.encode())
        digest.update(b"\0")
        digest.update(full_path.read_bytes())
        digest.update(b"\0")
    return RunnerFingerprint(digest=digest.hexdigest(), files=files)


def _runner_input_files(root: Path) -> list[str]:
    paths: set[str] = set()
    for pattern in RUNNER_INPUT_PATTERNS:
        for candidate in root.glob(pattern):
            if candidate.is_file() and "__pycache__" not in candidate.parts:
                paths.add(candidate.relative_to(root).as_posix())
    return sorted(paths)


def runtime_provenance(root: str | Path = ".") -> dict[str, object]:
    git = current_git_state(root)
    return {
        "image_digest": os.getenv("BOUNDARYBENCH_IMAGE_DIGEST")
        or _image_digest_from_ref(os.getenv("BOUNDARYBENCH_MANAGER_IMAGE")),
        "image_source_sha": os.getenv("BOUNDARYBENCH_IMAGE_SOURCE_SHA"),
        "branch_sha": os.getenv("BOUNDARYBENCH_BRANCH_SHA") or git.get("commit"),
        "base_main_sha": os.getenv("BOUNDARYBENCH_BASE_MAIN_SHA")
        or _safe_merge_base(root),
        "branch_name": os.getenv("BOUNDARYBENCH_BRANCH") or git.get("branch"),
        "dirty": _env_bool("BOUNDARYBENCH_DIRTY", bool(git.get("dirty"))),
        "build_time": os.getenv("BOUNDARYBENCH_IMAGE_BUILD_TIME"),
        "runner_fingerprint": os.getenv("BOUNDARYBENCH_RUNNER_FINGERPRINT")
        or _safe_runner_fingerprint(root),
    }


def stale_base_status(
    *,
    run_git: GitRunner | None = None,
    cwd: str | Path | None = None,
    refresh: bool = False,
) -> StaleBaseStatus:
    git = run_git or _run_git
    try:
        if refresh:
            git(["fetch", "origin", "main", "--quiet"], cwd)
        branch_sha = git(["rev-parse", "HEAD"], cwd)
        base_main_sha = git(["merge-base", "HEAD", "origin/main"], cwd)
        current_main_sha = git(["rev-parse", "origin/main"], cwd)
        branch_name = git(["branch", "--show-current"], cwd)
        dirty = bool(git(["status", "--short"], cwd))
    except Exception as exc:  # noqa: BLE001 - submit should emit a warning, not crash
        return StaleBaseStatus(checked=False, error=str(exc))
    missing = [
        name
        for name, value in (
            ("branch_sha", branch_sha),
            ("base_main_sha", base_main_sha),
            ("current_main_sha", current_main_sha),
        )
        if not value
    ]
    if missing:
        return StaleBaseStatus(
            branch_sha=branch_sha,
            base_main_sha=base_main_sha,
            current_main_sha=current_main_sha,
            branch_name=branch_name,
            dirty=dirty,
            checked=False,
            error=f"missing git values: {', '.join(missing)}",
        )
    stale = bool(base_main_sha and current_main_sha and base_main_sha != current_main_sha)
    return StaleBaseStatus(
        branch_sha=branch_sha,
        base_main_sha=base_main_sha,
        current_main_sha=current_main_sha,
        branch_name=branch_name,
        dirty=dirty,
        stale=stale,
        checked=True,
    )


def stale_base_warning(status: StaleBaseStatus) -> str | None:
    if not status.checked:
        return f"could not validate branch freshness against origin/main: {status.error}"
    if not status.stale:
        return None
    branch = status.branch_name or status.branch_sha or "current branch"
    return (
        f"{branch} is based on {status.base_main_sha}, but origin/main is newer "
        f"({status.current_main_sha}); rebase or pass --allow-stale-base."
    )


def current_git_state(root: str | Path = ".") -> dict[str, object]:
    return {
        "commit": _run_git(["rev-parse", "HEAD"], root),
        "branch": _run_git(["branch", "--show-current"], root),
        "dirty": bool(_run_git(["status", "--short"], root)),
    }


def _safe_merge_base(root: str | Path = ".") -> str | None:
    try:
        return _run_git(["merge-base", "HEAD", "origin/main"], root)
    except Exception:  # noqa: BLE001 - runtime may not have a git checkout
        return None


def _safe_runner_fingerprint(root: str | Path = ".") -> str | None:
    try:
        digest = runner_fingerprint(root).digest
    except Exception:  # noqa: BLE001 - runtime provenance should be best-effort
        return None
    return digest


def _image_digest_from_ref(ref: str | None) -> str | None:
    if ref and "@sha256:" in ref:
        return ref
    return None


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _run_git(args: list[str], cwd: str | Path | None = None) -> str | None:
    try:
        value = subprocess.check_output(
            ["git", *args],
            cwd=str(cwd) if cwd is not None else None,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return value or None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect BoundaryBench runner provenance helpers"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    fingerprint = subparsers.add_parser("fingerprint")
    fingerprint.add_argument("--root", default=".")
    fingerprint.add_argument("--json", action="store_true")
    fingerprint.add_argument(
        "--github-env",
        default=None,
        help="Append BOUNDARYBENCH_RUNNER_FINGERPRINT values to this file.",
    )
    subparsers.add_parser("runtime-provenance")
    stale = subparsers.add_parser("stale-base")
    stale.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "fingerprint":
        value = runner_fingerprint(args.root)
        if args.github_env:
            with Path(args.github_env).open("a", encoding="utf-8") as handle:
                handle.write(f"BOUNDARYBENCH_RUNNER_FINGERPRINT={value.digest}\n")
        if args.json:
            print(json.dumps(value.to_mapping(), sort_keys=True))
        else:
            print(value.digest)
        return 0
    if args.command == "runtime-provenance":
        print(json.dumps(runtime_provenance(), sort_keys=True))
        return 0
    if args.command == "stale-base":
        status = stale_base_status()
        if args.json:
            print(json.dumps(status.to_mapping(), sort_keys=True))
        else:
            warning = stale_base_warning(status)
            if warning:
                print(warning, file=sys.stderr)
        return 2 if status.checked and status.stale else 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
