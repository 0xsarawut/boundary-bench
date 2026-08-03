"""Securely capture verifier handoff files into a root-private staging tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shutil
import stat
import sys


def _require_root_owned_mode(
    file_stat: os.stat_result,
    *,
    expected_mode: int,
    description: str,
    required_owner_uid: int = 0,
) -> None:
    if file_stat.st_uid != required_owner_uid:
        raise PermissionError(f"{description} is not owned by uid {required_owner_uid}")
    if stat.S_IMODE(file_stat.st_mode) != expected_mode:
        raise PermissionError(
            f"{description} has unsafe mode {stat.S_IMODE(file_stat.st_mode):#o}"
        )


def _copy_regular_file(
    *,
    workspace_fd: int,
    staging_fd: int,
    relative_path: str,
    destination: str,
    max_file_bytes: int,
    max_total_bytes_remaining: int | None = None,
    required_owner_uid: int = 0,
) -> dict[str, int | str]:
    components = relative_path.split("/")
    parent_fd = os.dup(workspace_fd)
    source_fd = -1
    destination_fd = -1
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        source_fd = os.open(
            components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd
        )
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError(f"not a regular file: {relative_path}")
        source_size = source_stat.st_size
        if source_size > max_file_bytes:
            raise ValueError(
                f"artifact exceeds per-file byte cap: {relative_path} ({source_size})"
            )
        if (
            max_total_bytes_remaining is not None
            and source_size > max_total_bytes_remaining
        ):
            raise ValueError("artifacts exceed total byte cap")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode=0o600,
            dir_fd=staging_fd,
        )
        digest = hashlib.sha256()
        remaining = source_size
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError(f"source mutated during capture: {relative_path}")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise ValueError(f"source mutated during capture: {relative_path}")
        source_after = os.fstat(source_fd)
        identity_before = (
            source_stat.st_dev,
            source_stat.st_ino,
            source_stat.st_size,
            source_stat.st_mtime_ns,
            source_stat.st_ctime_ns,
        )
        identity_after = (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_size,
            source_after.st_mtime_ns,
            source_after.st_ctime_ns,
        )
        if identity_after != identity_before:
            raise ValueError(f"source mutated during capture: {relative_path}")
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o400)
        destination_stat = os.fstat(destination_fd)
        if not stat.S_ISREG(destination_stat.st_mode):
            raise PermissionError(f"staged artifact is not regular: {destination}")
        _require_root_owned_mode(
            destination_stat,
            expected_mode=0o400,
            description=f"staged artifact {destination}",
            required_owner_uid=required_owner_uid,
        )
        if destination_stat.st_size != source_size:
            raise ValueError(f"staged artifact size mismatch: {destination}")
        return {
            "size_bytes": source_size,
            "sha256": digest.hexdigest(),
        }
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-root", required=True)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--max-files", type=int, default=16)
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024**3)
    parser.add_argument("--max-total-bytes", type=int, default=3 * 1024**3)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise PermissionError("verifier artifact capture helper must run as root")
    if len(args.path) > args.max_files:
        raise ValueError(f"artifact count exceeds cap {args.max_files}")
    if min(args.max_files, args.max_file_bytes, args.max_total_bytes) <= 0:
        raise ValueError("artifact caps must be positive")

    workspace_root = posixpath.normpath(args.workspace_root)
    staging_root = posixpath.normpath(args.staging_root)
    if not posixpath.isabs(workspace_root) or workspace_root != args.workspace_root:
        raise ValueError("workspace root must be absolute and normalized")
    if not posixpath.isabs(staging_root) or staging_root != args.staging_root:
        raise ValueError("staging root must be absolute and normalized")

    os.mkdir(staging_root, mode=0o700)
    staging_stat = os.lstat(staging_root)
    if not stat.S_ISDIR(staging_stat.st_mode) or stat.S_ISLNK(staging_stat.st_mode):
        raise PermissionError("verifier artifact staging root is not a real directory")
    _require_root_owned_mode(
        staging_stat,
        expected_mode=0o700,
        description="verifier artifact staging root",
    )
    workspace_fd = -1
    staging_fd = -1
    try:
        workspace_fd = os.open(
            workspace_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        staging_fd = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        manifest_artifacts: list[dict[str, int | str]] = []
        total_bytes = 0
        for index, path in enumerate(args.path):
            normalized_path = posixpath.normpath(path)
            if not posixpath.isabs(path) or normalized_path != path:
                raise ValueError(f"path must be absolute and normalized: {path}")
            if posixpath.commonpath((workspace_root, path)) != workspace_root:
                raise ValueError(f"path escapes workspace root: {path}")
            relative_path = posixpath.relpath(path, workspace_root)
            if relative_path in ("", ".") or relative_path.startswith("../"):
                raise ValueError(f"path is not a workspace file: {path}")
            staged_name = f"{index:06d}"
            capture = _copy_regular_file(
                workspace_fd=workspace_fd,
                staging_fd=staging_fd,
                relative_path=relative_path,
                destination=staged_name,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes_remaining=args.max_total_bytes - total_bytes,
            )
            total_bytes += int(capture["size_bytes"])
            manifest_artifacts.append(
                {
                    "index": index,
                    "staged_name": staged_name,
                    "size_bytes": int(capture["size_bytes"]),
                    "sha256": str(capture["sha256"]),
                }
            )
        final_staging_stat = os.fstat(staging_fd)
        _require_root_owned_mode(
            final_staging_stat,
            expected_mode=0o700,
            description="verifier artifact staging root",
        )
        for index in range(len(args.path)):
            staged_name = f"{index:06d}"
            staged_fd = os.open(
                staged_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=staging_fd
            )
            try:
                staged_stat = os.fstat(staged_fd)
                if not stat.S_ISREG(staged_stat.st_mode):
                    raise PermissionError(
                        f"staged artifact is not regular: {staged_name}"
                    )
                _require_root_owned_mode(
                    staged_stat,
                    expected_mode=0o400,
                    description=f"staged artifact {staged_name}",
                )
                expected = manifest_artifacts[index]
                if staged_stat.st_size != expected["size_bytes"]:
                    raise ValueError(f"staged artifact size mismatch: {staged_name}")
                staged_digest = hashlib.sha256()
                while True:
                    chunk = os.read(staged_fd, 1024 * 1024)
                    if not chunk:
                        break
                    staged_digest.update(chunk)
                if staged_digest.hexdigest() != expected["sha256"]:
                    raise ValueError(f"staged artifact hash mismatch: {staged_name}")
            finally:
                os.close(staged_fd)
        print(
            json.dumps(
                {
                    "version": 1,
                    "file_count": len(manifest_artifacts),
                    "total_bytes": total_bytes,
                    "artifacts": manifest_artifacts,
                },
                sort_keys=True,
            )
        )
    except Exception:
        shutil.rmtree(staging_root, ignore_errors=True)
        raise
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if workspace_fd >= 0:
            os.close(workspace_fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verifier artifact capture failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
