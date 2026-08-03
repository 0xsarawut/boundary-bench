#!/usr/bin/env python3
from __future__ import annotations

import os
import stat
import sys
from collections.abc import Sequence


class CredentialPathError(ValueError):
    """An explicit credential path cannot be safely protected."""


def _path_components(path: str) -> tuple[str, ...]:
    if not path or not path.startswith("/") or path == "/":
        raise CredentialPathError(
            f"credential path must be absolute and must not be root: {path!r}"
        )
    components = tuple(path.split("/")[1:])
    if any(component in ("", ".", "..") for component in components):
        raise CredentialPathError(
            f"credential path contains an ambiguous component: {path!r}"
        )
    return components


def _protect_credential_path(path: str, *, uid: int, gid: int) -> None:
    components = _path_components(path)
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    credential_fd: int | None = None
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        credential_fd = os.open(
            components[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(credential_fd).st_mode):
            raise CredentialPathError(
                f"credential path is not a regular file: {path!r}"
            )
        os.fchown(credential_fd, uid, gid)
        os.fchmod(credential_fd, 0o600)
    except CredentialPathError:
        raise
    except OSError as exc:
        raise CredentialPathError(
            f"cannot safely protect credential path {path!r}: {exc}"
        ) from exc
    finally:
        if credential_fd is not None:
            os.close(credential_fd)
        os.close(directory_fd)


def protect_credential_paths(
    paths: Sequence[str], *, uid: int = 0, gid: int = 0
) -> None:
    for path in paths:
        _protect_credential_path(path, uid=uid, gid=gid)


def main(argv: Sequence[str] | None = None) -> int:
    paths = tuple(sys.argv[1:] if argv is None else argv)
    if not paths:
        print("at least one explicit credential path is required", file=sys.stderr)
        return 2
    try:
        protect_credential_paths(paths)
    except CredentialPathError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
