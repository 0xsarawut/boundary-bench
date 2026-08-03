from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
from typing import Any

import pytest


_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "boundarybench"
    / "daytona"
    / "scripts"
    / "protect_explicit_credential_paths.py"
)


def _load_helper() -> Any:
    assert _SCRIPT.exists(), "packaged credential-path helper is missing"
    spec = importlib.util.spec_from_file_location("credential_path_helper", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_helper_protects_an_existing_regular_file_without_replacing_it(tmp_path: Path):
    helper = _load_helper()
    credential = tmp_path / "provider-token"
    credential.write_text("secret", encoding="utf-8")
    before = credential.stat()

    helper.protect_credential_paths(
        [str(credential)], uid=os.getuid(), gid=os.getgid()
    )

    after = credential.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert credential.read_text(encoding="utf-8") == "secret"


@pytest.mark.parametrize("path", ["", "/", "relative/token", "/tmp/./token", "/tmp/../token"])
def test_helper_rejects_ambiguous_or_non_absolute_paths(path: str):
    helper = _load_helper()

    with pytest.raises(helper.CredentialPathError):
        helper.protect_credential_paths([path], uid=os.getuid(), gid=os.getgid())


def test_helper_rejects_a_symlink_parent(tmp_path: Path):
    helper = _load_helper()
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    credential = real_parent / "token"
    credential.write_text("secret", encoding="utf-8")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(helper.CredentialPathError):
        helper.protect_credential_paths(
            [str(linked_parent / "token")], uid=os.getuid(), gid=os.getgid()
        )


def test_helper_rejects_a_symlink_final_component(tmp_path: Path):
    helper = _load_helper()
    target = tmp_path / "target"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "token"
    link.symlink_to(target)

    with pytest.raises(helper.CredentialPathError):
        helper.protect_credential_paths([str(link)], uid=os.getuid(), gid=os.getgid())


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo"])
def test_helper_rejects_missing_or_non_regular_final_components(
    tmp_path: Path, kind: str
):
    helper = _load_helper()
    path = tmp_path / kind
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)

    with pytest.raises(helper.CredentialPathError):
        helper.protect_credential_paths([str(path)], uid=os.getuid(), gid=os.getgid())
