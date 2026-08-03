"""Unit tests for the shared ``policy_disclosure`` primitives.

These assert against the REAL N×F×P presets (``AXIS_PRESETS`` +
``build_daytona_config_from_axes``) so any drift in the presets — the writable
set, the home carveouts, or the trusted-domain base — breaks these tests rather
than silently changing what the disclosure channels (``policy_prompt`` and the
later ``recovery_skill``) tell the agent.
"""

from __future__ import annotations

from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)
from boundarybench.terminalbench import policy_disclosure as pd


def _cfg(name, task_id="hello-world"):
    return build_daytona_config_from_axes(AXIS_PRESETS[name], task_id=task_id)


def test_writable_dirs_high_nist_freezes_home_but_keeps_var_tmp():
    dirs = pd.writable_dirs(_cfg("high-nist"))
    assert "/app" in dirs
    assert "/var/tmp" in dirs
    assert not any(d.startswith("/home/") for d in dirs)


def test_home_carveout_dirs_high_nist():
    assert pd.home_carveout_dirs(_cfg("high-nist")) == (
        ".claude",
        ".cache",
        ".config",
        ".local",
    )


def test_disclosed_domains_hides_infra():
    cfg = _cfg("high-nist")
    infra = pd.normalized_infra(["api.anthropic.com"])
    dom = pd.disclosed_domains(cfg, infra)
    assert "api.anthropic.com" not in dom
    assert "pypi.org" in dom


def test_enforced_writable_display_high_nist_excludes_var_tmp():
    assert pd.enforced_writable_display(_cfg("high-nist")) == [
        "/app",
        "/tmp",
        "~/.claude",
        "~/.cache",
        "~/.config",
        "~/.local",
    ]


def test_enforced_writable_display_workspace_scope_keeps_var_tmp():
    display = pd.enforced_writable_display(_cfg("moderate-nist"))
    assert display[:3] == ["/app", "/tmp", "/var/tmp"]
    assert "~" in display


def test_enforced_writable_display_open_scope_is_base_only():
    assert pd.enforced_writable_display(_cfg("non-root")) == ["/app", "/tmp"]


def test_sha256_and_utf8_len_stable():
    assert (
        pd.sha256("abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert pd.sha256("abc") == pd.sha256("abc")
    assert pd.utf8_len("é") == 2
