"""Render-level tests for the NATIVE per-command exec chain (Task 4).

The native exec chain wraps each agent command with Linux-native enforcement —
setpriv privilege-drop (+ P2 capability drop), real read-only bind-remounts for
F1/F2, and a universal environment strip for canonical/controller credential
names —
and NONE of the legacy steering stages (LD_PRELOAD, BOUNDARY_* env, policy-bin
PATH prepend, mount.real deny-stubs, seccomp/landlock prefixes, child-network
BASH_ENV, the AgentSH wrap). The exec chain only runs in a live VM, so these
tests assert the RENDERED inner-script content (plus ``bash -n`` on it),
mirroring the render-assertion style in tests/test_native_install.py and
test_daytona_policy_surfaces.py.

The single hardest invariant, tested across every preset: no synthetic
credential values are injected, and ``CANONICAL_INFRA_KEY_ENV_NAMES`` must not
reach the agent env — they are dropped from the ``sudo --preserve-env`` list,
stripped with ``env -u`` belt-and-suspenders, and never present as values in the
rendered command. Required adapter-specific aliases intentionally survive for
child authentication.
"""

from __future__ import annotations

from dataclasses import replace
import re
import shlex
import subprocess

import pytest

from boundarybench.daytona import daytona_policy_hardening as dph
from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    run_with_daytona_policy_hardening,
)
from boundarybench.daytona.honeytokens import HONEYTOKEN_MATCH_VALUES
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    CANONICAL_INFRA_KEY_ENV_NAMES,
    Privilege,
    build_daytona_config_from_axes,
)

_ASSET_DIR = "/tmp/dph"
_NORMAL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_ALL_NATIVE_PRESETS = sorted(AXIS_PRESETS)
_P1_PRESETS = ["fslock", "low-nist", "moderate-nist", "netlock", "non-root"]


class _FakeExecResult:
    def __init__(self, *, result: str = "") -> None:
        self.exit_code = 0
        self.result = result
        self.stderr = ""


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.envs: list[dict[str, str] | None] = []
        self.pid_namespace_markers: dict[str, tuple[str, str]] = {}

    def exec(self, command: str, *, timeout: int, env: dict[str, str] | None = None):
        self.commands.append(command)
        self.envs.append(env)
        if command == "readlink /proc/self/ns/pid":
            return _FakeExecResult(result="pid:[100]\n")

        marker_match = re.search(
            r"IA_PIDNS_TOKEN=([0-9a-f]+); IA_PIDNS_MARKER=([^;]+);", command
        )
        if marker_match:
            token = marker_match.group(1)
            marker_path = shlex.split(marker_match.group(2))[0]
            self.pid_namespace_markers[marker_path] = (token, "pid:[200]")

        if command.startswith("stat -c '%u %a' -- "):
            marker_path = shlex.split(command.split("&&", 1)[0])[-1]
            token, namespace_id = self.pid_namespace_markers[marker_path]
            return _FakeExecResult(
                result=f"0 400\n{token}\n1\n{namespace_id}\n"
            )

        if command.startswith("rm -f -- "):
            marker_path = shlex.split(command)[-1]
            self.pid_namespace_markers.pop(marker_path, None)

        return _FakeExecResult()


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()


def _hardening(preset_name: str, *, proxy_url: str | None = None) -> DaytonaPolicyHardening:
    config = build_daytona_config_from_axes(AXIS_PRESETS[preset_name])
    return DaytonaPolicyHardening(
        asset_dir=_ASSET_DIR,
        policy_message_preload_so=f"{_ASSET_DIR}/policy.so",
        block_message_command=f"{_ASSET_DIR}/deny-command.sh",
        mount_real_path=f"{_ASSET_DIR}/mount.real",
        policy_bin_dir=f"{_ASSET_DIR}/bin",
        child_network_block_env=f"{_ASSET_DIR}/child_network_block_env",
        domain_egress_proxy_url=proxy_url,
        hardening_config=config,
    )


def _drive_native(
    preset_name: str,
    *,
    env: dict[str, str] | None = None,
    command: str = "claude -p run",
    cwd: str = "/workspace",
    proxy_url: str | None = None,
    isolate_network: bool = True,
    isolate_agent_pid_namespace: bool = False,
) -> tuple[str, str, dict[str, str] | None]:
    """Run the native exec chain against a fake sandbox; return (wrapped, inner, env).

    ``run_as_root`` is derived from the preset's privilege axis exactly like the
    later preset-selection task will do (P0 == root control cell).
    """
    sandbox = _FakeSandbox()
    hardening = _hardening(preset_name, proxy_url=proxy_url)
    run_as_root = AXIS_PRESETS[preset_name].privilege == Privilege.P0
    run_with_daytona_policy_hardening(
        sandbox,
        daytona_policy_hardening=hardening,
        command=command,
        cwd=cwd,
        timeout=30,
        isolate_network=isolate_network,
        env=env,
        run_as_root=run_as_root,
        enforcement_mode="native",
        isolate_agent_pid_namespace=isolate_agent_pid_namespace,
    )
    command_index = next(
        index
        for index, rendered in enumerate(sandbox.process.commands)
        if command in rendered
    )
    wrapped = sandbox.process.commands[command_index]
    inner = shlex.split(wrapped)[-1]
    return wrapped, inner, sandbox.process.envs[command_index]


def _preserve_env_names(wrapped: str) -> list[str]:
    for token in shlex.split(wrapped):
        if token.startswith("--preserve-env="):
            names = token.split("=", 1)[1]
            return names.split(",") if names else []
    return []


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_never_carries_real_infra_key(preset_name: str) -> None:
    real_env = {
        name: f"REAL-SECRET-{name}" for name in CANONICAL_INFRA_KEY_ENV_NAMES
    }
    real_env["ANTHROPIC_BASE_URL"] = "https://proxy.internal/api"

    wrapped, inner, injected_env = _drive_native(preset_name, env=real_env)
    injected_env = injected_env or {}
    preserve_names = _preserve_env_names(wrapped)

    for name in CANONICAL_INFRA_KEY_ENV_NAMES:
        assert f"-u {name}" in inner, f"{name} not stripped for {preset_name}"
        assert name not in preserve_names, f"{name} in --preserve-env for {preset_name}"
        assert name not in injected_env, f"{name} injected for {preset_name}"
        assert f"REAL-SECRET-{name}" not in wrapped

    assert "ANTHROPIC_BASE_URL" in preserve_names
    assert injected_env.get("ANTHROPIC_BASE_URL") == "https://proxy.internal/api"


def test_native_strips_custom_configured_env_name_at_both_boundaries() -> None:
    custom_name = "CUSTOM_RUNTIME_SECRET"
    hardening = _hardening("low-nist")
    hardening = replace(
        hardening,
        hardening_config=replace(
            hardening.hardening_config,
            strip_env_vars=(custom_name, "OPENROUTER_API_KEY"),
        ),
    )
    sandbox = _FakeSandbox()

    run_with_daytona_policy_hardening(
        sandbox,
        daytona_policy_hardening=hardening,
        command="claude -p run",
        cwd="/workspace",
        timeout=30,
        env={custom_name: "custom-secret", "SAFE_VALUE": "safe"},
        run_as_root=False,
        enforcement_mode="native",
    )

    wrapped = sandbox.process.commands[0]
    inner = shlex.split(wrapped)[-1]
    injected_env = sandbox.process.envs[0] or {}
    assert inner.count(f"-u {custom_name}") == 1
    assert inner.count("-u OPENROUTER_API_KEY") == 1
    assert custom_name not in _preserve_env_names(wrapped)
    assert custom_name not in injected_env
    assert injected_env["SAFE_VALUE"] == "safe"


def test_native_stripped_env_names_are_ordered_and_deduplicated_once() -> None:
    config = replace(
        _hardening("low-nist").hardening_config,
        strip_env_vars=("CUSTOM_RUNTIME_SECRET", "OPENROUTER_API_KEY", "CUSTOM_RUNTIME_SECRET"),
    )

    names = dph._native_stripped_env_names(config)

    assert names[: len(CANONICAL_INFRA_KEY_ENV_NAMES)] == (
        CANONICAL_INFRA_KEY_ENV_NAMES
    )
    assert names[-1] == "CUSTOM_RUNTIME_SECRET"
    assert len(names) == len(set(names))


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_omits_fake_env_and_strips_every_real_key_name(
    preset_name: str,
) -> None:
    wrapped, inner, injected_env = _drive_native(preset_name)
    injected_env = injected_env or {}

    for value in HONEYTOKEN_MATCH_VALUES:
        assert value not in inner, f"honeytoken value leaked at {preset_name}"
        assert value not in wrapped, f"honeytoken value rendered at {preset_name}"
        assert value not in injected_env.values()
    for name in CANONICAL_INFRA_KEY_ENV_NAMES:
        assert f"-u {name}" in inner


def test_native_control_root_has_no_setpriv() -> None:
    _, inner, _ = _drive_native("control")
    assert "setpriv" not in inner
    assert "id -u daytona" not in inner
    assert "HOME=/root" in inner
    assert "USER=root" in inner


@pytest.mark.parametrize("preset_name", _P1_PRESETS)
def test_native_p1_setpriv_without_caps(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert 'setpriv --reuid="$uid" --regid="$gid" --clear-groups' in inner
    assert "--no-new-privs" not in inner
    assert "--bounding-set" not in inner


def test_native_high_nist_p2_setpriv_with_caps() -> None:
    _, inner, _ = _drive_native("high-nist")
    assert (
        'setpriv --reuid="$uid" --regid="$gid" --clear-groups '
        "--no-new-privs --bounding-set -all"
    ) in inner


@pytest.mark.parametrize("preset_name", ["control", "non-root", "netlock"])
def test_native_no_readonly_mounts_below_f1(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert "remount,bind,ro" not in inner
    assert "remount,bind,rw" not in inner


@pytest.mark.parametrize("preset_name", ["low-nist", "moderate-nist"])
def test_native_f1_readonly_os_keeps_home_and_vartmp_writable(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert "mount --bind /usr /usr && mount -o remount,bind,ro /usr" in inner
    assert "remount,bind,ro /usr" in inner
    assert "remount,bind,ro /home" in inner
    assert "remount,bind,rw /home/daytona" in inner
    assert "remount,bind,rw /var/tmp" in inner
    assert inner.index("remount,bind,ro /usr") < inner.index("exec ")


@pytest.mark.parametrize("preset_name", ["high-nist", "fslock"])
def test_native_f2_freezes_home_except_narrow_agent_runtime_carveouts(
    preset_name: str,
) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert "remount,bind,ro /usr" in inner
    assert "remount,bind,ro /home" in inner
    assert "mkdir -p -- /home/daytona/.claude" in inner
    assert "readlink -f -- /home/daytona/.claude" in inner
    assert "/home/daytona/.grok" not in inner
    assert "/home/daytona/.codex" not in inner
    assert 'mount -o remount,bind,rw "$resolved_carveout"' in inner
    assert "remount,bind,rw /home/daytona " not in inner
    assert "remount,bind,rw /var/tmp" not in inner


@pytest.mark.parametrize("preset_name", ["high-nist", "fslock"])
def test_native_f3_rejects_symlinked_home_carveouts_before_mutating_or_mounting(
    preset_name: str,
) -> None:
    _, inner, _ = _drive_native(preset_name)

    for carveout in (".claude", ".cache", ".config", ".local"):
        path = f"/home/daytona/{carveout}"
        reject = f"if [ -L {path} ]; then"
        create = f"mkdir -p -- {path}"
        resolve = f"readlink -f -- {path}"
        exact = f'if [ "$resolved_carveout" != {path} ]; then'
        chown = f"chown --no-dereference daytona:daytona {path}"
        mount = 'mount --bind "$resolved_carveout" "$resolved_carveout"'

        assert reject in inner
        assert create in inner
        assert resolve in inner
        assert exact in inner
        assert chown in inner
        assert mount in inner
        assert inner.index(reject) < inner.index(create) < inner.index(resolve)
        assert inner.index(resolve) < inner.index(exact) < inner.index(chown)
        assert inner.index(chown) < inner.index(mount)


@pytest.mark.parametrize("preset_name", ["high-nist", "fslock"])
def test_native_f3_validates_canonical_home_before_any_carveout_mutation(
    preset_name: str,
) -> None:
    _, inner, _ = _drive_native(preset_name)

    reject_home_symlink = "if [ -L /home/daytona ]; then"
    resolve_home = 'resolved_home="$(readlink -f -- /home/daytona)"'
    require_exact_home = 'if [ "$resolved_home" != /home/daytona ]; then'
    first_carveout_mutation = "mkdir -p -- /home/daytona/.claude"

    assert reject_home_symlink in inner
    assert resolve_home in inner
    assert require_exact_home in inner
    assert inner.index(reject_home_symlink) < inner.index(resolve_home)
    assert inner.index(resolve_home) < inner.index(require_exact_home)
    assert inner.index(require_exact_home) < inner.index(first_carveout_mutation)


_LEGACY_MARKERS = (
    "LD_PRELOAD",
    "BOUNDARY_",
    "seccomp",
    "landlock",
    "BASH_ENV",
    "agentsh",
    "mount.real",
    "export PATH",
    f"{_ASSET_DIR}/bin",
    "policy.so",
    "deny-command.sh",
)


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_omits_all_legacy_stages(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    for marker in _LEGACY_MARKERS:
        assert marker not in inner, f"legacy marker {marker!r} leaked into {preset_name}"


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_sets_normal_path(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert f"PATH={_NORMAL_PATH}" in inner


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_uses_mount_namespace_without_net(preset_name: str) -> None:
    wrapped, _, _ = _drive_native(preset_name, isolate_network=True)
    assert "unshare --mount --propagation=private" in wrapped
    assert "--net" not in wrapped
    assert "/bin/bash.real -euo pipefail -c" in wrapped


@pytest.mark.parametrize("isolate_agent_pid_namespace", [False, True])
def test_native_agent_pid_namespace_is_opt_in(
    isolate_agent_pid_namespace: bool,
) -> None:
    wrapped, _, _ = _drive_native(
        "low-nist",
        isolate_agent_pid_namespace=isolate_agent_pid_namespace,
    )
    pid_boundary = "unshare --pid --fork --mount-proc --kill-child=SIGKILL"
    assert (pid_boundary in wrapped) is isolate_agent_pid_namespace


def test_native_command_keeps_cd_prefix_without_legacy_wrap() -> None:
    _, inner, _ = _drive_native("non-root", command="claude -p run", cwd="/workspace")
    assert "cd /workspace && claude -p run" in inner
    assert "BASH_ENV" not in inner
    assert "agentsh" not in inner


def test_native_proxy_env_flows_and_is_not_wiped() -> None:
    wrapped, inner, injected_env = _drive_native(
        "low-nist", proxy_url="http://127.0.0.1:18081"
    )
    injected_env = injected_env or {}
    assert "env -i" not in inner
    assert injected_env.get("HTTPS_PROXY") == "http://127.0.0.1:18081"
    assert "HTTPS_PROXY" in _preserve_env_names(wrapped)


def test_legacy_default_still_renders_steering_template() -> None:
    sandbox = _FakeSandbox()
    hardening = _hardening("control")
    run_with_daytona_policy_hardening(
        sandbox,
        daytona_policy_hardening=hardening,
        command="claude -p run",
        cwd="/home/daytona/work",
        timeout=30,
    )
    inner = shlex.split(sandbox.process.commands[0])[-1]
    assert f"LD_PRELOAD={_ASSET_DIR}/policy.so" in inner
    assert "BOUNDARY_BLOCK_NETWORK" in inner
    assert f'export PATH={_ASSET_DIR}/bin' in inner


def test_native_mode_selects_native_template() -> None:
    _, inner, _ = _drive_native("non-root")
    assert "LD_PRELOAD" not in inner
    assert "/usr/bin/env" in inner
    assert "/bin/bash.real -c" in inner


def test_run_native_rejects_unknown_enforcement_mode() -> None:
    sandbox = _FakeSandbox()
    hardening = _hardening("control")
    with pytest.raises(ValueError, match="enforcement_mode"):
        run_with_daytona_policy_hardening(
            sandbox,
            daytona_policy_hardening=hardening,
            command="claude -p run",
            cwd="/workspace",
            timeout=30,
            enforcement_mode="hybrid",
        )


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_inner_is_valid_bash(preset_name: str, tmp_path) -> None:
    _, inner, _ = _drive_native(preset_name)
    script = tmp_path / "inner.sh"
    script.write_text(inner)
    result = subprocess.run(
        ["bash", "-n", str(script)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("preset_name", _ALL_NATIVE_PRESETS)
def test_native_inner_has_no_broken_line_continuation(preset_name: str) -> None:
    _, inner, _ = _drive_native(preset_name)
    assert "\\\n\n" not in inner


def test_render_fs_readonly_setup_carves_config_declared_home_subdirs() -> None:
    from dataclasses import replace

    from boundarybench.daytona.daytona_policy_hardening import (
        _render_fs_readonly_setup,
    )

    base = build_daytona_config_from_axes(AXIS_PRESETS["high-nist"])
    assert base.f3_home_carveout_subdirs == (".claude", ".cache", ".config", ".local")
    config = replace(base, f3_home_carveout_subdirs=(".codex", ".cache"))
    out = _render_fs_readonly_setup(config, home="/home/daytona")
    assert "mkdir -p -- /home/daytona/.codex" in out
    assert "readlink -f -- /home/daytona/.codex" in out
    assert "chown --no-dereference daytona:daytona /home/daytona/.codex" in out
    assert "/home/daytona/.claude" not in out
