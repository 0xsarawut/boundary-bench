"""A/B-boundary invariant: the NATIVE path is steering-free (Task 6, decision #8).

Tasks 3 and 4 each ship a per-file no-legacy test (native install in
tests/test_native_install.py, native exec in tests/test_native_exec_chain.py).
This module is the single consolidated contract that BOTH native surfaces — the
install-time script AND the per-command exec wrapper — invoke NONE of the legacy
"steering" stages, for all 8 axis presets at once.

Per decision #8 the legacy mechanisms (LD_PRELOAD preload, command/tee shims,
deny stubs, seccomp launcher, landlock runner, AgentSH wrap, DENIED_MOUNTS,
child-network BASH_ENV, the policy-bin PATH prepend) are RETAINED IN TREE but
UNWIRED, for a future old(steering)-vs-new(native) philosophy A/B benchmark.
This test is the executable statement of that boundary: retained, but never
reached by the native path.
"""

from __future__ import annotations

import pytest

from boundarybench.daytona.daytona_policy_hardening import (
    DaytonaPolicyHardening,
    run_with_daytona_policy_hardening,
)
from boundarybench.daytona.hardening_assets import (
    render_native_install_command,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    Privilege,
    build_daytona_config_from_axes,
)

_ASSET_DIR = "/tmp/native_no_legacy"
_PROXY_PATH = f"{_ASSET_DIR}/domain_egress_proxy.py"
_PROXY_CONFIG_PATH = f"{_ASSET_DIR}/domain_egress_policy.json"

_LEGACY_MARKERS = (
    "LD_PRELOAD",
    "BOUNDARY_",
    "policy_msg",
    "libboundarybench_policy_msg",
    "deny-command.sh",
    "seccomp",
    "landlock",
    "mount.real",
    "child_network_block_env",
    "BASH_ENV",
    "agentsh",
    "export PATH",
    f"{_ASSET_DIR}/bin",
)

_ALL_PRESETS = sorted(AXIS_PRESETS)


class _FakeExecResult:
    exit_code = 0
    result = ""
    stderr = ""


class _FakeProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def exec(
        self, command: str, *, timeout: int, env: dict[str, str] | None = None
    ) -> _FakeExecResult:
        self.commands.append(command)
        return _FakeExecResult()


class _FakeSandbox:
    def __init__(self) -> None:
        self.process = _FakeProcess()


def _legacy_asset_hardening(preset_name: str) -> DaytonaPolicyHardening:
    """A hardening object carrying the REAL legacy asset paths install would make.

    Populating every legacy field with its true value (the preload .so, the
    deny-command.sh stub, mount.real, the policy bin dir, the seccomp launcher,
    the landlock runner, child_network_block_env) is what makes the native
    no-legacy assertions load-bearing rather than vacuous: if the native exec
    chain ever touched a legacy stage, the corresponding marker would appear in
    the rendered command.
    """
    config = build_daytona_config_from_axes(AXIS_PRESETS[preset_name])
    return DaytonaPolicyHardening(
        asset_dir=_ASSET_DIR,
        policy_message_preload_so=f"{_ASSET_DIR}/libboundarybench_policy_msg.so",
        block_message_command=f"{_ASSET_DIR}/deny-command.sh",
        mount_real_path=f"{_ASSET_DIR}/mount.real",
        policy_bin_dir=f"{_ASSET_DIR}/bin",
        child_network_block_env=f"{_ASSET_DIR}/child_network_block_env",
        seccomp_launcher_path=f"{_ASSET_DIR}/seccomp-launcher",
        landlock_mac_runner=f"{_ASSET_DIR}/landlock-mac-runner",
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )


def _native_install_render(preset_name: str) -> str:
    config = build_daytona_config_from_axes(AXIS_PRESETS[preset_name])
    return render_native_install_command(
        asset_dir=_ASSET_DIR,
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )


def _native_exec_wrapped(preset_name: str) -> str:
    """Drive the native exec chain against a fake sandbox; return the wrapped cmd.

    ``run_as_root`` follows the privilege axis exactly like the exec-chain tests
    (P0 == the root control cell), mirroring Task 4's test helper.
    """
    sandbox = _FakeSandbox()
    hardening = _legacy_asset_hardening(preset_name)
    run_as_root = AXIS_PRESETS[preset_name].privilege == Privilege.P0
    run_with_daytona_policy_hardening(
        sandbox,
        daytona_policy_hardening=hardening,
        command="claude -p run",
        cwd="/workspace",
        timeout=30,
        isolate_network=True,
        run_as_root=run_as_root,
        enforcement_mode="native",
    )
    return sandbox.process.commands[0]


def test_axis_preset_roster_is_the_expected_seven() -> None:
    assert len(AXIS_PRESETS) == 7


@pytest.mark.parametrize("preset_name", _ALL_PRESETS)
def test_native_install_render_has_no_legacy_stage(preset_name: str) -> None:
    script = _native_install_render(preset_name)
    for marker in _LEGACY_MARKERS:
        assert marker not in script, (
            f"legacy marker {marker!r} leaked into native INSTALL for {preset_name}"
        )


@pytest.mark.parametrize("preset_name", _ALL_PRESETS)
def test_native_exec_render_has_no_legacy_stage(preset_name: str) -> None:
    wrapped = _native_exec_wrapped(preset_name)
    for marker in _LEGACY_MARKERS:
        assert marker not in wrapped, (
            f"legacy marker {marker!r} leaked into native EXEC for {preset_name}"
        )
