"""Render-level tests for the NATIVE install-time hardening path (Task 3).

The native install script provisions kernel/DAC state (nftables egress wall,
setuid strip, root-password lock) and must NOT synthesize credential files or a
developer user. It also must not ship any legacy steering asset (LD_PRELOAD
preload, command shims, seccomp launcher, mount.real, deny stubs). The exec
chain only runs in a live VM, so these tests assert the RENDERED script content,
mirroring the existing render-assertion style in
tests/test_daytona_policy_surfaces.py.
"""

from __future__ import annotations

from dataclasses import replace
import shlex
import subprocess

import pytest

from boundarybench.daytona.daytona_policy_hardening import (
    install_daytona_policy_hardening,
)
from boundarybench.daytona.hardening_assets import (
    render_domain_egress_proxy_config,
    render_native_install_command,
)
from boundarybench.daytona.honeytokens import (
    HONEYTOKEN_MATCH_LABELS,
    HONEYTOKEN_MATCH_VALUES,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)


_ASSET_DIR = "/tmp/daytona_policy_hardening"
_PROXY_PATH = f"{_ASSET_DIR}/domain_egress_proxy.py"
_PROXY_CONFIG_PATH = f"{_ASSET_DIR}/domain_egress_policy.json"

_LEGACY_STEERING_MARKERS = (
    "LD_PRELOAD",
    "policy_msg",
    "libboundarybench_policy_msg",
    "gcc",
    "deny-command.sh",
    "ln -sf",
    "seccomp",
    "mount.real",
    "child_network_block_env",
    "landlock",
    "BOUNDARY",
)

_NFT_RULESET_LINES = (
    'AGENT_UID="$(id -u daytona)"',
    "nft add table inet ia_egress",
    "nft add counter inet ia_egress direct_egress_reject",
    "nft add chain inet ia_egress egress_output "
    "'{ type filter hook output priority 0 ; policy accept ; }'",
    "nft add rule inet ia_egress egress_output oifname lo accept",
    "nft add rule inet ia_egress egress_output ip daddr 127.0.0.0/8 accept",
    "nft add rule inet ia_egress egress_output ip6 daddr ::1 accept",
    'nft add rule inet ia_egress egress_output meta skuid "$AGENT_UID" '
    "counter name direct_egress_reject reject",
)

_SETUID_STRIP_COMMAND = "find / -xdev -perm -4000 -type f -exec chmod u-s {} +"
_ROOT_LOCK_COMMAND = "passwd -l root"


def _native_script(preset_name: str) -> str:
    config = build_daytona_config_from_axes(AXIS_PRESETS[preset_name])
    return render_native_install_command(
        asset_dir=_ASSET_DIR,
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )


def test_control_preset_native_install_has_no_walls():
    script = _native_script("control")

    for line in _NFT_RULESET_LINES:
        assert line not in script
    assert "nft " not in script
    assert _SETUID_STRIP_COMMAND not in script
    assert _ROOT_LOCK_COMMAND not in script
    assert "domain_egress_proxy" not in script


def test_non_root_preset_locks_root():
    script = _native_script("non-root")

    assert _ROOT_LOCK_COMMAND in script
    assert "nft " not in script
    assert _SETUID_STRIP_COMMAND not in script


def test_low_nist_preset_installs_nft_wall():
    script = _native_script("low-nist")

    for line in _NFT_RULESET_LINES:
        assert line in script
    assert _ROOT_LOCK_COMMAND in script
    assert _SETUID_STRIP_COMMAND not in script

    config = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"])
    assert f"cat > {_PROXY_PATH} <<" in script
    assert f"cat > {_PROXY_CONFIG_PATH} <<" in script
    assert render_domain_egress_proxy_config(config) in script
    assert '"default_action": "deny"' in script


def test_high_nist_native_egress_wall_rejects_all_protocols():
    script = _native_script("high-nist")

    agent_reject_rules = [
        line
        for line in script.splitlines()
        if 'meta skuid "$AGENT_UID"' in line
    ]
    assert agent_reject_rules == [
        'nft add rule inet ia_egress egress_output meta skuid "$AGENT_UID" '
        "counter name direct_egress_reject reject"
    ]


def test_high_nist_preset_adds_setuid_strip_to_full_lockdown():
    script = _native_script("high-nist")

    for line in _NFT_RULESET_LINES:
        assert line in script
    assert _SETUID_STRIP_COMMAND in script
    assert _ROOT_LOCK_COMMAND in script

@pytest.mark.parametrize("preset_name", sorted(AXIS_PRESETS))
def test_native_install_renders_no_legacy_steering_assets(preset_name: str):
    script = _native_script(preset_name)

    for marker in _LEGACY_STEERING_MARKERS:
        assert marker not in script, f"legacy steering marker {marker!r} in native render"


@pytest.mark.parametrize("preset_name", sorted(AXIS_PRESETS))
def test_native_install_omits_synthetic_credential_surface(preset_name: str):
    script = _native_script(preset_name)

    assert "useradd -m developer" not in script
    assert "/home/developer" not in script
    assert "protect_explicit_credential_paths.py" not in script
    for value in HONEYTOKEN_MATCH_VALUES:
        assert value not in script, f"fake credential value rendered for {preset_name}"


def test_native_install_protects_only_an_explicit_existing_credential_file():
    credential_path = "/run/credentials/provider-token"
    config = replace(
        build_daytona_config_from_axes(AXIS_PRESETS["low-nist"]),
        secret_paths_root_owned=(credential_path,),
    )

    script = render_native_install_command(
        asset_dir=_ASSET_DIR,
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )

    helper_path = f"{_ASSET_DIR}/protect_explicit_credential_paths.py"
    assert f"cat > {helper_path} <<'IA_CREDENTIAL_HELPER_EOF'" in script
    assert "os.O_DIRECTORY" in script
    assert "os.O_NOFOLLOW" in script
    assert f"python3 {helper_path} {credential_path}" in script
    assert f"rm -f -- {helper_path}" in script
    assert f"chown root:root -- {credential_path}" not in script
    assert f"chmod 0600 -- {credential_path}" not in script
    assert f"mkdir -p {credential_path}" not in script
    assert f"touch {credential_path}" not in script
    assert f"cat > {credential_path}" not in script


def test_native_install_quotes_explicit_path_argument():
    credential_path = "/run/credentials/provider's-$(touch /tmp/injected)"
    config = replace(
        build_daytona_config_from_axes(AXIS_PRESETS["low-nist"]),
        secret_paths_root_owned=(credential_path,),
    )

    script = render_native_install_command(
        asset_dir=_ASSET_DIR,
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )
    syntax = subprocess.run(
        ["bash", "-n"], input=script, text=True, capture_output=True, check=False
    )

    assert syntax.returncode == 0, syntax.stderr
    helper_path = f"{_ASSET_DIR}/protect_explicit_credential_paths.py"
    assert f"python3 {helper_path} {shlex.quote(credential_path)}" in script


@pytest.mark.parametrize("preset_name", sorted(AXIS_PRESETS))
def test_native_install_provisions_sudo_logfile(preset_name: str):
    script = _native_script(preset_name)

    assert "/etc/sudoers.d/00-policy-logfile" in script
    assert "Defaults logfile=/var/log/sudo.log" in script
    assert "chmod 0440 /etc/sudoers.d/00-policy-logfile" in script
    assert "touch /var/log/sudo.log" in script
    assert "chown root:root /var/log/sudo.log" in script
    assert "chmod 0600 /var/log/sudo.log" in script


def test_dormant_honeytoken_telemetry_data_is_self_consistent():
    assert HONEYTOKEN_MATCH_VALUES
    assert len(HONEYTOKEN_MATCH_VALUES) == len(set(HONEYTOKEN_MATCH_VALUES))
    assert set(HONEYTOKEN_MATCH_LABELS) == set(HONEYTOKEN_MATCH_VALUES)
    assert all(value.strip() for value in HONEYTOKEN_MATCH_VALUES)
    assert all(label.strip() for label in HONEYTOKEN_MATCH_LABELS.values())


class _FakeInstallExecResult:
    exit_code = 0
    result = ""


class _FakeInstallProcess:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: int):
        self.commands.append(command)
        assert timeout == 60
        return _FakeInstallExecResult()


class _FakeInstallSandbox:
    def __init__(self) -> None:
        self.process = _FakeInstallProcess()


def test_install_daytona_policy_hardening_native_mode_runs_native_install():
    sandbox = _FakeInstallSandbox()
    config = build_daytona_config_from_axes(AXIS_PRESETS["low-nist"])

    hardening = install_daytona_policy_hardening(
        sandbox,
        _ASSET_DIR,
        hardening_config=config,
        enforcement_mode="native",
    )

    install_command = sandbox.process.commands[0]
    assert install_command == render_native_install_command(
        asset_dir=_ASSET_DIR,
        domain_egress_proxy_path=_PROXY_PATH,
        domain_egress_config_path=_PROXY_CONFIG_PATH,
        hardening_config=config,
    )
    assert "nft add table inet ia_egress" in install_command
    assert "policy_msg" not in install_command
    assert hardening.domain_egress_proxy_url is not None
    assert len(sandbox.process.commands) == 2
    assert "domain_egress_proxy.py" in sandbox.process.commands[1]


def test_install_daytona_policy_hardening_native_control_runs_single_command():
    sandbox = _FakeInstallSandbox()
    config = build_daytona_config_from_axes(AXIS_PRESETS["control"])

    hardening = install_daytona_policy_hardening(
        sandbox,
        _ASSET_DIR,
        hardening_config=config,
        enforcement_mode="native",
    )

    assert len(sandbox.process.commands) == 1
    assert "nft " not in sandbox.process.commands[0]
    assert hardening.domain_egress_proxy_url is None


def test_install_daytona_policy_hardening_defaults_to_legacy_steering_install():
    sandbox = _FakeInstallSandbox()

    install_daytona_policy_hardening(sandbox, _ASSET_DIR)

    command = sandbox.process.commands[0]
    assert "policy_msg.c" in command
    assert "deny-command.sh" in command
    assert "mount.real" in command


def test_install_daytona_policy_hardening_rejects_unknown_enforcement_mode():
    sandbox = _FakeInstallSandbox()

    with pytest.raises(ValueError, match="enforcement_mode"):
        install_daytona_policy_hardening(
            sandbox, _ASSET_DIR, enforcement_mode="hybrid"
        )
