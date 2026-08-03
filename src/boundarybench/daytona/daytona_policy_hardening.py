from __future__ import annotations

import os
import re
import secrets
import shlex
import tempfile
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any

from boundarybench.daytona.hardening_assets import (
    render_install_command,
    render_native_install_command,
    render_preload_c_source,
)
from boundarybench.daytona.hardening_config import (
    DEFAULT_DAYTONA_HARDENING_CONFIG,
    DaytonaHardeningConfig,
)
from boundarybench.daytona.script_assets import render_daytona_script
from boundarybench.harness.openrouter import ACCOUNTING_PROXY_PORT


DEFAULT_POLICY_BLOCK_MESSAGE = DEFAULT_DAYTONA_HARDENING_CONFIG.block_message
_PRELOAD_C_SOURCE = render_preload_c_source(DEFAULT_DAYTONA_HARDENING_CONFIG)
DEFAULT_DOMAIN_EGRESS_PROXY_HOST = "127.0.0.1"
DEFAULT_DOMAIN_EGRESS_PROXY_PORT = 18081
DEFAULT_AGENTSH_SERVER_PORT = 18080
DEFAULT_DOMAIN_EGRESS_NO_PROXY = "127.0.0.1,localhost,::1"
POLICY_EVENT_LOG = "/tmp/boundarybench-policy-events.jsonl"
PROXY_ACCESS_LOG = "/tmp/boundarybench-proxy-access.jsonl"

_SESSION_POLL_INTERVAL_SEC = 5
_SESSION_POLL_MAX_TRANSIENT_ERRORS = 12
_SESSION_POLL_TRANSIENT_ERROR_MARKERS = (
    "failed to resolve container ip",
    "failed to execute command",
    "connection reset",
    "temporarily unavailable",
    "service unavailable",
    "gateway timeout",
)

_SESSION_TIMEOUT_GRACE_SEC = 8
_POST_COMMAND_PROBE_TIMEOUT_SEC = 10
_AGENT_PID_NAMESPACE_FLAGS = "--pid --fork --mount-proc --kill-child=SIGKILL"
_AGENT_PID_NAMESPACE_MARKER_DIR = "/run/boundarybench/pidns"
_PID_NAMESPACE_ID_RE = re.compile(r"^pid:\[[0-9]+\]$")


@dataclass(frozen=True)
class _PidNamespaceConfirmation:
    marker_path: str
    token: str
    outer_namespace_id: str


def _require_agent_pid_namespace_support(sandbox: Any, *, use_sudo: bool) -> None:
    prefix = "sudo " if use_sudo else ""
    command = f"{prefix}unshare {_AGENT_PID_NAMESPACE_FLAGS} -- /bin/true"
    result = sandbox.process.exec(command, timeout=30)
    if getattr(result, "exit_code", None) != 0:
        output = getattr(result, "result", "") or getattr(result, "stderr", "") or ""
        raise RuntimeError(f"PID namespace isolation unavailable: {output}")


def _prepare_pid_namespace_confirmation(sandbox: Any) -> _PidNamespaceConfirmation:
    result = sandbox.process.exec("readlink /proc/self/ns/pid", timeout=30)
    outer_namespace_id = (getattr(result, "result", "") or "").strip()
    if getattr(result, "exit_code", None) != 0 or not _PID_NAMESPACE_ID_RE.fullmatch(
        outer_namespace_id
    ):
        raise RuntimeError("PID namespace isolation confirmation setup failed")
    return _PidNamespaceConfirmation(
        marker_path=f"{_AGENT_PID_NAMESPACE_MARKER_DIR}/{uuid.uuid4().hex}",
        token=secrets.token_hex(32),
        outer_namespace_id=outer_namespace_id,
    )


def _pid_namespace_marker_setup(confirmation: _PidNamespaceConfirmation) -> str:
    return (
        f"IA_PIDNS_TOKEN={confirmation.token}; "
        f"IA_PIDNS_MARKER={shlex.quote(confirmation.marker_path)}; "
        "umask 077; "
        f"mkdir -p -- {shlex.quote(_AGENT_PID_NAMESPACE_MARKER_DIR)}; "
        f"chmod 0700 -- {shlex.quote(_AGENT_PID_NAMESPACE_MARKER_DIR)}; "
        "printf '%s\\n%s\\n%s\\n' \"$IA_PIDNS_TOKEN\" \"$$\" "
        "\"$(readlink /proc/self/ns/pid)\" > \"$IA_PIDNS_MARKER\"; "
        "chown 0:0 -- \"$IA_PIDNS_MARKER\"; chmod 0400 -- \"$IA_PIDNS_MARKER\"; "
    )


def _confirm_pid_namespace(
    sandbox: Any, confirmation: _PidNamespaceConfirmation
) -> None:
    marker = shlex.quote(confirmation.marker_path)
    try:
        result = sandbox.process.exec(
            f"stat -c '%u %a' -- {marker} && cat -- {marker}", timeout=30
        )
        lines = (getattr(result, "result", "") or "").splitlines()
        valid = (
            getattr(result, "exit_code", None) == 0
            and len(lines) == 4
            and lines[0] == "0 400"
            and secrets.compare_digest(lines[1], confirmation.token)
            and lines[2] == "1"
            and _PID_NAMESPACE_ID_RE.fullmatch(lines[3]) is not None
            and lines[3] != confirmation.outer_namespace_id
        )
        if not valid:
            raise RuntimeError("PID namespace isolation confirmation failed")
    finally:
        try:
            sandbox.process.exec(f"rm -f -- {marker}", timeout=30)
        except Exception:
            pass


def _wrap_command_in_agent_pid_namespace(
    command: str, confirmation: _PidNamespaceConfirmation
) -> str:
    return (
        f"unshare {_AGENT_PID_NAMESPACE_FLAGS} -- "
        f"/bin/bash.real -lc "
        f"{shlex.quote(_pid_namespace_marker_setup(confirmation) + command)}"
    )

@dataclass(frozen=True)
class DaytonaPolicyHardening:
    """Controller-launched Daytona policy hardening assets."""

    asset_dir: str
    policy_message_preload_so: str
    block_message_command: str
    mount_real_path: str
    policy_bin_dir: str
    child_network_block_env: str
    landlock_mac_runner: str | None = ""
    seccomp_launcher_path: str = ""
    domain_egress_proxy_path: str | None = None
    domain_egress_config_path: str | None = None
    domain_egress_proxy_url: str | None = None
    domain_egress_proxy_log: str | None = None
    hardening_config: DaytonaHardeningConfig = DEFAULT_DAYTONA_HARDENING_CONFIG

    @property
    def block_message(self) -> str | None:
        return self.hardening_config.block_message

    def to_metadata(self) -> dict[str, Any]:
        return {
            "asset_dir": self.asset_dir,
            "policy_message_preload_so": self.policy_message_preload_so,
            "block_message_command": self.block_message_command,
            "mount_real_path": self.mount_real_path,
            "policy_bin_dir": self.policy_bin_dir,
            "child_network_block_env": self.child_network_block_env,
            "landlock_mac_runner": self.landlock_mac_runner,
            "seccomp_launcher_path": self.seccomp_launcher_path,
            "domain_egress_proxy_path": self.domain_egress_proxy_path,
            "domain_egress_config_path": self.domain_egress_config_path,
            "domain_egress_proxy_url": self.domain_egress_proxy_url,
            "domain_egress_proxy_log": self.domain_egress_proxy_log,
            "block_message": self.block_message,
            "hardening_config": self.hardening_config.to_metadata(),
        }


@dataclass(frozen=True)
class DaytonaCommandResult:
    exit_code: int | None
    stdout: str
    stderr: str = ""
    timed_out: bool = False
    session_id: str | None = None
    pid_namespace_isolation_applied: bool = False
    post_command_probe_output: str | None = None


def install_daytona_policy_hardening(
    sandbox: Any,
    asset_dir: str,
    *,
    block_message: str | None = None,
    hardening_config: DaytonaHardeningConfig | None = None,
    install_landlock_mac_runner: bool = True,
    enforcement_mode: str = "legacy",
) -> DaytonaPolicyHardening:
    """Install policy hardening assets in a Daytona sandbox.

    The policy hardening is launched by the Daytona controller, not from inside an
    AgentSH session. That keeps mount/network namespace setup available even
    when AgentSH correctly prevents privilege escalation inside the session.

    ``enforcement_mode`` selects the install script: the default ``"legacy"``
    installs the steering assets (LD_PRELOAD preload, command shims, deny
    stubs) exactly as before; ``"native"`` installs only kernel/DAC state
    (nftables egress wall, setuid strip, root lock)
    via :func:`render_native_install_command` — no steering assets at all.
    """

    if enforcement_mode not in ("legacy", "native"):
        raise ValueError(
            f"unknown enforcement_mode: {enforcement_mode!r} "
            "(expected 'legacy' or 'native')"
        )
    selected_config = hardening_config or DEFAULT_DAYTONA_HARDENING_CONFIG
    if block_message is not None:
        selected_config = selected_config.with_block_message(block_message)
    asset_dir = asset_dir.rstrip("/")
    daytona_policy_hardening = DaytonaPolicyHardening(
        asset_dir=asset_dir,
        policy_message_preload_so=f"{asset_dir}/libboundarybench_policy_msg.so",
        block_message_command=f"{asset_dir}/deny-command.sh",
        mount_real_path=f"{asset_dir}/mount.real",
        policy_bin_dir=f"{asset_dir}/bin",
        child_network_block_env=f"{asset_dir}/child_network_block_env",
        landlock_mac_runner=(
            f"{asset_dir}/landlock-mac-runner" if install_landlock_mac_runner else None
        ),
        seccomp_launcher_path=f"{asset_dir}/seccomp-launcher",
        domain_egress_proxy_path=f"{asset_dir}/domain_egress_proxy.py",
        domain_egress_config_path=f"{asset_dir}/domain_egress_policy.json",
        domain_egress_proxy_url=(
            f"http://{DEFAULT_DOMAIN_EGRESS_PROXY_HOST}:{DEFAULT_DOMAIN_EGRESS_PROXY_PORT}"
            if selected_config.domain_egress_enabled
            else None
        ),
        domain_egress_proxy_log=f"{asset_dir}/domain_egress_proxy.log",
        hardening_config=selected_config,
    )
    if enforcement_mode == "native":
        command = render_native_install_command(
            asset_dir=daytona_policy_hardening.asset_dir,
            domain_egress_proxy_path=daytona_policy_hardening.domain_egress_proxy_path
            or f"{asset_dir}/domain_egress_proxy.py",
            domain_egress_config_path=daytona_policy_hardening.domain_egress_config_path
            or f"{asset_dir}/domain_egress_policy.json",
            hardening_config=selected_config,
        )
    else:
        command = render_install_command(
            asset_dir=daytona_policy_hardening.asset_dir,
            policy_bin_dir=daytona_policy_hardening.policy_bin_dir,
            policy_message_preload_so=daytona_policy_hardening.policy_message_preload_so,
            block_message_command=daytona_policy_hardening.block_message_command,
            mount_real_path=daytona_policy_hardening.mount_real_path,
            child_network_block_env=daytona_policy_hardening.child_network_block_env,
            seccomp_launcher_path=daytona_policy_hardening.seccomp_launcher_path,
            domain_egress_proxy_path=daytona_policy_hardening.domain_egress_proxy_path
            or f"{asset_dir}/domain_egress_proxy.py",
            domain_egress_config_path=daytona_policy_hardening.domain_egress_config_path
            or f"{asset_dir}/domain_egress_policy.json",
            hardening_config=selected_config,
            install_landlock_mac_runner=install_landlock_mac_runner,
        )
    result = sandbox.process.exec(command, timeout=60)
    exit_code = getattr(result, "exit_code", None)
    output = getattr(result, "result", "") or ""
    if exit_code != 0:
        raise RuntimeError(f"failed to install Daytona policy hardening assets: {output}")
    if selected_config.domain_egress_enabled:
        _start_domain_egress_proxy(sandbox, daytona_policy_hardening)
    return daytona_policy_hardening


def wrap_command_for_agentsh_session(
    *,
    session_id: str,
    command: str,
    timeout_seconds: int,
) -> str:
    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id:
        raise ValueError("agentsh_session_id cannot be empty")
    normalized_timeout = int(timeout_seconds)
    if normalized_timeout <= 0:
        raise ValueError("agentsh timeout_seconds must be positive")
    client_timeout = normalized_timeout + 60
    return (
        f"/usr/bin/agentsh --client-timeout {client_timeout}s wrap "
        f"--session {shlex.quote(normalized_session_id)} --report=false -- "
        f"/bin/bash.real -lc {shlex.quote(command)}"
    )


def run_with_daytona_policy_hardening(
    sandbox: Any,
    *,
    daytona_policy_hardening: DaytonaPolicyHardening,
    command: str,
    cwd: str,
    workspace: str | None = None,
    timeout: int,
    isolate_network: bool = True,
    block_network: bool | None = None,
    block_child_shell_network: bool = False,
    full_mac_enforcement: bool = False,
    env: dict[str, str] | None = None,
    run_as_root: bool = False,
    short_command: bool = False,
    agentsh_session_id: str | None = None,
    capture_output_to_files: bool = False,
    enforcement_mode: str = "legacy",
    preserve_session: bool = False,
    session_id_prefix: str = "ia-agent-",
    post_command_probe: str | None = None,
    isolate_agent_pid_namespace: bool = False,
) -> DaytonaCommandResult:
    """Run a command under Daytona mount/network policy hardening controls.

    ``cwd`` is where the command starts; ``workspace`` is the directory tree
    the Landlock MAC policy grants write access to (defaults to ``cwd``).
    They differ when a task image's WORKDIR is a subdirectory of the task
    workspace: the agent starts in the subdirectory but must keep write
    access to the whole workspace.

    ``enforcement_mode`` selects the per-command exec chain. The default
    ``"legacy"`` renders ``run_policy_hardening.sh`` EXACTLY as before (every
    existing caller/test is unchanged). ``"native"`` renders the steering-free
    ``run_policy_hardening_native.sh`` — setpriv privilege-drop (+ P2 capability
    drop), real read-only bind-remounts for F1/F2, and a universal environment
    strip for canonical/controller credential names — and NONE of the legacy steering
    stages (no LD_PRELOAD, BOUNDARY_* env, policy-bin PATH prepend, mount.real
    deny-stubs, seccomp/landlock prefixes, child-network BASH_ENV, or AgentSH
    wrap).

    ``preserve_session`` leaves the Daytona session alive until sandbox cleanup,
    for commands whose background daemons must survive into a later verifier.
    ``session_id_prefix`` makes those deliberately persistent sessions auditable.
    """

    if enforcement_mode not in ("legacy", "native"):
        raise ValueError(
            f"unknown enforcement_mode: {enforcement_mode!r} "
            "(expected 'legacy' or 'native')"
        )
    if isolate_agent_pid_namespace:
        _require_agent_pid_namespace_support(sandbox, use_sudo=True)
        pid_namespace_confirmation = _prepare_pid_namespace_confirmation(sandbox)
    else:
        pid_namespace_confirmation = None
    if workspace is None:
        workspace = cwd
    if block_network is None:
        block_network = isolate_network
    cidr_egress = (
        bool(daytona_policy_hardening.hardening_config.egress_cidr_denylist)
        or daytona_policy_hardening.hardening_config.egress_cidr_default_action == "deny"
    )
    child_cidr_egress = bool(
        daytona_policy_hardening.hardening_config.egress_cidr_command_names
    )
    extra_env = {str(key): str(value) for key, value in (env or {}).items()}
    if daytona_policy_hardening.hardening_config.read_only_root:
        extra_env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    if daytona_policy_hardening.domain_egress_proxy_url:
        extra_env.update(
            _domain_proxy_env(daytona_policy_hardening.domain_egress_proxy_url)
        )
    for name in extra_env:
        _validate_env_name(name)

    if enforcement_mode == "native":
        stripped_names = frozenset(
            _native_stripped_env_names(
                daytona_policy_hardening.hardening_config
            )
        )
        extra_env = {
            name: value
            for name, value in extra_env.items()
            if name not in stripped_names
        }
        native_sudo_env_args = ""
        if extra_env:
            names = ",".join(sorted(extra_env))
            native_sudo_env_args = f"--preserve-env={shlex.quote(names)} "
        native_namespace_flags = "--mount --propagation=private"
        if isolate_agent_pid_namespace:
            native_namespace_flags = (
                f"{_AGENT_PID_NAMESPACE_FLAGS} {native_namespace_flags}"
            )
        inner = _render_native_inner(
            daytona_policy_hardening,
            command=command,
            cwd=cwd,
            run_as_root=run_as_root,
        )
        if pid_namespace_confirmation is not None:
            inner = _pid_namespace_marker_setup(pid_namespace_confirmation) + inner
        wrapped = (
            f"sudo {native_sudo_env_args}unshare {native_namespace_flags} -- "
            f"/bin/bash.real -euo pipefail -c {shlex.quote(inner)}"
        )
        return _run_command_with_deadline(
            sandbox,
            command=wrapped,
            env=extra_env,
            timeout=timeout,
            short_command=short_command,
            capture_output_to_files=capture_output_to_files,
            preserve_session=preserve_session,
            session_id_prefix=session_id_prefix,
            post_command_probe=post_command_probe,
            pid_namespace_confirmation=pid_namespace_confirmation,
        )

    namespace_flags = "--mount --propagation=private"
    if isolate_network:
        namespace_flags = f"--net {namespace_flags}"
    if isolate_agent_pid_namespace:
        namespace_flags = f"{_AGENT_PID_NAMESPACE_FLAGS} {namespace_flags}"
    sudo_env_args = ""
    if extra_env:
        names = ",".join(sorted(extra_env))
        sudo_env_args = f"--preserve-env={shlex.quote(names)} "

    denied_mounts = "\n".join(
        f"if [ -e {shlex.quote(path)} ]; then "
        f"{shlex.quote(daytona_policy_hardening.mount_real_path)} --bind "
        f"{shlex.quote(daytona_policy_hardening.block_message_command)} "
        f"{shlex.quote(path)}; fi"
        for path in daytona_policy_hardening.hardening_config.denied_exec_paths
    )
    stripped_env_args = "\n".join(
        f"    -u {shlex.quote(name)} \\"
        for name in daytona_policy_hardening.hardening_config.strip_env_vars
    ) or "    \\"
    command_prefix = ""
    if block_child_shell_network:
        command_prefix = f"/usr/bin/env BASH_ENV={shlex.quote(daytona_policy_hardening.child_network_block_env)} "
    command_to_run = f"cd {shlex.quote(cwd)} && {command_prefix}{command}"
    if agentsh_session_id is not None:
        command_to_run = wrap_command_for_agentsh_session(
            session_id=agentsh_session_id,
            command=command_to_run,
            timeout_seconds=timeout,
        )
    seccomp_prefix = ""
    if daytona_policy_hardening.hardening_config.seccomp_block_syscalls:
        seccomp_prefix = shlex.quote(daytona_policy_hardening.seccomp_launcher_path)
    if run_as_root:
        user_setup = ""
        exec_prefix = ""
        home = "/root"
        user = "root"
        logname = "root"
    else:
        user_setup = 'uid="$(id -u daytona)"\ngid="$(id -g daytona)"'
        exec_prefix = 'setpriv --reuid="$uid" --regid="$gid" --clear-groups'
        home = "/home/daytona"
        user = "daytona"
        logname = "daytona"
    landlock_prefix = ""
    if full_mac_enforcement:
        if not daytona_policy_hardening.landlock_mac_runner:
            raise RuntimeError("full_mac_enforcement requires landlock_mac_runner")
        landlock_prefix = " ".join(
            [
                shlex.quote(daytona_policy_hardening.landlock_mac_runner),
                "--workspace",
                shlex.quote(workspace),
                "--home",
                shlex.quote(home),
                "--tmp",
                "/tmp",
                "--allow-tcp-connect",
                "443",
                "--allow-tcp-connect",
                str(DEFAULT_AGENTSH_SERVER_PORT),
                "--allow-tcp-connect",
                str(DEFAULT_DOMAIN_EGRESS_PROXY_PORT),
                "--allow-tcp-connect",
                str(ACCOUNTING_PROXY_PORT),
                "--require-network",
                "--",
            ]
        )
    inner = render_daytona_script(
        "run_policy_hardening.sh",
        {
            "USER_SETUP": user_setup,
            "POLICY_BIN_DIR": shlex.quote(daytona_policy_hardening.policy_bin_dir),
            "DENIED_MOUNTS": denied_mounts,
            "EXEC_PREFIX": exec_prefix,
            "LANDLOCK_PREFIX": landlock_prefix,
            "STRIPPED_ENV_ARGS": stripped_env_args,
            "HOME": shlex.quote(home),
            "USER": shlex.quote(user),
            "LOGNAME": shlex.quote(logname),
            "POLICY_MESSAGE_PRELOAD_SO": shlex.quote(
                daytona_policy_hardening.policy_message_preload_so
            ),
            "SECCOMP_PREFIX": seccomp_prefix,
            "BLOCK_MESSAGE": shlex.quote(daytona_policy_hardening.block_message),
            "BLOCK_NETWORK": shlex.quote("1" if block_network else "0"),
            "CIDR_EGRESS": shlex.quote("1" if cidr_egress else "0"),
            "CHILD_BLOCK_NETWORK": shlex.quote(
                "1" if block_child_shell_network else "0"
            ),
            "CHILD_CIDR_EGRESS": shlex.quote("1" if child_cidr_egress else "0"),
            "COMMAND_TO_RUN": shlex.quote(command_to_run),
        },
    )
    if pid_namespace_confirmation is not None:
        inner = _pid_namespace_marker_setup(pid_namespace_confirmation) + inner
    wrapped = (
        f"sudo {sudo_env_args}unshare {namespace_flags} -- "
        f"/bin/bash.real -euo pipefail -c {shlex.quote(inner)}"
    )
    return _run_command_with_deadline(
        sandbox,
        command=wrapped,
        env=extra_env,
        timeout=timeout,
        short_command=short_command,
        capture_output_to_files=capture_output_to_files,
        preserve_session=preserve_session,
        session_id_prefix=session_id_prefix,
        post_command_probe=post_command_probe,
        pid_namespace_confirmation=pid_namespace_confirmation,
    )


NATIVE_AGENT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_NATIVE_RO_OS_TREES: tuple[str, ...] = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/opt",
    "/boot",
    "/srv",
    "/root",
    "/var",
    "/home",
)


def _render_fs_readonly_setup(
    hardening_config: DaytonaHardeningConfig, *, home: str
) -> str:
    """Render the F1/F2 read-only bind-remount stage (empty at F0/"guarded").

    Runs as root inside the pre-existing ``unshare --mount --propagation=private``
    namespace, BEFORE the setpriv drop. F0 (``open``) — and the generic
    caller-only ``guarded`` scope (conditional credential paths, no remount) —
    add nothing: a non-root agent already can't write the OS (native EACCES).
    F1 (``workspace``) remounts the OS trees read-only and carves the agent
    home + ``/var/tmp`` back to read-write; F2 (``read_only``) freezes the home
    tree too (no home / ``/var/tmp`` carveout). Carveouts follow the read-only
    pass so they win. Mount failures are NOT swallowed: if the read-only
    guarantee can't be established the run fails rather than silently running
    unhardened.
    """
    scope = hardening_config.filesystem_scope
    if scope in ("open", "guarded"):
        return ""
    lines: list[str] = []
    home_carveouts = (
        [f"{home}/{sub}" for sub in hardening_config.f3_home_carveout_subdirs]
        if scope == "read_only"
        else []
    )
    if home_carveouts:
        quoted_home = shlex.quote(home)
        lines.extend(
            (
                f"if [ -L {quoted_home} ]; then "
                f"echo 'refusing symlinked frozen home: {home}' >&2; exit 1; fi",
                f"if [ ! -d {quoted_home} ]; then "
                f"echo 'missing frozen-home directory: {home}' >&2; exit 1; fi",
                f"resolved_home=\"$(readlink -f -- {quoted_home})\"",
                f"if [ \"$resolved_home\" != {quoted_home} ]; then "
                f"echo 'frozen home escaped intended path: {home}' >&2; exit 1; fi",
            )
        )
    for path in home_carveouts:
        quoted_path = shlex.quote(path)
        lines.extend(
            (
                f"if [ -L {quoted_path} ]; then "
                f"echo 'refusing symlinked home carveout: {path}' >&2; exit 1; fi",
                f"mkdir -p -- {quoted_path}",
                f"resolved_carveout=\"$(readlink -f -- {quoted_path})\"",
                f"if [ \"$resolved_carveout\" != {quoted_path} ]; then "
                f"echo 'home carveout escaped intended path: {path}' >&2; exit 1; fi",
                f"chown --no-dereference daytona:daytona {quoted_path}",
            )
        )
    lines += [
        f"if [ -e {shlex.quote(tree)} ]; then "
        f"mount --bind {shlex.quote(tree)} {shlex.quote(tree)} && "
        f"mount -o remount,bind,ro {shlex.quote(tree)}; fi"
        for tree in _NATIVE_RO_OS_TREES
    ]
    if scope == "workspace":
        rw_carveouts = ["/var/tmp", home]
    else:
        rw_carveouts = home_carveouts
    for sub in rw_carveouts:
        quoted_sub = shlex.quote(sub)
        if scope == "read_only":
            lines.extend(
                (
                    f"if [ -L {quoted_sub} ]; then "
                    f"echo 'refusing symlinked F3 carveout: {sub}' >&2; exit 1; fi",
                    f"resolved_carveout=\"$(readlink -f -- {quoted_sub})\"",
                    f"if [ \"$resolved_carveout\" != {quoted_sub} ]; then "
                    f"echo 'F3 carveout escaped intended path: {sub}' >&2; exit 1; fi",
                    'mount --bind "$resolved_carveout" "$resolved_carveout" && '
                    'mount -o remount,bind,rw "$resolved_carveout"',
                )
            )
        else:
            lines.append(
                f"if [ -e {quoted_sub} ]; then "
                f"mount --bind {quoted_sub} {quoted_sub} && "
                f"mount -o remount,bind,rw {quoted_sub}; fi"
            )
    return "\n".join(lines)


def _native_stripped_env_names(
    hardening_config: DaytonaHardeningConfig,
) -> tuple[str, ...]:
    """Canonical plus configured strip names, deduplicated in stable order."""
    from boundarybench.daytona.policy_axes import CANONICAL_INFRA_KEY_ENV_NAMES

    return tuple(
        dict.fromkeys(
            (*CANONICAL_INFRA_KEY_ENV_NAMES, *hardening_config.strip_env_vars)
        )
    )


def _render_native_env_args(hardening_config: DaytonaHardeningConfig) -> str:
    """Render canonical and caller-configured strip operands."""

    return (
        "\n".join(
            f"    -u {shlex.quote(name)} \\"
            for name in _native_stripped_env_names(hardening_config)
        )
        or "    \\"
    )


def _render_native_inner(
    daytona_policy_hardening: DaytonaPolicyHardening,
    *,
    command: str,
    cwd: str,
    run_as_root: bool,
) -> str:
    """Render the native per-command inner script (no legacy steering stages)."""
    config = daytona_policy_hardening.hardening_config
    if run_as_root:
        user_setup = ""
        exec_prefix = ""
        home = "/root"
        user = "root"
        logname = "root"
    else:
        user_setup = 'uid="$(id -u daytona)"\ngid="$(id -g daytona)"'
        exec_prefix = 'setpriv --reuid="$uid" --regid="$gid" --clear-groups'
        if config.no_new_privs:
            exec_prefix += " --no-new-privs"
        if config.drop_bounding_caps:
            exec_prefix += " --bounding-set -all"
        home = "/home/daytona"
        user = "daytona"
        logname = "daytona"
    env_strip_args = _render_native_env_args(config)
    command_to_run = f"cd {shlex.quote(cwd)} && {command}"
    return render_daytona_script(
        "run_policy_hardening_native.sh",
        {
            "USER_SETUP": user_setup,
            "FS_READONLY_SETUP": _render_fs_readonly_setup(config, home=home),
            "EXEC_PREFIX": exec_prefix,
            "ENV_STRIP_ARGS": env_strip_args,
            "HOME": shlex.quote(home),
            "USER": shlex.quote(user),
            "LOGNAME": shlex.quote(logname),
            "PATH": shlex.quote(NATIVE_AGENT_PATH),
            "COMMAND_TO_RUN": shlex.quote(command_to_run),
        },
    )


def _start_domain_egress_proxy(
    sandbox: Any, daytona_policy_hardening: DaytonaPolicyHardening
) -> None:
    assert daytona_policy_hardening.domain_egress_proxy_path is not None
    assert daytona_policy_hardening.domain_egress_config_path is not None
    assert daytona_policy_hardening.domain_egress_proxy_log is not None
    command = (
        f"rm -f {shlex.quote(daytona_policy_hardening.domain_egress_proxy_log)}; "
        f"nohup python3 {shlex.quote(daytona_policy_hardening.domain_egress_proxy_path)} "
        f"--config {shlex.quote(daytona_policy_hardening.domain_egress_config_path)} "
        f"--host {shlex.quote(DEFAULT_DOMAIN_EGRESS_PROXY_HOST)} "
        f"--port {DEFAULT_DOMAIN_EGRESS_PROXY_PORT} "
        f"--event-log {shlex.quote(POLICY_EVENT_LOG)} "
        f"--access-log {shlex.quote(PROXY_ACCESS_LOG)} "
        f">{shlex.quote(daytona_policy_hardening.domain_egress_proxy_log)} 2>&1 & "
        "pid=$!; sleep 0.2; "
        f"if ! kill -0 \"$pid\" 2>/dev/null; then "
        f"cat {shlex.quote(daytona_policy_hardening.domain_egress_proxy_log)} >&2 || true; "
        "exit 1; fi"
    )
    result = sandbox.process.exec(command, timeout=60)
    exit_code = getattr(result, "exit_code", None)
    output = getattr(result, "result", "") or getattr(result, "stderr", "") or ""
    if exit_code != 0:
        raise RuntimeError(f"failed to start domain egress proxy: {output}")


def _domain_proxy_env(proxy_url: str) -> dict[str, str]:
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "all_proxy": proxy_url,
        "NO_PROXY": DEFAULT_DOMAIN_EGRESS_NO_PROXY,
        "no_proxy": DEFAULT_DOMAIN_EGRESS_NO_PROXY,
    }


def _run_command_with_deadline(
    sandbox: Any,
    *,
    command: str,
    env: dict[str, str],
    timeout: int,
    short_command: bool = False,
    capture_output_to_files: bool = False,
    preserve_session: bool = False,
    session_id_prefix: str = "ia-agent-",
    post_command_probe: str | None = None,
    isolate_agent_pid_namespace: bool = False,
    pid_namespace_confirmation: _PidNamespaceConfirmation | None = None,
) -> DaytonaCommandResult:
    """Run ``command`` and enforce ``timeout`` ourselves.

    Real Daytona sandboxes run the (potentially 20-minute) agent as an async
    session command and we poll for completion, so the deadline is enforced
    client-side regardless of Daytona's internal sync-exec ceiling. On timeout
    we still capture whatever the command produced (so the verifier can score
    the partial work and the transcript survives) and flag ``timed_out``.
    Fakes/sandboxes without the session API fall back to a single blocking exec.
    """

    if isolate_agent_pid_namespace:
        _require_agent_pid_namespace_support(sandbox, use_sudo=False)
        pid_namespace_confirmation = _prepare_pid_namespace_confirmation(sandbox)
        command = _wrap_command_in_agent_pid_namespace(
            command, pid_namespace_confirmation
        )

    process = sandbox.process
    if short_command:
        result = process.exec(command, timeout=timeout, env=env or None)
        command_result = DaytonaCommandResult(
            exit_code=getattr(result, "exit_code", None),
            stdout=getattr(result, "result", "") or "",
            stderr=getattr(result, "stderr", "") or "",
        )
        if pid_namespace_confirmation is not None:
            _confirm_pid_namespace(sandbox, pid_namespace_confirmation)
            command_result = replace(
                command_result, pid_namespace_isolation_applied=True
            )
        return command_result
    if not hasattr(process, "create_session"):
        result = process.exec(command, timeout=timeout + 60, env=env or None)
        command_result = DaytonaCommandResult(
            exit_code=getattr(result, "exit_code", None),
            stdout=getattr(result, "result", "") or "",
            stderr=getattr(result, "stderr", "") or "",
        )
        if pid_namespace_confirmation is not None:
            _confirm_pid_namespace(sandbox, pid_namespace_confirmation)
            command_result = replace(
                command_result, pid_namespace_isolation_applied=True
            )
        return command_result

    from daytona_sdk.common.process import SessionExecuteRequest

    session_id = session_id_prefix + uuid.uuid4().hex[:12]
    env_remote = "/tmp/boundarybench-agent-env.sh"
    capture_id = uuid.uuid4().hex[:12]
    stdout_remote = f"/tmp/boundarybench-agent-stdout-{capture_id}.log"
    stderr_remote = f"/tmp/boundarybench-agent-stderr-{capture_id}.log"
    setup = ""
    if env:
        lines = "".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items())
        fh = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        try:
            fh.write(lines)
            fh.close()
            sandbox.fs.upload_file(fh.name, env_remote)
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass
    try:
        if env:
            chmod_result = process.exec(
                f"chmod 600 {shlex.quote(env_remote)}", timeout=30
            )
            if getattr(chmod_result, "exit_code", None) != 0:
                output = (
                    getattr(chmod_result, "result", "")
                    or getattr(chmod_result, "stderr", "")
                    or ""
                )
                raise RuntimeError(
                    f"failed to secure remote agent environment: {output}"
                )
            setup = (
                f"set -a; . {shlex.quote(env_remote)} && "
                f"rm -f {shlex.quote(env_remote)} && set +a && "
            )
        process.create_session(session_id)
    except Exception:
        if env:
            _remove_remote_agent_env(process, env_remote)
        raise
    exit_code: int | None = None
    timed_out = False
    stdout = ""
    stderr = ""
    post_command_probe_output: str | None = None
    command_completed = False
    try:
        session_command = setup + command
        if capture_output_to_files:
            session_command = setup + _file_capture_command(
                command,
                stdout_remote=stdout_remote,
                stderr_remote=stderr_remote,
            )
        resp = process.execute_session_command(
            session_id,
            SessionExecuteRequest(command=session_command, run_async=True),
            timeout=60,
        )
        cmd_id = resp.cmd_id
        start = time.monotonic()
        consecutive_poll_errors = 0
        while True:
            try:
                info = process.get_session_command(session_id, cmd_id)
                consecutive_poll_errors = 0
            except Exception as exc:
                text = f"{type(exc).__name__}: {exc!r}".lower()
                if not any(
                    marker in text
                    for marker in _SESSION_POLL_TRANSIENT_ERROR_MARKERS
                ):
                    raise
                consecutive_poll_errors += 1
                if time.monotonic() - start > timeout:
                    timed_out = True
                    break
                if consecutive_poll_errors > _SESSION_POLL_MAX_TRANSIENT_ERRORS:
                    raise
                time.sleep(_SESSION_POLL_INTERVAL_SEC)
                continue
            if getattr(info, "exit_code", None) is not None:
                exit_code = int(info.exit_code)
                break
            if time.monotonic() - start > timeout:
                timed_out = True
                break
            time.sleep(_SESSION_POLL_INTERVAL_SEC)
        if timed_out:
            _signal_agent_process_tree(process, "-INT")
            time.sleep(_SESSION_TIMEOUT_GRACE_SEC)
            try:
                info = process.get_session_command(session_id, cmd_id)
                if getattr(info, "exit_code", None) is not None:
                    exit_code = int(info.exit_code)
                    timed_out = False
            except Exception:
                pass
            if timed_out:
                _signal_agent_process_tree(process, "-KILL")
        try:
            logs = process.get_session_command_logs(session_id, cmd_id)
            stdout = getattr(logs, "stdout", None) or getattr(logs, "output", "") or ""
            stderr = getattr(logs, "stderr", "") or ""
        except Exception:
            stdout = ""
            stderr = ""
        if capture_output_to_files:
            captured_stdout = _download_remote_text_file(sandbox, stdout_remote)
            captured_stderr = _download_remote_text_file(sandbox, stderr_remote)
            if captured_stdout is not None:
                stdout = captured_stdout
            if captured_stderr is not None:
                stderr = captured_stderr
        if post_command_probe is not None:
            try:
                probe = process.exec(
                    post_command_probe, timeout=_POST_COMMAND_PROBE_TIMEOUT_SEC
                )
                post_command_probe_output = getattr(probe, "result", "") or ""
            except Exception as exc:
                post_command_probe_output = f"probe-error: {exc!r}"
        command_completed = True
    finally:
        if not preserve_session or not command_completed:
            try:
                process.delete_session(session_id)
            except Exception:
                pass
        if env:
            _remove_remote_agent_env(process, env_remote)
        if capture_output_to_files:
            try:
                process.exec(
                    "rm -f "
                    f"{shlex.quote(stdout_remote)} {shlex.quote(stderr_remote)}",
                    timeout=15,
                )
            except Exception:
                pass
    command_result = DaytonaCommandResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        session_id=session_id,
        post_command_probe_output=post_command_probe_output,
    )
    if pid_namespace_confirmation is not None:
        _confirm_pid_namespace(sandbox, pid_namespace_confirmation)
        command_result = replace(command_result, pid_namespace_isolation_applied=True)
    return command_result


def _file_capture_command(
    command: str, *, stdout_remote: str, stderr_remote: str
) -> str:
    return (
        f"( : > {shlex.quote(stdout_remote)}; "
        f": > {shlex.quote(stderr_remote)}; "
        f"{command} > {shlex.quote(stdout_remote)} "
        f"2> {shlex.quote(stderr_remote)} )"
    )


def _remove_remote_agent_env(process: Any, env_remote: str) -> None:
    try:
        process.exec(f"rm -f {shlex.quote(env_remote)}", timeout=15)
    except Exception:
        pass


def _download_remote_text_file(sandbox: Any, remote_path: str) -> str | None:
    try:
        data = sandbox.fs.download_file(remote_path)
    except Exception:
        return None
    if data is None:
        return None
    if isinstance(data, str):
        return data
    return bytes(data).decode("utf-8", errors="replace")


def _signal_agent_process_tree(process: Any, signal: str) -> None:
    command = render_daytona_script(
        "signal_agent_process_tree.sh",
        {"SIGNAL": signal},
    )
    try:
        process.exec(command, timeout=20)
    except Exception:
        pass


def _validate_env_name(name: str) -> None:
    if not name or not (name[0].isalpha() or name[0] == "_"):
        raise ValueError(f"invalid environment variable name: {name!r}")
    if not all(part.isalnum() or part == "_" for part in name):
        raise ValueError(f"invalid environment variable name: {name!r}")
