from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Literal


APPARMOR_CAPABILITY_SCHEMA_VERSION = 1
DEFAULT_APPARMOR_PROFILE_NAME = "boundarybench-agent"
DEFAULT_APPARMOR_PROBE_WORKSPACE = "/tmp/boundarybench-apparmor-probe"
DEFAULT_APPARMOR_DENIED_PATH = "/tmp/boundarybench-apparmor-denied/secret.txt"

AppArmorCapabilityStatus = Literal["enforced", "unsupported", "failed"]

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_APPARMOR_PATH_RE = re.compile(r"^/[A-Za-z0-9_./:-]+$")


@dataclass(frozen=True)
class AppArmorCommandEvidence:
    command_id: str
    command: str
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_metadata(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command": self.command,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": _compact_text(self.stdout),
            "stderr": _compact_text(self.stderr),
        }


@dataclass(frozen=True)
class AppArmorCapabilityProbeReport:
    profile_name: str
    workspace: str
    denied_path: str
    status: AppArmorCapabilityStatus
    unsupported_reason: str = ""
    profile_loaded: bool = False
    profile_attached: bool = False
    child_inherits_profile: bool = False
    denied_action_blocked: bool = False
    workspace_write_allowed: bool = False
    substrate: dict[str, str] = field(default_factory=dict)
    command_evidence: tuple[AppArmorCommandEvidence, ...] = ()

    @property
    def supported(self) -> bool:
        return self.status == "enforced"

    def to_metadata(self) -> dict[str, Any]:
        return {
            "schema_version": APPARMOR_CAPABILITY_SCHEMA_VERSION,
            "engine": "apparmor",
            "profile_name": self.profile_name,
            "workspace": self.workspace,
            "status": self.status,
            "supported": self.supported,
            "unsupported_reason": self.unsupported_reason or None,
            "profile_loaded": self.profile_loaded,
            "profile_attached": self.profile_attached,
            "child_inherits_profile": self.child_inherits_profile,
            "denied_action_blocked": self.denied_action_blocked,
            "workspace_write_allowed": self.workspace_write_allowed,
            "denied_action": {
                "kind": "file_read",
                "path": self.denied_path,
                "expected": "blocked",
                "blocked": self.denied_action_blocked,
            },
            "substrate": dict(self.substrate),
            "command_evidence": [
                command.to_metadata() for command in self.command_evidence
            ],
        }


def run_apparmor_capability_probe(
    sandbox: Any,
    *,
    profile_name: str = DEFAULT_APPARMOR_PROFILE_NAME,
    workspace: str = DEFAULT_APPARMOR_PROBE_WORKSPACE,
    denied_path: str = DEFAULT_APPARMOR_DENIED_PATH,
    timeout_seconds: int = 30,
) -> AppArmorCapabilityProbeReport:
    """Probe whether the sandbox can load and attach an AppArmor profile.

    This is a capability spike. It records proof that AppArmor is available,
    but it does not change the catalog support status for full MAC enforcement.
    """

    _validate_profile_name(profile_name)
    _validate_absolute_path(workspace, field_name="workspace")
    _validate_absolute_path(denied_path, field_name="denied_path")

    evidence: list[AppArmorCommandEvidence] = []
    substrate = _exec(
        sandbox,
        command_id="substrate",
        command=_substrate_command(),
        timeout=timeout_seconds,
    )
    evidence.append(substrate)
    substrate_details = _parse_key_value_stdout(substrate.stdout)

    unsupported_reason = _substrate_unsupported_reason(
        substrate,
        substrate_details,
    )
    if unsupported_reason:
        return _report(
            profile_name=profile_name,
            workspace=workspace,
            denied_path=denied_path,
            status="unsupported",
            unsupported_reason=unsupported_reason,
            substrate=substrate_details,
            evidence=evidence,
        )

    profile_path = f"{workspace.rstrip('/')}/{profile_name}.apparmor"
    profile_source = render_apparmor_probe_profile(
        profile_name=profile_name,
        workspace=workspace,
        denied_path=denied_path,
    )
    prepare = _exec(
        sandbox,
        command_id="write_profile",
        command=_write_profile_command(
            workspace=workspace,
            denied_path=denied_path,
            profile_path=profile_path,
            profile_source=profile_source,
        ),
        timeout=timeout_seconds,
    )
    evidence.append(prepare)
    if not prepare.passed:
        return _failed_report(
            "failed to write AppArmor probe profile and fixtures",
            profile_name=profile_name,
            workspace=workspace,
            denied_path=denied_path,
            substrate=substrate_details,
            evidence=evidence,
        )

    load = _exec(
        sandbox,
        command_id="load_profile",
        command=(
            f"apparmor_parser -r {shlex.quote(profile_path)} 2>&1"
        ),
        timeout=timeout_seconds,
    )
    evidence.append(load)
    if not load.passed:
        return _failed_report(
            "apparmor_parser failed to load the probe profile",
            profile_name=profile_name,
            workspace=workspace,
            denied_path=denied_path,
            substrate=substrate_details,
            evidence=evidence,
        )

    loaded = _exec(
        sandbox,
        command_id="profile_loaded",
        command=(
            "grep -F -- "
            f"{shlex.quote(profile_name)} "
            "/sys/kernel/security/apparmor/profiles"
        ),
        timeout=timeout_seconds,
    )
    evidence.append(loaded)
    profile_loaded = _output_mentions_profile(loaded.stdout, profile_name)

    attached = _exec(
        sandbox,
        command_id="attached_profile",
        command=(
            f"aa-exec -p {shlex.quote(profile_name)} -- "
            "sh -c 'cat /proc/self/attr/current'"
        ),
        timeout=timeout_seconds,
    )
    evidence.append(attached)
    profile_attached = _output_mentions_profile(attached.stdout, profile_name)

    child = _exec(
        sandbox,
        command_id="child_inherits_profile",
        command=(
            f"aa-exec -p {shlex.quote(profile_name)} -- "
            "sh -c 'printf \"CHILD_APPARMOR_CURRENT=\"; "
            "sh -c \"cat /proc/self/attr/current\"'"
        ),
        timeout=timeout_seconds,
    )
    evidence.append(child)
    child_inherits_profile = _output_mentions_profile(child.stdout, profile_name)

    denied = _exec(
        sandbox,
        command_id="denied_file_read",
        command=(
            f"aa-exec -p {shlex.quote(profile_name)} -- "
            f"sh -c 'cat {shlex.quote(denied_path)} >/dev/null'"
        ),
        timeout=timeout_seconds,
    )
    evidence.append(denied)
    denied_action_blocked = denied.exit_code not in {0, None} and not denied.timed_out

    allowed = _exec(
        sandbox,
        command_id="workspace_allowed_write",
        command=(
            f"aa-exec -p {shlex.quote(profile_name)} -- "
            "sh -c "
            + shlex.quote(
                "tmp="
                f"{workspace.rstrip('/')}/apparmor-allowed.$$; "
                "trap 'rm -f \"$tmp\"' EXIT; "
                "printf ok > \"$tmp\" && cat \"$tmp\""
            )
        ),
        timeout=timeout_seconds,
    )
    evidence.append(allowed)
    workspace_write_allowed = allowed.passed and "ok" in allowed.stdout

    cleanup = _exec(
        sandbox,
        command_id="cleanup_profile",
        command=f"apparmor_parser -R {shlex.quote(profile_path)} 2>&1",
        timeout=timeout_seconds,
    )
    evidence.append(cleanup)

    status: AppArmorCapabilityStatus = (
        "enforced"
        if (
            profile_loaded
            and profile_attached
            and child_inherits_profile
            and denied_action_blocked
            and workspace_write_allowed
        )
        else "failed"
    )
    unsupported = "" if status == "enforced" else "AppArmor capability proof was incomplete"
    return _report(
        profile_name=profile_name,
        workspace=workspace,
        denied_path=denied_path,
        status=status,
        unsupported_reason=unsupported,
        profile_loaded=profile_loaded,
        profile_attached=profile_attached,
        child_inherits_profile=child_inherits_profile,
        denied_action_blocked=denied_action_blocked,
        workspace_write_allowed=workspace_write_allowed,
        substrate=substrate_details,
        evidence=evidence,
    )


def render_apparmor_probe_profile(
    *,
    profile_name: str = DEFAULT_APPARMOR_PROFILE_NAME,
    workspace: str = DEFAULT_APPARMOR_PROBE_WORKSPACE,
    denied_path: str = DEFAULT_APPARMOR_DENIED_PATH,
) -> str:
    _validate_profile_name(profile_name)
    _validate_absolute_path(workspace, field_name="workspace")
    _validate_absolute_path(denied_path, field_name="denied_path")
    workspace_glob = f"{workspace.rstrip('/')}/**"
    denied_rule_path = denied_path
    return "\n".join(
        [
            "#include <tunables/global>",
            "",
            f"profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{",
            "  #include <abstractions/base>",
            "",
            "  file,",
            "  network,",
            "  capability,",
            "",
            f"  deny {denied_rule_path} r,",
            "",
            f"  {workspace_glob} rwkl,",
            f"  owner {workspace_glob} rwkl,",
            "  /tmp/** rwkl,",
            "  owner /tmp/** rwkl,",
            "  /dev/null rw,",
            "  /dev/urandom r,",
            "  /etc/ld.so.cache r,",
            "  /etc/nsswitch.conf r,",
            "  /etc/passwd r,",
            "  /etc/group r,",
            "  /proc/** r,",
            "  /bin/** ix,",
            "  /usr/bin/** ix,",
            "  /lib/** mr,",
            "  /lib64/** mr,",
            "  /usr/lib/** mr,",
            "}",
            "",
        ]
    )


def unique_apparmor_probe_profile_name(
    prefix: str = DEFAULT_APPARMOR_PROFILE_NAME,
) -> str:
    _validate_profile_name(prefix)
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _report(
    *,
    profile_name: str,
    workspace: str,
    denied_path: str,
    status: AppArmorCapabilityStatus,
    unsupported_reason: str = "",
    profile_loaded: bool = False,
    profile_attached: bool = False,
    child_inherits_profile: bool = False,
    denied_action_blocked: bool = False,
    workspace_write_allowed: bool = False,
    substrate: dict[str, str],
    evidence: list[AppArmorCommandEvidence],
) -> AppArmorCapabilityProbeReport:
    return AppArmorCapabilityProbeReport(
        profile_name=profile_name,
        workspace=workspace,
        denied_path=denied_path,
        status=status,
        unsupported_reason=unsupported_reason,
        profile_loaded=profile_loaded,
        profile_attached=profile_attached,
        child_inherits_profile=child_inherits_profile,
        denied_action_blocked=denied_action_blocked,
        workspace_write_allowed=workspace_write_allowed,
        substrate=substrate,
        command_evidence=tuple(evidence),
    )


def _failed_report(
    reason: str,
    *,
    profile_name: str,
    workspace: str,
    denied_path: str,
    substrate: dict[str, str],
    evidence: list[AppArmorCommandEvidence],
) -> AppArmorCapabilityProbeReport:
    return _report(
        profile_name=profile_name,
        workspace=workspace,
        denied_path=denied_path,
        status="failed",
        unsupported_reason=reason,
        substrate=substrate,
        evidence=evidence,
    )


def _exec(
    sandbox: Any,
    *,
    command_id: str,
    command: str,
    timeout: int,
) -> AppArmorCommandEvidence:
    try:
        result = sandbox.process.exec(command, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - preserve probe evidence
        return AppArmorCommandEvidence(
            command_id=command_id,
            command=command,
            exit_code=None,
            stderr=repr(exc),
        )
    return AppArmorCommandEvidence(
        command_id=command_id,
        command=command,
        exit_code=getattr(result, "exit_code", None),
        stdout=getattr(result, "result", "") or "",
        stderr=getattr(result, "stderr", "") or "",
        timed_out=bool(getattr(result, "timed_out", False)),
    )


def _substrate_command() -> str:
    return "\n".join(
        [
            "printf 'LSM=%s\\n' \"$(cat /sys/kernel/security/lsm 2>/dev/null || true)\"",
            "printf 'APPARMOR_ENABLED=%s\\n' \"$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true)\"",
            "if test -r /sys/kernel/security/apparmor/profiles; then profiles_readable=yes; else profiles_readable=no; fi",
            "printf 'PROFILES_READABLE=%s\\n' \"$profiles_readable\"",
            "printf 'CURRENT=%s\\n' \"$(cat /proc/self/attr/current 2>/dev/null || true)\"",
            "printf 'APPARMOR_PARSER=%s\\n' \"$(command -v apparmor_parser 2>/dev/null || true)\"",
            "printf 'AA_EXEC=%s\\n' \"$(command -v aa-exec 2>/dev/null || true)\"",
            "printf 'AA_STATUS=%s\\n' \"$(command -v aa-status 2>/dev/null || true)\"",
        ]
    )


def _write_profile_command(
    *,
    workspace: str,
    denied_path: str,
    profile_path: str,
    profile_source: str,
) -> str:
    denied_parent = str(PurePosixPath(denied_path).parent)
    return (
        f"install -d -m 1777 {shlex.quote(workspace)} "
        f"{shlex.quote(denied_parent)} && "
        f"printf apparmor-secret > {shlex.quote(denied_path)} && "
        f"chmod 0644 {shlex.quote(denied_path)} && "
        f"cat > {shlex.quote(profile_path)} <<'EOF'\n"
        f"{profile_source}"
        "EOF\n"
    )


def _substrate_unsupported_reason(
    substrate: AppArmorCommandEvidence,
    details: dict[str, str],
) -> str:
    if not substrate.passed:
        return "AppArmor substrate inspection command failed"
    missing_tools = [
        name
        for name, key in (
            ("apparmor_parser", "APPARMOR_PARSER"),
            ("aa-exec", "AA_EXEC"),
        )
        if not details.get(key)
    ]
    if missing_tools:
        return "AppArmor tools unavailable: " + ", ".join(missing_tools)
    lsm = details.get("LSM", "")
    enabled = details.get("APPARMOR_ENABLED", "").strip().upper()
    if "apparmor" not in lsm.lower() and enabled not in {"Y", "YES", "1", "TRUE"}:
        return "AppArmor is not enabled in the sandbox kernel/LSM view"
    if details.get("PROFILES_READABLE") != "yes":
        return "AppArmor profile list is not readable from the sandbox"
    return ""


def _parse_key_value_stdout(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _output_mentions_profile(stdout: str, profile_name: str) -> bool:
    return profile_name in stdout and "enforce" in stdout.lower()


def _validate_profile_name(profile_name: str) -> None:
    if not _PROFILE_NAME_RE.match(profile_name):
        raise ValueError("AppArmor profile_name must contain only safe profile characters")


def _validate_absolute_path(path: str, *, field_name: str) -> None:
    if not _APPARMOR_PATH_RE.match(path):
        raise ValueError(
            f"AppArmor {field_name} must be an absolute path with safe characters"
        )


def _compact_text(value: str, *, limit: int = 2000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
