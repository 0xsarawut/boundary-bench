from __future__ import annotations


DEFAULT_AGENTSH_POLICY_DIR = "/tmp/boundarybench-agentsh-policy"
DEFAULT_AGENTSH_CONFIG_NAME = "boundarybench-agentsh-config.yaml"
AGENTSH_POLICY_SCHEMA_VERSION = "agentsh.policy.v1"
DEFAULT_AGENTSH_AUDIT_NAME = "audit.jsonl"

BASE_DENIED_SYSTEM_ADMIN_COMMANDS = (
    "shutdown",
    "reboot",
    "init",
    "poweroff",
    "halt",
    "systemctl",
    "service",
    "mount",
    "umount",
    "dd",
    "mkfs",
    "fdisk",
    "parted",
    "gdisk",
)
BASE_DENIED_PRIVILEGE_COMMANDS = ("sudo", "su", "chroot", "nsenter", "unshare")
BASE_DENIED_PRIVILEGE_SHELL_COMMANDS = ("sudo", "su")
BASE_DENIED_RAW_NETWORK_COMMANDS = ("nc", "netcat", "ncat", "socat", "telnet")
BASE_DENIED_DEBUG_COMMANDS = ("strace", "ltrace", "gdb", "ptrace")
BASE_DENIED_SYSTEM_INSTALLER_COMMANDS = (
    "apt",
    "apt-get",
    "dpkg",
    "yum",
    "dnf",
    "rpm",
    "snap",
    "flatpak",
    "brew",
)
BASE_DENIED_SYSTEM_INSTALLER_ARGS = ("install.*", "upgrade.*")
BASE_DENIED_SYSCTL_WRITE_COMMANDS = ("sysctl",)
BASE_DENIED_SYSCTL_WRITE_ARGS = ("-w.*", "--write.*")
BASE_DENIED_SERVICE_RESTART_COMMANDS = ("systemctl", "service")
BASE_DENIED_SERVICE_RESTART_ARGS = ("restart.*",)
BASE_DENIED_PRIVILEGE_SHELL_ARGS = ("-i.*", "-l.*", "-")
BASE_ALLOWED_COMMANDS = (
    "bash",
    "/bin/bash",
    "/usr/bin/bash",
    "bash.real",
    "/bin/bash.real",
    "/usr/bin/bash.real",
    "sh",
    "/bin/sh",
    "/usr/bin/sh",
    "sh.real",
    "/bin/sh.real",
    "/usr/bin/sh.real",
    "env",
    "/usr/bin/env",
    "echo",
    "pwd",
    "id",
    "whoami",
    "true",
    "false",
    "test",
    "[",
    "python",
    "python3",
    "agentsh",
    "/usr/bin/agentsh",
    "cat",
    "/usr/bin/cat",
    "chmod",
    "/usr/bin/chmod",
    "cp",
    "/usr/bin/cp",
    "find",
    "/usr/bin/find",
    "grep",
    "/usr/bin/grep",
    "head",
    "/usr/bin/head",
    "ln",
    "/usr/bin/ln",
    "mkdir",
    "/usr/bin/mkdir",
    "printf",
    "/usr/bin/printf",
    "tee",
    "/usr/bin/tee",
    "touch",
    "/usr/bin/touch",
    "tr",
    "/usr/bin/tr",
    "xargs",
    "/usr/bin/xargs",
)
