from __future__ import annotations

import ipaddress
import json
import posixpath
import shlex

from boundarybench.daytona.hardening_config import DaytonaHardeningConfig
from boundarybench.daytona.script_assets import (
    read_daytona_script,
    render_daytona_script,
)


def render_install_command(
    *,
    asset_dir: str,
    policy_bin_dir: str,
    policy_message_preload_so: str,
    block_message_command: str,
    mount_real_path: str,
    child_network_block_env: str,
    seccomp_launcher_path: str,
    domain_egress_proxy_path: str,
    domain_egress_config_path: str,
    hardening_config: DaytonaHardeningConfig,
    install_landlock_mac_runner: bool = True,
) -> str:
    c_source_path = f"{asset_dir}/policy_msg.c"
    landlock_c_source_path = f"{asset_dir}/landlock_mac_runner.c"
    seccomp_source_path = f"{asset_dir}/seccomp-launcher.c"
    return render_daytona_script(
        "install_policy_hardening.sh",
        {
            "ASSET_DIR": shlex.quote(asset_dir),
            "POLICY_BIN_DIR": shlex.quote(policy_bin_dir),
            "C_SOURCE_PATH": shlex.quote(c_source_path),
            "PRELOAD_C_SOURCE": render_preload_c_source(hardening_config),
            "POLICY_MESSAGE_PRELOAD_SO": shlex.quote(policy_message_preload_so),
            "LANDLOCK_C_SOURCE_PATH": shlex.quote(landlock_c_source_path),
            "LANDLOCK_C_SOURCE": (
                render_landlock_mac_runner_c_source()
                if install_landlock_mac_runner
                else ""
            ),
            "LANDLOCK_MAC_RUNNER": shlex.quote(f"{asset_dir}/landlock-mac-runner"),
            "LANDLOCK_ENABLED": "1" if install_landlock_mac_runner else "0",
            "SECCOMP_ENABLED": "1" if hardening_config.seccomp_block_syscalls else "0",
            "SECCOMP_SOURCE_PATH": shlex.quote(seccomp_source_path),
            "SECCOMP_C_SOURCE": render_seccomp_launcher_c_source(hardening_config),
            "SECCOMP_LAUNCHER_PATH": shlex.quote(seccomp_launcher_path),
            "MOUNT_REAL_PATH": shlex.quote(mount_real_path),
            "BLOCK_MESSAGE_COMMAND": shlex.quote(block_message_command),
            "DENY_COMMAND_SCRIPT": read_daytona_script("deny_command.sh").strip(),
            "COMMAND_NAME_SHIMS": _render_command_name_shims(
                policy_bin_dir,
                block_message_command,
                hardening_config,
            ),
            "TEE_SHIM_PATH": shlex.quote(f"{policy_bin_dir}/tee"),
            "TEE_SHIM_SCRIPT": render_daytona_script(
                "tee_shim.sh",
                {"TEE_CASES": _render_tee_cases(hardening_config)},
            ),
            "CHILD_NETWORK_BLOCK_ENV": shlex.quote(child_network_block_env),
            "CHILD_NETWORK_BLOCK_ENV_SCRIPT": read_daytona_script(
                "child_network_block_env.sh"
            ).strip(),
            "DOMAIN_EGRESS_PROXY_PATH": shlex.quote(domain_egress_proxy_path),
            "DOMAIN_EGRESS_PROXY_SCRIPT": read_daytona_script(
                "domain_egress_proxy.py"
            ).strip(),
            "DOMAIN_EGRESS_CONFIG_PATH": shlex.quote(domain_egress_config_path),
            "DOMAIN_EGRESS_PROXY_CONFIG": render_domain_egress_proxy_config(
                hardening_config
            ),
        },
    )


def render_seccomp_launcher_c_source(hardening_config: DaytonaHardeningConfig) -> str:
    return _SECCOMP_LAUNCHER_C_TEMPLATE.replace(
        "__SECCOMP_RULES__",
        _render_seccomp_rules(hardening_config.seccomp_block_syscalls),
    )


def render_preload_c_source(hardening_config: DaytonaHardeningConfig) -> str:
    return _PRELOAD_C_TEMPLATE.format(
        read_only_root_enabled="true" if hardening_config.read_only_root else "false",
        denied_path_exact=_render_c_string_array(
            "DENIED_PATH_EXACT",
            hardening_config.denied_path_exact,
        ),
        denied_path_prefixes=_render_c_string_array(
            "DENIED_PATH_PREFIXES",
            hardening_config.denied_path_prefixes,
        ),
        child_network_commands=_render_c_string_array(
            "CHILD_NETWORK_COMMANDS",
            hardening_config.child_network_command_names,
        ),
        egress_cidr_commands=_render_c_string_array(
            "CIDR_EGRESS_COMMANDS",
            hardening_config.egress_cidr_command_names,
        ),
        egress_cidr_denylist=_render_cidr_rules(
            "EGRESS_CIDR_DENYLIST",
            hardening_config.egress_cidr_denylist,
        ),
        egress_cidr_allowlist=_render_cidr_rules(
            "EGRESS_CIDR_ALLOWLIST",
            hardening_config.egress_cidr_allowlist,
        ),
        egress_cidr_default_deny=(
            "1" if hardening_config.egress_cidr_default_action == "deny" else "0"
        ),
        writable_path_exact=_render_c_string_array(
            "WRITABLE_PATH_EXACT",
            hardening_config.writable_path_exact,
        ),
        writable_path_prefixes=_render_c_string_array(
            "WRITABLE_PATH_PREFIXES",
            hardening_config.writable_path_prefixes,
        ),
    )

def render_landlock_mac_runner_c_source() -> str:
    return _LANDLOCK_MAC_RUNNER_C_SOURCE


def render_domain_egress_proxy_config(
    hardening_config: DaytonaHardeningConfig,
) -> str:
    payload = {
        "allowlist": list(hardening_config.egress_domain_allowlist),
        "denylist": list(hardening_config.egress_domain_denylist),
        "default_action": hardening_config.egress_domain_default_action,
        "cidr_allowlist": list(hardening_config.egress_cidr_allowlist),
        "cidr_denylist": list(hardening_config.egress_cidr_denylist),
        "cidr_default_action": hardening_config.egress_cidr_default_action,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_native_install_command(
    *,
    asset_dir: str,
    domain_egress_proxy_path: str,
    domain_egress_config_path: str,
    hardening_config: DaytonaHardeningConfig,
) -> str:
    """Render the NATIVE install-time hardening script (run once as root).

    Native enforcement provisions only kernel/DAC state: the domain-egress
    proxy assets, the uid-scoped nftables egress wall, protection for explicitly
    supplied existing credential files, the setuid-bit strip, and the
    root-password lock. It deliberately creates no credential files and NONE of
    the legacy steering assets (LD_PRELOAD preload, command shims, seccomp
    launcher, mount.real, deny stubs) — the agent must only ever see native
    errors (Connection refused, EACCES, EPERM, sudoers/su failures).
    """
    return render_daytona_script(
        "install_policy_hardening_native.sh",
        {
            "ASSET_DIR": shlex.quote(asset_dir),
            "DOMAIN_EGRESS_PROXY_BLOCK": _render_native_domain_egress_proxy_block(
                domain_egress_proxy_path,
                domain_egress_config_path,
                hardening_config,
            ),
            "NATIVE_EGRESS_REJECT_BLOCK": (
                _NATIVE_EGRESS_NFT_BLOCK
                if hardening_config.native_egress_reject
                else ""
            ),
            "EXPLICIT_CREDENTIAL_PATHS_BLOCK": (
                _render_explicit_credential_paths_block(
                    asset_dir=asset_dir,
                    hardening_config=hardening_config,
                )
            ),
            "STRIP_SETUID_BLOCK": (
                _NATIVE_STRIP_SETUID_COMMAND if hardening_config.strip_setuid else ""
            ),
            "LOCK_ROOT_PASSWORD_BLOCK": (
                _NATIVE_LOCK_ROOT_COMMAND
                if hardening_config.lock_root_password
                else ""
            ),
        },
    )


_NATIVE_EGRESS_NFT_BLOCK = """\
AGENT_UID="$(id -u daytona)"
nft add table inet ia_egress
nft add counter inet ia_egress direct_egress_reject
nft add chain inet ia_egress egress_output '{ type filter hook output priority 0 ; policy accept ; }'
nft add rule inet ia_egress egress_output oifname lo accept
nft add rule inet ia_egress egress_output ip daddr 127.0.0.0/8 accept
nft add rule inet ia_egress egress_output ip6 daddr ::1 accept
nft add rule inet ia_egress egress_output meta skuid "$AGENT_UID" counter name direct_egress_reject reject"""

_NATIVE_STRIP_SETUID_COMMAND = "find / -xdev -perm -4000 -type f -exec chmod u-s {} +"

_NATIVE_LOCK_ROOT_COMMAND = "passwd -l root"


def _render_explicit_credential_paths_block(
    *, asset_dir: str, hardening_config: DaytonaHardeningConfig
) -> str:
    """Render the packaged dir-fd credential protector only when configured."""

    paths = hardening_config.secret_paths_root_owned
    if not paths:
        return ""
    helper_path = posixpath.join(asset_dir, "protect_explicit_credential_paths.py")
    quoted_helper = shlex.quote(helper_path)
    quoted_paths = " ".join(shlex.quote(path) for path in paths)
    return "\n".join(
        (
            f"cat > {quoted_helper} <<'IA_CREDENTIAL_HELPER_EOF'",
            read_daytona_script("protect_explicit_credential_paths.py").strip(),
            "IA_CREDENTIAL_HELPER_EOF",
            f"chmod 0500 -- {quoted_helper}",
            f"python3 {quoted_helper} {quoted_paths}",
            f"rm -f -- {quoted_helper}",
        )
    )


def _render_native_domain_egress_proxy_block(
    domain_egress_proxy_path: str,
    domain_egress_config_path: str,
    hardening_config: DaytonaHardeningConfig,
) -> str:
    if not hardening_config.domain_egress_enabled:
        return ""
    return "\n".join(
        [
            f"cat > {shlex.quote(domain_egress_proxy_path)} <<'EOF'",
            read_daytona_script("domain_egress_proxy.py").strip(),
            "EOF",
            f"chmod 0555 {shlex.quote(domain_egress_proxy_path)}",
            f"cat > {shlex.quote(domain_egress_config_path)} <<'EOF'",
            render_domain_egress_proxy_config(hardening_config),
            "EOF",
            f"chmod 0444 {shlex.quote(domain_egress_config_path)}",
        ]
    )


def _render_command_name_shims(
    policy_bin_dir: str,
    block_message_command: str,
    hardening_config: DaytonaHardeningConfig,
) -> str:
    lines = []
    for name in hardening_config.denied_command_names:
        lines.append(
            f"ln -sf {shlex.quote(block_message_command)} "
            f"{shlex.quote(f'{policy_bin_dir}/{name}')}"
        )
    return "\n".join(lines)


def _render_tee_cases(hardening_config: DaytonaHardeningConfig) -> str:
    lines: list[str] = []
    for pattern in hardening_config.tee_denied_patterns:
        lines.extend(
            [
                f"    {pattern})",
                "      emit_tee_policy_block \"$arg\"",
                "      printf '%s\\n' \"${BOUNDARY_POLICY_BLOCK_MESSAGE:-Permission denied}\" >&2",
                "      exit 1",
                "      ;;",
            ]
        )
    return "\n".join(lines)


def _render_seccomp_rules(syscalls: tuple[str, ...]) -> str:
    lines: list[str] = []
    for syscall in syscalls:
        lines.append(
            "    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), "
            f"SCMP_SYS({syscall}), 0) < 0) {{"
        )
        lines.append(
            f'        fprintf(stderr, "failed to add seccomp rule for {syscall}\\n");'
        )
        lines.append("        seccomp_release(ctx);")
        lines.append("        return 126;")
        lines.append("    }")
    return "\n".join(lines) or "    /* no syscall deny rules configured */"


def _render_c_string_array(name: str, values: tuple[str, ...]) -> str:
    lines = [f"static const char *{name}[] = {{"]
    for value in values:
        lines.append(f"    {_c_string(value)},")
    lines.append("    NULL,")
    lines.append("};")
    return "\n".join(lines)


def _render_cidr_rules(name: str, values: tuple[str, ...]) -> str:
    lines = [f"static const struct cidr_rule {name}[] = {{"]
    for value in values:
        network = ipaddress.ip_network(value, strict=False)
        address = network.network_address
        family = "AF_INET" if network.version == 4 else "AF_INET6"
        packed = address.packed
        if network.version == 4:
            bytes_literal = ", ".join(str(byte) for byte in packed + bytes(12))
        else:
            bytes_literal = ", ".join(f"0x{byte:02x}" for byte in packed)
        lines.append(
            "    "
            f"{{ {family}, {{ {bytes_literal} }}, {network.prefixlen}, "
            f"{_c_string_literal(str(address))} }},"
        )
    lines.append("    { 0, { 0 }, 0, NULL },")
    lines.append("};")
    return "\n".join(lines)


def _c_string(value: str) -> str:
    return _c_string_literal(value)


def _c_string_literal(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


_SECCOMP_LAUNCHER_C_TEMPLATE = r'''
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: seccomp-launcher command [args...]\n");
        return 64;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "failed to initialize seccomp filter\n");
        return 126;
    }
    if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1) < 0) {
        fprintf(stderr, "failed to set seccomp no-new-privileges attribute\n");
        seccomp_release(ctx);
        return 126;
    }
__SECCOMP_RULES__
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "failed to load seccomp filter\n");
        seccomp_release(ctx);
        return 126;
    }
    seccomp_release(ctx);

    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 127;
}
'''


_PRELOAD_C_TEMPLATE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

{denied_path_exact}

{denied_path_prefixes}

{child_network_commands}

{egress_cidr_commands}

struct cidr_rule {{
    int family;
    unsigned char address[16];
    unsigned int prefix;
    const char *target;
}};

{egress_cidr_denylist}

{egress_cidr_allowlist}

#define EGRESS_CIDR_DEFAULT_DENY {egress_cidr_default_deny}

static const bool READ_ONLY_ROOT_ENABLED = {read_only_root_enabled};

{writable_path_exact}

{writable_path_prefixes}

static const char *block_message(void) {{
    const char *message = getenv("BOUNDARY_POLICY_BLOCK_MESSAGE");
    if (message == NULL || message[0] == '\0') {{
        return "Permission denied";
    }}
    return message;
}}

static void write_json_string(FILE *log, const char *value) {{
    fputc('"', log);
    if (value != NULL) {{
        for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {{
            switch (*p) {{
                case '\\\\':
                    fputs("\\\\\\\\", log);
                    break;
                case '"':
                    fputs("\\\\\"", log);
                    break;
                case '\n':
                    fputs("\\\\n", log);
                    break;
                case '\r':
                    fputs("\\\\r", log);
                    break;
                case '\t':
                    fputs("\\\\t", log);
                    break;
                default:
                    if (*p < 0x20) {{
                        fputc('?', log);
                    }} else {{
                        fputc(*p, log);
                    }}
            }}
        }}
    }}
    fputc('"', log);
}}

static void write_json_long_field(FILE *log, const char *name, long value) {{
    fputs(",\"", log);
    fputs(name, log);
    fprintf(log, "\":%ld", value);
}}

static void write_json_string_field(FILE *log, const char *name, const char *value) {{
    fputs(",\"", log);
    fputs(name, log);
    fputs("\":", log);
    write_json_string(log, value);
}}

static void read_proc_text(const char *path, char *buffer, size_t buffer_size, const char *fallback) {{
    if (buffer == NULL || buffer_size == 0) {{
        return;
    }}
    int written = snprintf(buffer, buffer_size, "%s", fallback == NULL ? "unknown" : fallback);
    if (written < 0 || (size_t)written >= buffer_size) {{
        buffer[buffer_size - 1] = '\0';
    }}
    FILE *handle = fopen(path, "r");
    if (handle == NULL) {{
        return;
    }}
    if (fgets(buffer, (int)buffer_size, handle) == NULL) {{
        fclose(handle);
        written = snprintf(buffer, buffer_size, "%s", fallback == NULL ? "unknown" : fallback);
        if (written < 0 || (size_t)written >= buffer_size) {{
            buffer[buffer_size - 1] = '\0';
        }}
        return;
    }}
    fclose(handle);
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {{
        buffer[len - 1] = '\0';
        len--;
    }}
    if (buffer[0] == '\0') {{
        written = snprintf(buffer, buffer_size, "%s", fallback == NULL ? "unknown" : fallback);
        if (written < 0 || (size_t)written >= buffer_size) {{
            buffer[buffer_size - 1] = '\0';
        }}
    }}
}}

static void read_proc_cmdline(char *buffer, size_t buffer_size) {{
    if (buffer == NULL || buffer_size == 0) {{
        return;
    }}
    buffer[0] = '\0';
    FILE *handle = fopen("/proc/self/cmdline", "r");
    if (handle == NULL) {{
        snprintf(buffer, buffer_size, "unknown");
        return;
    }}
    size_t length = fread(buffer, 1, buffer_size - 1, handle);
    fclose(handle);
    if (length == 0) {{
        snprintf(buffer, buffer_size, "unknown");
        return;
    }}
    buffer[length] = '\0';
    for (size_t i = 0; i < length; i++) {{
        if (buffer[i] == '\0') {{
            buffer[i] = ' ';
        }}
    }}
    while (length > 0 && buffer[length - 1] == ' ') {{
        buffer[length - 1] = '\0';
        length--;
    }}
}}

static void write_process_attribution(FILE *log) {{
    char cwd[PATH_MAX];
    char comm[128];
    char exe[PATH_MAX];
    char cmdline[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {{
        snprintf(cwd, sizeof(cwd), "unknown");
    }}
    read_proc_text("/proc/self/comm", comm, sizeof(comm), "unknown");
    ssize_t exe_length = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (exe_length < 0) {{
        snprintf(exe, sizeof(exe), "unknown");
    }} else {{
        exe[exe_length] = '\0';
    }}
    read_proc_cmdline(cmdline, sizeof(cmdline));
    fputs(",\"attribution_scope\":\"intercepted_process\"", log);
    write_json_long_field(log, "pid", (long)getpid());
    write_json_long_field(log, "ppid", (long)getppid());
    write_json_long_field(log, "uid", (long)getuid());
    write_json_string_field(log, "cwd", cwd);
    write_json_string_field(log, "comm", comm);
    write_json_string_field(log, "exe", exe);
    write_json_string_field(log, "cmdline", cmdline);
}}

static void write_event_timestamp(FILE *log) {{
    char timestamp[32];
    time_t now = time(NULL);
    struct tm tm_utc;
    if (now == (time_t)-1 || gmtime_r(&now, &tm_utc) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {{
        snprintf(timestamp, sizeof(timestamp), "unknown");
    }}
    write_json_string_field(log, "timestamp", timestamp);
}}

static void emit_block(const char *surface, const char *target) {{
    static __thread bool emitting_block = false;
    const char *event_log = getenv("BOUNDARY_POLICY_EVENT_LOG");
    if (event_log == NULL || event_log[0] == '\0') {{
        event_log = "/tmp/boundarybench-policy-events.jsonl";
    }}
    if (!emitting_block) {{
        emitting_block = true;
        FILE *log = fopen(event_log, "a");
        if (log != NULL) {{
            fputs("{{\"event_type\":\"policy_block\"", log);
            write_event_timestamp(log);
            fputs(",\"surface\":", log);
            write_json_string(log, surface == NULL ? "unknown" : surface);
            fputs(",\"target\":", log);
            write_json_string(log, target == NULL ? "unknown" : target);
            write_process_attribution(log);
            fputs("}}\n", log);
            fclose(log);
        }}
        emitting_block = false;
    }}
    fprintf(stderr, "%s\n", block_message());
}}

static bool starts_with(const char *value, const char *prefix) {{
    return strncmp(value, prefix, strlen(prefix)) == 0;
}}

static bool string_in_list(const char *value, const char *items[]) {{
    if (value == NULL) {{
        return false;
    }}
    for (int i = 0; items[i] != NULL; i++) {{
        if (strcmp(value, items[i]) == 0) {{
            return true;
        }}
    }}
    return false;
}}

static bool starts_with_any(const char *value, const char *prefixes[]) {{
    if (value == NULL) {{
        return false;
    }}
    for (int i = 0; prefixes[i] != NULL; i++) {{
        if (starts_with(value, prefixes[i])) {{
            return true;
        }}
    }}
    return false;
}}

static bool deny_raw_path(const char *path) {{
    return string_in_list(path, DENIED_PATH_EXACT) ||
           starts_with_any(path, DENIED_PATH_PREFIXES);
}}

static bool deny_path(const char *path) {{
    if (deny_raw_path(path)) {{
        return true;
    }}
    char resolved[PATH_MAX];
    if (path != NULL && realpath(path, resolved) != NULL && deny_raw_path(resolved)) {{
        return true;
    }}
    return false;
}}

static bool deny_path_at(int dirfd, const char *path) {{
    if (deny_path(path)) {{
        return true;
    }}
    if (path == NULL || path[0] == '/' || dirfd == AT_FDCWD) {{
        return false;
    }}
    char dirlink[64];
    char dirname[PATH_MAX];
    char combined[PATH_MAX];
    snprintf(dirlink, sizeof(dirlink), "/proc/self/fd/%d", dirfd);
    ssize_t length = readlink(dirlink, dirname, sizeof(dirname) - 1);
    if (length < 0) {{
        return false;
    }}
    dirname[length] = '\0';
    int written = snprintf(combined, sizeof(combined), "%s/%s", dirname, path);
    if (written < 0 || (size_t)written >= sizeof(combined)) {{
        return false;
    }}
    return deny_path(combined);
}}

static int deny_errno(const char *surface, const char *target) {{
    emit_block(surface, target);
    errno = EACCES;
    return -1;
}}

static FILE *deny_file(const char *surface, const char *target) {{
    emit_block(surface, target);
    errno = EACCES;
    return NULL;
}}

static bool needs_open_mode(int flags) {{
#ifdef O_TMPFILE
    return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
#else
    return (flags & O_CREAT) != 0;
#endif
}}

static bool write_access_flags(int flags) {{
    int access_mode = flags & O_ACCMODE;
    if (access_mode == O_WRONLY || access_mode == O_RDWR) {{
        return true;
    }}
    if ((flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0) {{
        return true;
    }}
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) {{
        return true;
    }}
#endif
    return false;
}}

static bool fopen_write_mode(const char *mode) {{
    if (mode == NULL) {{
        return false;
    }}
    return strchr(mode, 'w') != NULL ||
           strchr(mode, 'a') != NULL ||
           strchr(mode, '+') != NULL;
}}

static bool write_path_allowed_raw(const char *path) {{
    return string_in_list(path, WRITABLE_PATH_EXACT) ||
           starts_with_any(path, WRITABLE_PATH_PREFIXES);
}}

static bool absolute_candidate(const char *path, char *buffer, size_t buffer_size) {{
    if (path == NULL) {{
        return false;
    }}
    if (path[0] == '/') {{
        int written = snprintf(buffer, buffer_size, "%s", path);
        return written >= 0 && (size_t)written < buffer_size;
    }}
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {{
        return false;
    }}
    int written = snprintf(buffer, buffer_size, "%s/%s", cwd, path);
    return written >= 0 && (size_t)written < buffer_size;
}}

static bool append_unresolved_suffix(
    const char *resolved_parent,
    const char *suffix,
    char *buffer,
    size_t buffer_size
) {{
    int written;
    if (strcmp(resolved_parent, "/") == 0) {{
        written = snprintf(buffer, buffer_size, "/%s", suffix);
    }} else {{
        written = snprintf(buffer, buffer_size, "%s/%s", resolved_parent, suffix);
    }}
    return written >= 0 && (size_t)written < buffer_size;
}}

static bool canonical_write_candidate_from_deepest_existing_parent(
    const char *candidate,
    char *buffer,
    size_t buffer_size
) {{
    char parent[PATH_MAX];
    char resolved_parent[PATH_MAX];
    int written = snprintf(parent, sizeof(parent), "%s", candidate);
    if (written < 0 || (size_t)written >= sizeof(parent)) {{
        return false;
    }}
    size_t parent_len = strlen(parent);
    while (parent_len > 1 && parent[parent_len - 1] == '/') {{
        parent[parent_len - 1] = '\0';
        parent_len--;
    }}
    char suffix[PATH_MAX] = "";
    while (realpath(parent, resolved_parent) == NULL) {{
        char *slash = strrchr(parent, '/');
        if (slash == NULL) {{
            return false;
        }}
        const char *leaf = slash + 1;
        if (leaf[0] == '\0' || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) {{
            return false;
        }}
        char updated_suffix[PATH_MAX];
        if (suffix[0] == '\0') {{
            written = snprintf(updated_suffix, sizeof(updated_suffix), "%s", leaf);
        }} else {{
            written = snprintf(updated_suffix, sizeof(updated_suffix), "%s/%s", leaf, suffix);
        }}
        if (written <= 0 || (size_t)written >= sizeof(updated_suffix)) {{
            return false;
        }}
        written = snprintf(suffix, sizeof(suffix), "%s", updated_suffix);
        if (written <= 0 || (size_t)written >= sizeof(suffix)) {{
            return false;
        }}
        if (slash == parent) {{
            parent[1] = '\0';
            if (realpath(parent, resolved_parent) == NULL) {{
                return false;
            }}
            break;
        }}
        *slash = '\0';
    }}
    if (suffix[0] == '\0') {{
        written = snprintf(buffer, buffer_size, "%s", resolved_parent);
        return written >= 0 && (size_t)written < buffer_size;
    }}
    return append_unresolved_suffix(resolved_parent, suffix, buffer, buffer_size);
}}

static bool canonical_write_candidate(const char *path, char *buffer, size_t buffer_size) {{
    char candidate[PATH_MAX];
    if (!absolute_candidate(path, candidate, sizeof(candidate))) {{
        return false;
    }}
    char resolved[PATH_MAX];
    if (realpath(candidate, resolved) != NULL) {{
        int written = snprintf(buffer, buffer_size, "%s", resolved);
        return written >= 0 && (size_t)written < buffer_size;
    }}
    return canonical_write_candidate_from_deepest_existing_parent(
        candidate, buffer, buffer_size
    );
}}

static bool write_path_allowed(const char *path) {{
    if (!READ_ONLY_ROOT_ENABLED) {{
        return true;
    }}
    char resolved[PATH_MAX];
    if (!canonical_write_candidate(path, resolved, sizeof(resolved))) {{
        return false;
    }}
    return write_path_allowed_raw(resolved);
}}

static bool write_path_allowed_at(int dirfd, const char *path) {{
    if (!READ_ONLY_ROOT_ENABLED) {{
        return true;
    }}
    if (path == NULL || path[0] == '/' || dirfd == AT_FDCWD) {{
        return write_path_allowed(path);
    }}
    char dirlink[64];
    char dirname[PATH_MAX];
    char combined[PATH_MAX];
    snprintf(dirlink, sizeof(dirlink), "/proc/self/fd/%d", dirfd);
    ssize_t length = readlink(dirlink, dirname, sizeof(dirname) - 1);
    if (length < 0) {{
        return false;
    }}
    dirname[length] = '\0';
    int written = snprintf(combined, sizeof(combined), "%s/%s", dirname, path);
    if (written < 0 || (size_t)written >= sizeof(combined)) {{
        return false;
    }}
    return write_path_allowed(combined);
}}

static bool existing_directory(const char *path) {{
    struct stat st;
    return path != NULL && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}}

static bool existing_directory_at(int dirfd, const char *path) {{
    if (path == NULL || path[0] == '/' || dirfd == AT_FDCWD) {{
        return existing_directory(path);
    }}
    struct stat st;
    return fstatat(dirfd, path, &st, 0) == 0 && S_ISDIR(st.st_mode);
}}

static bool deny_write_path(const char *path) {{
    return READ_ONLY_ROOT_ENABLED && !write_path_allowed(path);
}}

static bool deny_write_path_at(int dirfd, const char *path) {{
    return READ_ONLY_ROOT_ENABLED && !write_path_allowed_at(dirfd, path);
}}

static const char *base_name(const char *path) {{
    if (path == NULL) {{
        return "";
    }}
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}}

static bool should_block_child_network(const char *path) {{
    const char *enabled = getenv("BOUNDARY_CHILD_BLOCK_NETWORK");
    if (enabled == NULL || strcmp(enabled, "1") != 0) {{
        return false;
    }}
    return string_in_list(base_name(path), CHILD_NETWORK_COMMANDS);
}}

static bool should_enable_child_cidr_egress(const char *path) {{
    const char *enabled = getenv("BOUNDARY_CHILD_CIDR_EGRESS");
    if (enabled == NULL || strcmp(enabled, "1") != 0) {{
        return false;
    }}
    return string_in_list(base_name(path), CIDR_EGRESS_COMMANDS);
}}

static char **with_child_network_overrides(
    char *const envp[],
    bool block_network,
    bool cidr_egress
) {{
    int count = 0;
    bool replaced_block_network = false;
    bool replaced_cidr_egress = false;
    if (envp != NULL) {{
        while (envp[count] != NULL) {{
            count++;
        }}
    }}
    char **updated = calloc((size_t)count + 3, sizeof(char *));
    if (updated == NULL) {{
        return (char **)envp;
    }}
    for (int i = 0; i < count; i++) {{
        if (strncmp(envp[i], "BOUNDARY_BLOCK_NETWORK=", 25) == 0) {{
            updated[i] = block_network
                ? "BOUNDARY_BLOCK_NETWORK=1"
                : envp[i];
            replaced_block_network = true;
        }} else if (strncmp(envp[i], "BOUNDARY_CIDR_EGRESS=", 23) == 0) {{
            updated[i] = cidr_egress
                ? "BOUNDARY_CIDR_EGRESS=1"
                : envp[i];
            replaced_cidr_egress = true;
        }} else {{
            updated[i] = envp[i];
        }}
    }}
    if (block_network && !replaced_block_network) {{
        updated[count++] = "BOUNDARY_BLOCK_NETWORK=1";
    }}
    if (cidr_egress && !replaced_cidr_egress) {{
        updated[count++] = "BOUNDARY_CIDR_EGRESS=1";
    }}
    updated[count] = NULL;
    return updated;
}}

static void free_child_network_overrides(char *const original[], char **updated) {{
    if (updated != NULL && updated != (char **)original) {{
        free(updated);
    }}
}}

int open(const char *pathname, int flags, ...) {{
    mode_t mode = 0;
    if (needs_open_mode(flags)) {{
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }}
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (write_access_flags(flags) && deny_write_path(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    if (needs_open_mode(flags)) {{
        return real_open(pathname, flags, mode);
    }}
    return real_open(pathname, flags);
}}

int open64(const char *pathname, int flags, ...) {{
    mode_t mode = 0;
    if (needs_open_mode(flags)) {{
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }}
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (write_access_flags(flags) && deny_write_path(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_open64)(const char *, int, ...) = dlsym(RTLD_NEXT, "open64");
    if (needs_open_mode(flags)) {{
        return real_open64(pathname, flags, mode);
    }}
    return real_open64(pathname, flags);
}}

int openat(int dirfd, const char *pathname, int flags, ...) {{
    mode_t mode = 0;
    if (needs_open_mode(flags)) {{
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }}
    if (deny_path_at(dirfd, pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (write_access_flags(flags) && deny_write_path_at(dirfd, pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    if (needs_open_mode(flags)) {{
        return real_openat(dirfd, pathname, flags, mode);
    }}
    return real_openat(dirfd, pathname, flags);
}}

int openat64(int dirfd, const char *pathname, int flags, ...) {{
    mode_t mode = 0;
    if (needs_open_mode(flags)) {{
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }}
    if (deny_path_at(dirfd, pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (write_access_flags(flags) && deny_write_path_at(dirfd, pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_openat64)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat64");
    if (needs_open_mode(flags)) {{
        return real_openat64(dirfd, pathname, flags, mode);
    }}
    return real_openat64(dirfd, pathname, flags);
}}

int creat(const char *pathname, mode_t mode) {{
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (deny_write_path(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_creat)(const char *, mode_t) = dlsym(RTLD_NEXT, "creat");
    return real_creat(pathname, mode);
}}

int mkdir(const char *pathname, mode_t mode) {{
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    int (*real_mkdir)(const char *, mode_t) = dlsym(RTLD_NEXT, "mkdir");
    if (deny_write_path(pathname) && !existing_directory(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    return real_mkdir(pathname, mode);
}}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {{
    if (deny_path_at(dirfd, pathname)) {{
        return deny_errno("path", pathname);
    }}
    int (*real_mkdirat)(int, const char *, mode_t) = dlsym(RTLD_NEXT, "mkdirat");
    if (deny_write_path_at(dirfd, pathname) && !existing_directory_at(dirfd, pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    return real_mkdirat(dirfd, pathname, mode);
}}

FILE *fopen(const char *pathname, const char *mode) {{
    if (deny_path(pathname)) {{
        return deny_file("path", pathname);
    }}
    if (fopen_write_mode(mode) && deny_write_path(pathname)) {{
        return deny_file("read_only_write_denial", pathname);
    }}
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(pathname, mode);
}}

FILE *fopen64(const char *pathname, const char *mode) {{
    if (deny_path(pathname)) {{
        return deny_file("path", pathname);
    }}
    if (fopen_write_mode(mode) && deny_write_path(pathname)) {{
        return deny_file("read_only_write_denial", pathname);
    }}
    FILE *(*real_fopen64)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen64");
    return real_fopen64(pathname, mode);
}}

int unlink(const char *pathname) {{
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (deny_write_path(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_unlink)(const char *) = dlsym(RTLD_NEXT, "unlink");
    return real_unlink(pathname);
}}

int unlinkat(int dirfd, const char *pathname, int flags) {{
    if (deny_path_at(dirfd, pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (deny_write_path_at(dirfd, pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_unlinkat)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    return real_unlinkat(dirfd, pathname, flags);
}}

int rename(const char *oldpath, const char *newpath) {{
    if (deny_path(oldpath) || deny_path(newpath)) {{
        return deny_errno("path", oldpath);
    }}
    if (deny_write_path(oldpath) || deny_write_path(newpath)) {{
        return deny_errno("read_only_write_denial", newpath);
    }}
    int (*real_rename)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    return real_rename(oldpath, newpath);
}}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {{
    if (deny_path_at(olddirfd, oldpath) || deny_path_at(newdirfd, newpath)) {{
        return deny_errno("path", oldpath);
    }}
    if (deny_write_path_at(olddirfd, oldpath) || deny_write_path_at(newdirfd, newpath)) {{
        return deny_errno("read_only_write_denial", newpath);
    }}
    int (*real_renameat)(int, const char *, int, const char *) = dlsym(RTLD_NEXT, "renameat");
    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {{
    if (deny_path_at(olddirfd, oldpath) || deny_path_at(newdirfd, newpath)) {{
        return deny_errno("path", oldpath);
    }}
    if (deny_write_path_at(olddirfd, oldpath) || deny_write_path_at(newdirfd, newpath)) {{
        return deny_errno("read_only_write_denial", newpath);
    }}
    int (*real_renameat2)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}}

int rmdir(const char *pathname) {{
    if (deny_path(pathname)) {{
        return deny_errno("path", pathname);
    }}
    if (deny_write_path(pathname)) {{
        return deny_errno("read_only_write_denial", pathname);
    }}
    int (*real_rmdir)(const char *) = dlsym(RTLD_NEXT, "rmdir");
    return real_rmdir(pathname);
}}

static bool network_block_enabled(void) {{
    /* Fail closed: only an explicit "0" allows network egress. Unset or any
       other value blocks, so a child that drops the variable cannot regain
       egress. The hardening wrappers always set this explicitly. */
    const char *block_network = getenv("BOUNDARY_BLOCK_NETWORK");
    return block_network == NULL || strcmp(block_network, "0") != 0;
}}

static bool cidr_egress_enabled(void) {{
    const char *enabled = getenv("BOUNDARY_CIDR_EGRESS");
    return enabled != NULL && strcmp(enabled, "1") == 0;
}}

static bool inet_sockaddr(const struct sockaddr *addr, socklen_t addrlen) {{
    if (addr == NULL || addrlen < sizeof(sa_family_t)) {{
        return false;
    }}
    return addr->sa_family == AF_INET || addr->sa_family == AF_INET6;
}}

static bool sockaddr_ip_bytes(
    const struct sockaddr *addr,
    socklen_t addrlen,
    int *family,
    unsigned char bytes[16],
    char *target,
    size_t target_len
) {{
    if (addr == NULL || addrlen < sizeof(sa_family_t)) {{
        return false;
    }}
    memset(bytes, 0, 16);
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {{
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        *family = AF_INET;
        memcpy(bytes, &a4->sin_addr, 4);
        if (target != NULL && target_len > 0) {{
            if (inet_ntop(AF_INET, &a4->sin_addr, target, (socklen_t)target_len) == NULL) {{
                snprintf(target, target_len, "unknown");
            }}
        }}
        return true;
    }}
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {{
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        const unsigned char *raw = a6->sin6_addr.s6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {{
            *family = AF_INET;
            memcpy(bytes, raw + 12, 4);
            if (target != NULL && target_len > 0) {{
                if (inet_ntop(AF_INET, raw + 12, target, (socklen_t)target_len) == NULL) {{
                    snprintf(target, target_len, "unknown");
                }}
            }}
            return true;
        }}
        *family = AF_INET6;
        memcpy(bytes, raw, 16);
        if (target != NULL && target_len > 0) {{
            if (inet_ntop(AF_INET6, &a6->sin6_addr, target, (socklen_t)target_len) == NULL) {{
                snprintf(target, target_len, "unknown");
            }}
        }}
        return true;
    }}
    return false;
}}

static bool cidr_rule_matches(
    const struct cidr_rule *rule,
    int family,
    const unsigned char bytes[16]
) {{
    if (rule == NULL || rule->target == NULL || rule->family != family) {{
        return false;
    }}
    unsigned int max_prefix = family == AF_INET ? 32 : 128;
    if (rule->prefix > max_prefix) {{
        return false;
    }}
    unsigned int full_bytes = rule->prefix / 8;
    unsigned int remainder = rule->prefix % 8;
    if (full_bytes > 0 && memcmp(bytes, rule->address, full_bytes) != 0) {{
        return false;
    }}
    if (remainder == 0) {{
        return true;
    }}
    unsigned char mask = (unsigned char)(0xff << (8 - remainder));
    return (bytes[full_bytes] & mask) == (rule->address[full_bytes] & mask);
}}

static bool cidr_rule_list_matches(
    const struct cidr_rule rules[],
    int family,
    const unsigned char bytes[16]
) {{
    for (int i = 0; rules[i].target != NULL; i++) {{
        if (cidr_rule_matches(&rules[i], family, bytes)) {{
            return true;
        }}
    }}
    return false;
}}

static bool cidr_denied_sockaddr(
    const struct sockaddr *addr,
    socklen_t addrlen,
    char *target,
    size_t target_len
) {{
    if (!cidr_egress_enabled()) {{
        return false;
    }}
    int family = 0;
    unsigned char bytes[16];
    if (!sockaddr_ip_bytes(addr, addrlen, &family, bytes, target, target_len)) {{
        return false;
    }}
    if (cidr_rule_list_matches(EGRESS_CIDR_ALLOWLIST, family, bytes)) {{
        return false;
    }}
    if (cidr_rule_list_matches(EGRESS_CIDR_DENYLIST, family, bytes)) {{
        return true;
    }}
    return EGRESS_CIDR_DEFAULT_DENY != 0;
}}

/* Loopback (127.0.0.0/8, ::1, IPv4-mapped ::ffff:127.0.0.0/104) is not network
   egress: it never leaves the host, so it cannot reach cloud metadata, private
   ranges, or the internet. Exempting it lets legitimate local client/server
   tasks work under hardening while the metadata/private/external egress block
   (the security contract) is unchanged. */
static bool loopback_sockaddr(const struct sockaddr *addr, socklen_t addrlen) {{
    if (addr == NULL) {{
        return false;
    }}
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {{
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        return (ntohl(a4->sin_addr.s_addr) >> 24) == 127;
    }}
    if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {{
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_LOOPBACK(&a6->sin6_addr)) {{
            return true;
        }}
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {{
            const unsigned char *bytes = a6->sin6_addr.s6_addr;
            return bytes[12] == 127;
        }}
    }}
    return false;
}}

static bool datagram_socket(int sockfd) {{
    int socket_type = 0;
    socklen_t socket_type_len = sizeof(socket_type);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_len) != 0) {{
        return false;
    }}
    return socket_type == SOCK_DGRAM;
}}

static bool inet_socket_family(int sockfd) {{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) != 0) {{
        return false;
    }}
    return inet_sockaddr((const struct sockaddr *)&addr, addrlen);
}}

static bool cidr_denied_datagram(
    int sockfd,
    const struct sockaddr *addr,
    socklen_t addrlen,
    char *target,
    size_t target_len
) {{
    if (cidr_denied_sockaddr(addr, addrlen, target, target_len)) {{
        return true;
    }}
    if (addr != NULL || !datagram_socket(sockfd)) {{
        return false;
    }}
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (getpeername(sockfd, (struct sockaddr *)&peer, &peer_len) != 0) {{
        return false;
    }}
    return cidr_denied_sockaddr((const struct sockaddr *)&peer, peer_len, target, target_len);
}}

static bool should_block_datagram_egress(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {{
    if (!network_block_enabled() || !datagram_socket(sockfd)) {{
        return false;
    }}
    if (inet_sockaddr(addr, addrlen)) {{
        return !loopback_sockaddr(addr, addrlen);
    }}
    if (addr != NULL) {{
        return false;
    }}
    return inet_socket_family(sockfd);
}}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {{
    char cidr_target[INET6_ADDRSTRLEN];
    if (cidr_denied_sockaddr(addr, addrlen, cidr_target, sizeof(cidr_target))) {{
        return deny_errno("network_cidr", cidr_target);
    }}
    if (network_block_enabled() && inet_sockaddr(addr, addrlen)
            && !loopback_sockaddr(addr, addrlen)) {{
        return deny_errno("network", "connect");
    }}
    int (*real_connect)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    return real_connect(sockfd, addr, addrlen);
}}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {{
    char cidr_target[INET6_ADDRSTRLEN];
    if (cidr_denied_datagram(sockfd, dest_addr, addrlen, cidr_target, sizeof(cidr_target))) {{
        return deny_errno("network_cidr", cidr_target);
    }}
    if (should_block_datagram_egress(sockfd, dest_addr, addrlen)) {{
        return deny_errno("network", "sendto");
    }}
    ssize_t (*real_sendto)(int, const void *, size_t, int,
                           const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "sendto");
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {{
    const struct sockaddr *dest_addr = NULL;
    socklen_t addrlen = 0;
    if (msg != NULL) {{
        dest_addr = (const struct sockaddr *)msg->msg_name;
        addrlen = (socklen_t)msg->msg_namelen;
    }}
    char cidr_target[INET6_ADDRSTRLEN];
    if (cidr_denied_datagram(sockfd, dest_addr, addrlen, cidr_target, sizeof(cidr_target))) {{
        return deny_errno("network_cidr", cidr_target);
    }}
    if (should_block_datagram_egress(sockfd, dest_addr, addrlen)) {{
        return deny_errno("network", "sendmsg");
    }}
    ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = dlsym(RTLD_NEXT, "sendmsg");
    return real_sendmsg(sockfd, msg, flags);
}}

int execve(const char *pathname, char *const argv[], char *const envp[]) {{
    int (*real_execve)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    bool block_network = should_block_child_network(pathname);
    bool cidr_egress = should_enable_child_cidr_egress(pathname);
    if (block_network || cidr_egress) {{
        char **updated_envp = with_child_network_overrides(envp, block_network, cidr_egress);
        int result = real_execve(pathname, argv, updated_envp);
        free_child_network_overrides(envp, updated_envp);
        return result;
    }}
    return real_execve(pathname, argv, envp);
}}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[], char *const envp[]) {{
    int (*real_posix_spawn)(pid_t *, const char *,
                            const posix_spawn_file_actions_t *,
                            const posix_spawnattr_t *,
                            char *const[], char *const[]) = dlsym(RTLD_NEXT, "posix_spawn");
    bool block_network = should_block_child_network(path);
    bool cidr_egress = should_enable_child_cidr_egress(path);
    if (block_network || cidr_egress) {{
        char **updated_envp = with_child_network_overrides(envp, block_network, cidr_egress);
        int result = real_posix_spawn(pid, path, file_actions, attrp, argv, updated_envp);
        free_child_network_overrides(envp, updated_envp);
        return result;
    }}
    return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp,
                 char *const argv[], char *const envp[]) {{
    int (*real_posix_spawnp)(pid_t *, const char *,
                             const posix_spawn_file_actions_t *,
                             const posix_spawnattr_t *,
                             char *const[], char *const[]) = dlsym(RTLD_NEXT, "posix_spawnp");
    bool block_network = should_block_child_network(file);
    bool cidr_egress = should_enable_child_cidr_egress(file);
    if (block_network || cidr_egress) {{
        char **updated_envp = with_child_network_overrides(envp, block_network, cidr_egress);
        int result = real_posix_spawnp(pid, file, file_actions, attrp, argv, updated_envp);
        free_child_network_overrides(envp, updated_envp);
        return result;
    }}
    return real_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
}}
'''


_LANDLOCK_MAC_RUNNER_C_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif
#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#else
#error "landlock syscall numbers are unavailable for this architecture"
#endif
#endif

struct ia_landlock_ruleset_attr {
    __u64 handled_access_fs;
    __u64 handled_access_net;
};

struct ia_landlock_net_port_attr {
    __u64 allowed_access;
    __u64 port;
};

static __u64 fs_rights_for_abi(int abi) {
    __u64 rights =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) {
        rights |= LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi >= 3) {
        rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if (abi >= 5) {
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    return rights;
}

static int add_path_rule(int ruleset_fd, const char *path, __u64 allowed_access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        fprintf(stderr, "landlock-mac-runner: open %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    struct landlock_path_beneath_attr attr = {
        .allowed_access = allowed_access,
        .parent_fd = fd,
    };
    int rc = (int)syscall(
        __NR_landlock_add_rule,
        ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH,
        &attr,
        0
    );
    int saved_errno = errno;
    close(fd);
    if (rc < 0) {
        errno = saved_errno;
        fprintf(stderr, "landlock-mac-runner: add path rule %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int add_net_port_rule(int ruleset_fd, unsigned long long port) {
    struct ia_landlock_net_port_attr attr = {
        .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .port = port,
    };
    int rc = (int)syscall(
        __NR_landlock_add_rule,
        ruleset_fd,
        LANDLOCK_RULE_NET_PORT,
        &attr,
        0
    );
    if (rc < 0) {
        fprintf(stderr, "landlock-mac-runner: add TCP port %llu rule failed: %s\n", port, strerror(errno));
        return -1;
    }
    return 0;
}

static void emit_applied_event(int abi) {
    const char *event_log = getenv("BOUNDARY_POLICY_EVENT_LOG");
    if (event_log == NULL || event_log[0] == '\0') {
        event_log = "/tmp/boundarybench-policy-events.jsonl";
    }
    FILE *log = fopen(event_log, "a");
    if (log == NULL) {
        return;
    }
    fprintf(
        log,
        "{\"event_type\":\"policy_enforce\",\"surface\":\"full_mac_enforcement\",\"engine\":\"landlock\",\"abi\":%d}\n",
        abi
    );
    fclose(log);
}

static int parse_port(const char *value, unsigned long long *port_out) {
    char *end = NULL;
    unsigned long long port = strtoull(value, &end, 10);
    if (end == value || *end != '\0' || port > 65535ULL) {
        fprintf(stderr, "landlock-mac-runner: invalid TCP port %s\n", value);
        return -1;
    }
    *port_out = port;
    return 0;
}

int main(int argc, char **argv) {
    const char *workspace = NULL;
    const char *home = NULL;
    const char *tmp = "/tmp";
    int require_network = 0;
    unsigned long long allow_ports[16];
    size_t allow_port_count = 0;
    int command_index = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            command_index = i + 1;
            break;
        } else if (strcmp(argv[i], "--workspace") == 0 && i + 1 < argc) {
            workspace = argv[++i];
        } else if (strcmp(argv[i], "--home") == 0 && i + 1 < argc) {
            home = argv[++i];
        } else if (strcmp(argv[i], "--tmp") == 0 && i + 1 < argc) {
            tmp = argv[++i];
        } else if (strcmp(argv[i], "--allow-tcp-connect") == 0 && i + 1 < argc) {
            if (allow_port_count >= sizeof(allow_ports) / sizeof(allow_ports[0])) {
                fprintf(stderr, "landlock-mac-runner: too many TCP allow ports\n");
                return 2;
            }
            if (parse_port(argv[++i], &allow_ports[allow_port_count]) != 0) {
                return 2;
            }
            allow_port_count++;
        } else if (strcmp(argv[i], "--require-network") == 0) {
            require_network = 1;
        } else {
            fprintf(stderr, "landlock-mac-runner: unknown or incomplete option %s\n", argv[i]);
            return 2;
        }
    }
    if (command_index < 0 || command_index >= argc) {
        fprintf(stderr, "landlock-mac-runner: missing command after --\n");
        return 2;
    }
    if (workspace == NULL || home == NULL || workspace[0] != '/' || home[0] != '/') {
        fprintf(stderr, "landlock-mac-runner: --workspace and --home must be absolute paths\n");
        return 2;
    }

    int abi = (int)syscall(
        __NR_landlock_create_ruleset,
        NULL,
        0,
        LANDLOCK_CREATE_RULESET_VERSION
    );
    if (abi < 1) {
        fprintf(stderr, "landlock-mac-runner: Landlock is unavailable: %s\n", strerror(errno));
        return 126;
    }
    if (require_network && abi < 4) {
        fprintf(stderr, "landlock-mac-runner: Landlock ABI %d lacks TCP connect enforcement\n", abi);
        return 126;
    }

    __u64 fs_rights = fs_rights_for_abi(abi);
    __u64 read_exec = LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_EXECUTE;
    __u64 read_only = LANDLOCK_ACCESS_FS_READ_FILE;
    __u64 read_write_file = LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_WRITE_FILE;
    __u64 net_rights = abi >= 4 ? LANDLOCK_ACCESS_NET_CONNECT_TCP : 0;
    struct ia_landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = fs_rights,
        .handled_access_net = net_rights,
    };
    size_t ruleset_size = abi >= 4 ? sizeof(ruleset_attr) : sizeof(ruleset_attr.handled_access_fs);
    int ruleset_fd = (int)syscall(
        __NR_landlock_create_ruleset,
        &ruleset_attr,
        ruleset_size,
        0
    );
    if (ruleset_fd < 0) {
        fprintf(stderr, "landlock-mac-runner: create ruleset failed: %s\n", strerror(errno));
        return 126;
    }

    const char *read_exec_dirs[] = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/opt",
        "/proc",
        NULL,
    };
    const char *read_only_files[] = {
        "/etc/passwd",
        "/etc/group",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/gai.conf",
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/etc/timezone",
        "/dev/urandom",
        "/dev/random",
        "/dev/zero",
        NULL,
    };
    const char *read_write_files[] = {
        "/dev/null",
        NULL,
    };
    const char *read_write_dirs[] = {
        workspace,
        home,
        tmp,
        "/var/tmp",
        NULL,
    };
    for (int i = 0; read_exec_dirs[i] != NULL; i++) {
        if (add_path_rule(ruleset_fd, read_exec_dirs[i], read_exec) != 0) {
            close(ruleset_fd);
            return 126;
        }
    }
    for (int i = 0; read_only_files[i] != NULL; i++) {
        if (add_path_rule(ruleset_fd, read_only_files[i], read_only) != 0) {
            close(ruleset_fd);
            return 126;
        }
    }
    for (int i = 0; read_write_files[i] != NULL; i++) {
        if (add_path_rule(ruleset_fd, read_write_files[i], read_write_file) != 0) {
            close(ruleset_fd);
            return 126;
        }
    }
    for (int i = 0; read_write_dirs[i] != NULL; i++) {
        if (add_path_rule(ruleset_fd, read_write_dirs[i], fs_rights) != 0) {
            close(ruleset_fd);
            return 126;
        }
    }
    if (abi >= 4) {
        for (size_t i = 0; i < allow_port_count; i++) {
            if (add_net_port_rule(ruleset_fd, allow_ports[i]) != 0) {
                close(ruleset_fd);
                return 126;
            }
        }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "landlock-mac-runner: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return 126;
    }
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        fprintf(stderr, "landlock-mac-runner: restrict_self failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return 126;
    }
    close(ruleset_fd);
    emit_applied_event(abi);
    execvp(argv[command_index], &argv[command_index]);
    fprintf(stderr, "landlock-mac-runner: exec %s failed: %s\n", argv[command_index], strerror(errno));
    return 126;
}
'''
