set -eu

CLAUDE_BIN=__CLAUDE_BIN__
RUN_AGENT_AS_ROOT=__RUN_AGENT_AS_ROOT__
# Pinned by the adapter (CLAUDE_CODE_VERSION); an operator can override the env
# var to bump the release without editing this script.
CLAUDE_CODE_VERSION="${CLAUDE_CODE_VERSION:-__CLAUDE_CODE_VERSION__}"

log() {
  echo "harness-claude-code: $*"
}

cleanup_claude_install_log() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    cat /tmp/claude-install.log 2>/dev/null || true
  fi
  cleanup_status=0
  rm -f /tmp/claude-install.log || cleanup_status=$?
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=$cleanup_status
  fi
  exit "$status"
}
trap cleanup_claude_install_log EXIT

# Returns nonzero (rather than exiting) when no user switch is possible so the
# soft version check below can tolerate it; install callers still abort via
# `set -e`. The error goes to stderr so command substitutions never capture it.
run_as_daytona() {
  if command -v su >/dev/null 2>&1; then
    su - daytona -c "$1"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -H -u daytona /bin/bash.real -lc "$1"
  else
    echo "harness install failed: cannot switch to daytona user" >&2
    return 1
  fi
}

install_claude_for_root() {
  test -x "$CLAUDE_BIN" && return 0
  curl -fsSL https://claude.ai/install.sh | /bin/bash.real -s -- "$CLAUDE_CODE_VERSION" >/tmp/claude-install.log 2>&1
}

install_claude_for_daytona() {
  test -x "$CLAUDE_BIN" && return 0
  # The version is expanded here and handed to the inner shell single-quoted so
  # it stays one inert word through the second evaluation (adapter validates
  # the charset, so no embedded single quotes).
  run_as_daytona "curl -fsSL https://claude.ai/install.sh | /bin/bash.real -s -- '$CLAUDE_CODE_VERSION' >/tmp/claude-install.log 2>&1"
}

log "installing claude code $CLAUDE_CODE_VERSION"
if [ "$RUN_AGENT_AS_ROOT" = "1" ]; then
  install_claude_for_root
else
  install_claude_for_daytona
fi

test -x "$CLAUDE_BIN" || { echo "claude not installed at $CLAUDE_BIN"; cat /tmp/claude-install.log 2>/dev/null || true; exit 1; }
# Record what actually landed so the provisioning transcript can be audited
# against the pin. Soft check only: an operator override may be latest/stable.
if [ "$RUN_AGENT_AS_ROOT" = "1" ]; then
  installed_version="$("$CLAUDE_BIN" --version 2>/dev/null || true)"
else
  installed_version="$(run_as_daytona "$CLAUDE_BIN --version" 2>/dev/null || true)"
fi
log "installed ${installed_version:-unknown (version check failed)}"
echo HARNESS_INSTALL_OK
