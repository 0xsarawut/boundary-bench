set -eu

CODEX_BIN=__CODEX_BIN__
CODEX_HOME=__CODEX_HOME__
RUN_AGENT_AS_ROOT=__RUN_AGENT_AS_ROOT__
codex_archive=/tmp/codex.tar.gz
extract_dir=
# Pinned by the adapter (CODEX_VERSION); an operator can override the env var to
# bump the release without editing this script.
CODEX_VERSION="${CODEX_VERSION:-__CODEX_VERSION__}"

log() {
  echo "harness-codex: $*"
}

cleanup_codex_staging() {
  rm -f "$codex_archive"
  if [ -n "$extract_dir" ]; then
    rm -rf "$extract_dir"
  fi
}
trap cleanup_codex_staging EXIT

# Codex ships static musl release binaries, so no Node/npm is needed in the
# task image. Download a PINNED release via GitHub's REST-API-free asset URL
# (releases/download/<tag>/<asset>) — this avoids the GitHub REST API, which is
# rate-limited (60 req/hr) from shared Daytona egress IPs and would otherwise
# make installs fail nondeterministically. Installs run before hardening, so
# egress to github.com is available here, same as the Claude path.
install_codex_binary() {
  test -x "$CODEX_BIN" && return 0
  arch="$(uname -m)"
  case "$arch" in
    x86_64) codex_arch="x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) codex_arch="aarch64-unknown-linux-musl" ;;
    *) echo "unsupported arch for codex: $arch"; exit 1 ;;
  esac
  asset="codex-${codex_arch}.tar.gz"
  url="https://github.com/openai/codex/releases/download/${CODEX_VERSION}/${asset}"
  log "downloading $url"
  # Retry a few times to ride out transient GitHub/CDN blips.
  curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$codex_archive"
  extract_dir="$(mktemp -d)"
  tar -xzf "$codex_archive" -C "$extract_dir"
  # The archive ships a single static binary; locate it rather than assuming
  # its exact path, so a future release layout change fails loudly with a
  # directory listing instead of an opaque `mv` error.
  codex_src="$(find "$extract_dir" -type f -name "codex-${codex_arch}" | head -n 1)"
  if [ -z "$codex_src" ]; then
    codex_src="$(find "$extract_dir" -type f -name 'codex*' | head -n 1)"
  fi
  if [ -z "$codex_src" ]; then
    echo "codex binary not found in downloaded archive; contents:"
    ls -lR "$extract_dir"
    exit 1
  fi
  bin_dir="$(dirname "$CODEX_BIN")"
  mkdir -p "$bin_dir"
  mv "$codex_src" "$CODEX_BIN"
  chmod +x "$CODEX_BIN"
}

write_codex_config() {
  mkdir -p "$CODEX_HOME"
  cat > "$CODEX_HOME/config.toml" <<'CODEX_CONFIG'
__CODEX_CONFIG_TOML__
CODEX_CONFIG
}

# Codex shells out to ripgrep for search; harbor installs it before codex on
# every TB 2.1 install path, so its absence changes agent behavior vs the
# reference runs. Failure is fatal, matching this script's fail-loud style.
install_ripgrep() {
  command -v rg >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq ripgrep >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq ripgrep >/dev/null 2>&1; } \
      || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ripgrep >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ripgrep >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ripgrep >/dev/null 2>&1 || true
  fi
  command -v rg >/dev/null 2>&1 || { echo "ripgrep not installed"; exit 1; }
}

run_as_daytona() {
  if command -v su >/dev/null 2>&1; then
    su - daytona -c "$1"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -H -u daytona /bin/bash.real -lc "$1"
  else
    echo "harness bootstrap failed: cannot switch to daytona user" >&2
    return 1
  fi
}

# Setup-before-policy: START codex once, pre-boundary, as the user the agent
# will run as. All first-run state (config load, $CODEX_HOME/tmp/arg0 PATH
# aliases, in-process app-server init) is laid down and PROVEN here, where no
# policy walls exist — a harness that cannot initialize fails PROVISIONING
# (this script is fatal on the gate), never a hardened task attempt. The model
# call itself is expected to fail (the loopback OpenRouter proxy is not up at
# install time); only initialization failures trip the gate.
bootstrap_codex() {
  bootstrap_log=/tmp/codex-bootstrap.log
  bootstrap_cmd="CODEX_HOME=$CODEX_HOME RUST_LOG=error timeout 60 $CODEX_BIN exec --color never --skip-git-repo-check --json --enable unified_exec --dangerously-bypass-approvals-and-sandbox 'bootstrap start-check' </dev/null"
  if [ "$RUN_AGENT_AS_ROOT" = "1" ]; then
    sh -c "$bootstrap_cmd" >"$bootstrap_log" 2>&1 || true
  else
    run_as_daytona "$bootstrap_cmd" >"$bootstrap_log" 2>&1 || true
  fi
  if grep -q "failed to initialize" "$bootstrap_log"; then
    echo "codex failed its pre-boundary start-check:" >&2
    cat "$bootstrap_log" >&2
    exit 1
  fi
  # Drop the throwaway bootstrap rollout so exported session artifacts carry
  # only the real task run.
  rm -rf "$CODEX_HOME/sessions"/* 2>/dev/null || true
  echo HARNESS_BOOTSTRAP_OK
}

install_ripgrep
install_codex_binary
write_codex_config

if [ "$RUN_AGENT_AS_ROOT" != "1" ]; then
  # Installed as root (into daytona's home); hand the whole created tree —
  # including the root-created ~/.local parent — to daytona so codex can write
  # its session state at runtime. A chown failure is fatal (no `|| true`): a
  # root-owned CODEX_HOME silently breaks codex.
  if command -v chown >/dev/null 2>&1; then
    local_root="$(dirname "$(dirname "$CODEX_BIN")")"
    chown -R daytona:daytona "$local_root" "$CODEX_HOME"
  fi
fi

test -x "$CODEX_BIN" || { echo "codex not installed at $CODEX_BIN"; exit 1; }
bootstrap_codex
echo HARNESS_INSTALL_OK
