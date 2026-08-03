set -eu

GROK_BIN=__GROK_BIN__
GROK_HOME=__GROK_HOME__
RUN_AGENT_AS_ROOT=__RUN_AGENT_AS_ROOT__
# Pinned by the adapter (GROK_VERSION); an operator can override the env var to
# bump the release without editing this script.
GROK_VERSION="${GROK_VERSION:-__GROK_VERSION__}"

log() {
  echo "harness-grok: $*"
}

# Grok ships a single static binary (NOT a tarball). Download the PINNED version
# from the public GCS artifact bucket — no API, no rate limit — then chmod +x.
# Installs run before hardening, so egress to storage.googleapis.com is
# available here, same as the Claude/Codex paths.
install_grok_binary() {
  test -x "$GROK_BIN" && return 0
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) grok_arch="x86_64" ;;
    aarch64 | arm64) grok_arch="aarch64" ;;
    *) echo "unsupported arch for grok: $arch"; exit 1 ;;
  esac
  url="https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-${GROK_VERSION}-linux-${grok_arch}"
  log "downloading $url"
  bin_dir="$(dirname "$GROK_BIN")"
  mkdir -p "$bin_dir"
  # Retry a few times to ride out transient GCS/CDN blips.
  curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$GROK_BIN"
  chmod +x "$GROK_BIN"
  # Sanity-check the bare binary actually runs on this arch.
  "$GROK_BIN" --version </dev/null >/dev/null 2>&1 || { echo "grok failed to run"; exit 1; }
}

write_grok_config() {
  mkdir -p "$GROK_HOME"
  cat > "$GROK_HOME/config.toml" <<'GROK_CONFIG'
__GROK_CONFIG_TOML__
GROK_CONFIG
}

# Write the config first so the binary's --version sanity run (and anything
# else) already sees telemetry/auto-update disabled.
write_grok_config
install_grok_binary

if [ "$RUN_AGENT_AS_ROOT" != "1" ]; then
  # Installed as root (into daytona's home); hand the whole created tree —
  # including the root-created ~/.local parent — to daytona so grok can write
  # its session state at runtime. A chown failure is fatal (no `|| true`): a
  # root-owned GROK_HOME silently breaks grok.
  if command -v chown >/dev/null 2>&1; then
    local_root="$(dirname "$(dirname "$GROK_BIN")")"
    chown -R daytona:daytona "$local_root" "$GROK_HOME"
  fi
fi

test -x "$GROK_BIN" || { echo "grok not installed at $GROK_BIN"; exit 1; }
echo HARNESS_INSTALL_OK
