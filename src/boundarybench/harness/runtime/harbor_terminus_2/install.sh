set -eu

TERMINUS_BIN=__TERMINUS_BIN__
TERMINUS_HOME=__TERMINUS_HOME__
RUN_AGENT_AS_ROOT=__RUN_AGENT_AS_ROOT__
HARBOR_VERSION=__HARBOR_VERSION__
PYTHON_VERSION=__PYTHON_VERSION__
UV_VERSION=__UV_VERSION__
UV_SHA256_X86_64=__UV_SHA256_X86_64__
UV_SHA256_AARCH64=__UV_SHA256_AARCH64__
runner_source=/tmp/boundarybench-terminus-2-runner.py
patches_source=/tmp/boundarybench-terminus-2-patches.py
requirements_lock=/tmp/boundarybench-terminus-2-requirements.lock
uv_archive=/tmp/boundarybench-terminus-2-uv.tar.gz
uv_extract=/tmp/boundarybench-terminus-2-uv
venv_dir="$TERMINUS_HOME/venv"
uv_bin="$TERMINUS_HOME/bootstrap/uv"

log() {
  echo "harness-terminus-2: $*"
}

install_tmux() {
  command -v tmux >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq tmux >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq tmux >/dev/null 2>&1; }
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache tmux >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y tmux >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y tmux >/dev/null
  fi
  command -v tmux >/dev/null 2>&1 || { echo "tmux not installed"; exit 1; }
}

install_uv() {
  test -x "$uv_bin" && return 0
  arch="$(uname -m)"
  case "$arch" in
    x86_64)
      uv_arch=x86_64-unknown-linux-musl
      uv_sha256="$UV_SHA256_X86_64"
      ;;
    aarch64 | arm64)
      uv_arch=aarch64-unknown-linux-musl
      uv_sha256="$UV_SHA256_AARCH64"
      ;;
    *) echo "unsupported arch for uv: $arch"; exit 1 ;;
  esac
  url="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_arch}.tar.gz"
  rm -rf "$uv_extract"
  mkdir -p "$uv_extract" "$(dirname "$uv_bin")"
  curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$uv_archive"
  printf '%s  %s\n' "$uv_sha256" "$uv_archive" | sha256sum -c - >/dev/null
  tar -xzf "$uv_archive" -C "$uv_extract"
  uv_source="$(find "$uv_extract" -type f -name uv | head -n 1)"
  test -n "$uv_source" || { echo "uv binary not found in release archive"; exit 1; }
  cp "$uv_source" "$uv_bin"
  chmod +x "$uv_bin"
}

install_terminus() {
  mkdir -p "$TERMINUS_HOME" "$(dirname "$TERMINUS_BIN")"
  awk -v expected="harbor==$HARBOR_VERSION" \
    '$1 == expected { found=1 } END { exit !found }' "$requirements_lock" \
    || { echo "requirements lock does not match Harbor pin"; exit 1; }
  export UV_PYTHON_INSTALL_DIR="$TERMINUS_HOME/python"
  export UV_CACHE_DIR="$TERMINUS_HOME/cache"
  "$uv_bin" python install "$PYTHON_VERSION" >/dev/null
  "$uv_bin" venv --python "$PYTHON_VERSION" "$venv_dir" >/dev/null
  "$uv_bin" pip sync --require-hashes --python "$venv_dir/bin/python" \
    "$requirements_lock" >/dev/null
  cp "$runner_source" "$TERMINUS_HOME/runner.py"
  cp "$patches_source" "$TERMINUS_HOME/patches.py"
  cat > "$TERMINUS_BIN" <<EOF
#!/bin/sh
exec "$venv_dir/bin/python" "$TERMINUS_HOME/runner.py" "\$@"
EOF
  chmod +x "$TERMINUS_BIN" "$TERMINUS_HOME/runner.py"
}

run_self_check() {
  self_check_dir="$TERMINUS_HOME/self-check"
  if [ "$RUN_AGENT_AS_ROOT" = "1" ]; then
    "$TERMINUS_BIN" --self-check --logs-dir "$self_check_dir"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -H -u daytona -- "$TERMINUS_BIN" --self-check --logs-dir "$self_check_dir"
  else
    su -s /bin/bash.real daytona -c \
      "'$TERMINUS_BIN' --self-check --logs-dir '$self_check_dir'"
  fi
  rm -rf "$self_check_dir"
}

cat > "$runner_source" <<'TERMINUS_RUNNER'
__TERMINUS_RUNNER_PY__
TERMINUS_RUNNER

cat > "$patches_source" <<'TERMINUS_PATCHES'
__TERMINUS_PATCHES_PY__
TERMINUS_PATCHES

install_tmux
install_uv
install_terminus

if [ "$RUN_AGENT_AS_ROOT" != "1" ]; then
  chown -R daytona:daytona "$TERMINUS_HOME" "$(dirname "$TERMINUS_BIN")"
fi

test -x "$TERMINUS_BIN" || { echo "terminus-2 runner not installed"; exit 1; }
run_self_check
rm -rf "$runner_source" "$patches_source" "$requirements_lock" "$uv_archive" "$uv_extract"
echo HARNESS_BOOTSTRAP_OK
echo HARNESS_INSTALL_OK
