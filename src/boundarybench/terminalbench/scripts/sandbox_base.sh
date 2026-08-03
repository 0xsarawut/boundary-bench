set -eu

WORKDIR=__WORKDIR__
RUN_AGENT_AS_ROOT=__RUN_AGENT_AS_ROOT__
export DEBIAN_FRONTEND=noninteractive

log() {
  echo "sandbox-base: $*"
}

retry_apt_get() {
  max_attempts=3
  attempt=1

  while ! apt-get "$@"; do
    if [ "$attempt" -ge "$max_attempts" ]; then
      log "apt-get failed after $max_attempts attempts: $*" >&2
      return 1
    fi

    delay=$((attempt * 2))
    log "apt-get failed (attempt $attempt/$max_attempts); retrying in ${delay}s: $*" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

install_runtime_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    retry_apt_get update -qq || log "apt-get update failed; continuing"
    retry_apt_get install -y -qq curl ca-certificates gcc libseccomp-dev sudo bash passwd util-linux python3 python3-venv python3-dev linux-libc-dev nftables iproute2 >/dev/null \
      || log "apt-get prerequisite install failed; continuing"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl ca-certificates gcc libseccomp-dev sudo bash shadow util-linux python3 py3-pip python3-dev linux-headers nftables iproute2 >/dev/null \
      || log "apk prerequisite install failed; continuing"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl ca-certificates gcc libseccomp-devel sudo bash shadow-utils util-linux python3 python3-devel kernel-headers nftables iproute >/dev/null \
      || log "dnf prerequisite install failed; continuing"
  else
    log "no supported package manager found; using existing image tools"
  fi
}

ensure_bash_real() {
  if [ -x /bin/bash.real ]; then
    return 0
  fi
  bash_path="$(command -v bash || true)"
  if [ -z "$bash_path" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      retry_apt_get update -qq || true
      retry_apt_get install -y -qq bash >/dev/null || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache bash >/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q bash >/dev/null || true
    fi
    bash_path="$(command -v bash || true)"
  fi
  if [ -z "$bash_path" ]; then
    echo "sandbox base layering failed: bash not found and could not be installed"
    exit 1
  fi
  cp -f "$bash_path" /bin/bash.real || ln -sf "$bash_path" /bin/bash.real
}

ensure_daytona_user() {
  id daytona >/dev/null 2>&1 && return 0
  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s /bin/bash.real daytona || useradd -m -s /bin/bash daytona
  elif command -v adduser >/dev/null 2>&1; then
    adduser -D -h /home/daytona -s /bin/bash.real daytona \
      || adduser --disabled-password --gecos "" --home /home/daytona --shell /bin/bash.real daytona
  else
    echo "sandbox base layering failed: cannot create daytona user"
    exit 1
  fi
}

install_runtime_packages
ensure_bash_real
mkdir -p "$WORKDIR"

if [ "$RUN_AGENT_AS_ROOT" != "1" ]; then
  ensure_daytona_user
  chown -R daytona:daytona "$WORKDIR"
fi

echo SANDBOX_BASE_OK
