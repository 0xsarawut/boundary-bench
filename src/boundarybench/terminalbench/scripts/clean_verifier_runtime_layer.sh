set -eu

WORKDIR=__WORKDIR__
export DEBIAN_FRONTEND=noninteractive

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  apt-get install -y -qq curl ca-certificates bash util-linux >/dev/null || true
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache curl ca-certificates bash util-linux >/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl ca-certificates bash util-linux >/dev/null || true
fi

if ! command -v bash >/dev/null 2>&1; then
  echo "clean verifier runtime failed: bash not found"
  exit 1
fi

if [ ! -x /bin/bash.real ]; then
  bash_path="$(command -v bash)"
  cp -f "$bash_path" /bin/bash.real 2>/dev/null || ln -sf "$bash_path" /bin/bash.real
fi

mkdir -p "$WORKDIR"

echo CLEAN_VERIFIER_RUNTIME_OK
