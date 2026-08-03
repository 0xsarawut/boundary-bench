#!/usr/bin/env bash
# Build a clean release zip of the repository.
#
# Uses `git archive` from HEAD, so:
#   - only committed, tracked files are included (no .git, no untracked scratch),
#   - the archive root is `boundarybench/` (not the checkout directory name).
#
# Usage: scripts/build_release_zip.sh [output.zip]
set -euo pipefail

OUT="${1:-boundarybench.zip}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git archive --format=zip --prefix=boundarybench/ -o "$OUT" HEAD

BYTES=$(wc -c < "$OUT" | tr -d ' ')
MB=$(awk "BEGIN { printf \"%.2f\", $BYTES / 1048576 }")
echo "Built $OUT"
echo "Size: ${BYTES} bytes (${MB} MiB)"
if [ "$BYTES" -gt 52428800 ]; then
  echo "WARNING: exceeds the 50 MiB size limit" >&2
  exit 1
fi
