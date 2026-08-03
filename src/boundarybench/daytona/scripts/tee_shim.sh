#!/bin/bash.real
# DO NOT DELETE — retained unwired for the future old(steering)-vs-new(native) philosophy A/B benchmark

json_escape() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

emit_tee_policy_block() {
  local target="$1"
  local event_log="${BOUNDARY_POLICY_EVENT_LOG:-/tmp/boundarybench-policy-events.jsonl}"
  local cwd
  local comm
  local uid
  local cmdline
  local timestamp
  cwd="$(pwd -P 2>/dev/null || pwd 2>/dev/null || printf unknown)"
  comm="$(cat "/proc/$$/comm" 2>/dev/null || printf tee)"
  uid="$(id -u 2>/dev/null || printf 0)"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)"
  cmdline="$0"
  for item in "$@"; do
    cmdline="$cmdline $item"
  done
  printf '{"event_type":"policy_block","timestamp":"%s","surface":"tee_write","target":"%s","attribution_scope":"tee_shim_process","pid":%s,"ppid":%s,"uid":%s,"cwd":"%s","comm":"%s","cmdline":"%s"}\n' \
    "$(json_escape "$timestamp")" \
    "$(json_escape "$target")" \
    "$$" \
    "${PPID:-0}" \
    "$uid" \
    "$(json_escape "$cwd")" \
    "$(json_escape "$comm")" \
    "$(json_escape "$cmdline")" >>"$event_log" 2>/dev/null || true
}

for arg in "$@"; do
  case "$arg" in
__TEE_CASES__
  esac
done
exec /usr/bin/tee "$@"
