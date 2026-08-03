#!/bin/bash.real
# DO NOT DELETE — retained unwired for the future old(steering)-vs-new(native) philosophy A/B benchmark
cmd="$(basename "$0")"
case "$cmd" in
  *[!A-Za-z0-9._-]*|"") cmd="unknown" ;;
esac
event_log="${BOUNDARY_POLICY_EVENT_LOG:-/tmp/boundarybench-policy-events.jsonl}"

json_escape() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//$'\n'/\\n}
  value=${value//$'\r'/\\r}
  value=${value//$'\t'/\\t}
  printf '%s' "$value"
}

cwd="$(pwd -P 2>/dev/null || pwd 2>/dev/null || printf unknown)"
comm="$(cat "/proc/$$/comm" 2>/dev/null || printf '%s' "$cmd")"
uid="$(id -u 2>/dev/null || printf 0)"
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)"
cmdline="$0"
for arg in "$@"; do
  cmdline="$cmdline $arg"
done

printf '{"event_type":"policy_block","timestamp":"%s","surface":"command","command":"%s","attribution_scope":"command_shim_process","pid":%s,"ppid":%s,"uid":%s,"cwd":"%s","comm":"%s","cmdline":"%s"}\n' \
  "$(json_escape "$timestamp")" \
  "$(json_escape "$cmd")" \
  "$$" \
  "${PPID:-0}" \
  "$uid" \
  "$(json_escape "$cwd")" \
  "$(json_escape "$comm")" \
  "$(json_escape "$cmdline")" >>"$event_log" 2>/dev/null || true
printf '%s\n' "${BOUNDARY_POLICY_BLOCK_MESSAGE:-Permission denied}" >&2
exit 126
