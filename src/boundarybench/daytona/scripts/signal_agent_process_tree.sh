signal="__SIGNAL__"
_n1="cla""ude"
_n2="boundarybench-task-""prompt"
pids=""
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  cmdline="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
  case "$cmdline" in
    *"$_n1"*|*"$_n2"*) pids="$pids $pid" ;;
  esac
done
changed=1
while [ "$changed" = 1 ]; do
  changed=0
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    stat="$(cat "$p/stat" 2>/dev/null || true)"
    rest="${stat##*) }"
    ppid="$(printf '%s\n' "$rest" | awk '{print $2}')"
    [ -n "$ppid" ] || continue
    case " $pids " in
      *" $ppid "*)
        case " $pids " in
          *" $pid "*) ;;
          *) pids="$pids $pid"; changed=1 ;;
        esac
        ;;
    esac
  done
done
for pid in $pids; do
  kill "$signal" "$pid" 2>/dev/null || true
done
