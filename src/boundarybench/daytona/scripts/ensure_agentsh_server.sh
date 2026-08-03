if ! curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1; then
  pkill -f '/usr/bin/agentsh server' >/dev/null 2>&1 || true
  nohup /usr/bin/agentsh server --config __CONFIG_PATH__ >/tmp/boundarybench-agentsh-server.log 2>&1 &
fi
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1 || curl -fsS http://127.0.0.1:18080/api/v1/health >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done
cat /tmp/boundarybench-agentsh-server.log 2>/dev/null || true
exit 1
