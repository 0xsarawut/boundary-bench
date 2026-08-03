set -eu
rm -rf /tmp/boundary-hardening-fixture/shims
mkdir -p /tests /logs/agent /logs/verifier
chmod -R a+rwX /app /tests /logs 2>/dev/null || true
chmod -R a+rX /tmp/boundary-hardening-fixture 2>/dev/null || true
printf '{"lifted":["command_shims","agent_workspace_permissions","verifier_paths","fixture_permissions"]}\n'
