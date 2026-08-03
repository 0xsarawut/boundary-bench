set -euo pipefail
mkdir -p __ASSET_DIR__
chmod 0711 __ASSET_DIR__
# Sudo's own logfile feature (no daemon): record every sudo attempt so the
# post-run telemetry harvester can read the agent's privilege-escalation
# attempts from /var/log/sudo.log. Always on in native mode.
install -d -m 0755 /etc/sudoers.d
cat > /etc/sudoers.d/00-policy-logfile <<'IA_SUDOERS_EOF'
Defaults logfile=/var/log/sudo.log
IA_SUDOERS_EOF
chmod 0440 /etc/sudoers.d/00-policy-logfile
touch /var/log/sudo.log
chown root:root /var/log/sudo.log
chmod 0600 /var/log/sudo.log
__DOMAIN_EGRESS_PROXY_BLOCK__
__NATIVE_EGRESS_REJECT_BLOCK__
__EXPLICIT_CREDENTIAL_PATHS_BLOCK__
__STRIP_SETUID_BLOCK__
__LOCK_ROOT_PASSWORD_BLOCK__
