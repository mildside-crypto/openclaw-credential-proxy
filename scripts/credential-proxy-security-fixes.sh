#!/usr/bin/env bash
set -euo pipefail

# Credential proxy security fixes (Telegram)
# - Fix logrotate postrotate service name
# - Remove legacy proxy file
# - Ensure cert hosts dir permissions are correct
# - Install/refresh systemd drop-in to regenerate+apply iptables rules on service start
#
# NOTE: This script is safe to run multiple times. It does not flush iptables.

LOGROTATE_FILE=/etc/logrotate.d/credential-proxy
DROPIN_DIR=/etc/systemd/system/credential-proxy.service.d
DROPIN_FILE=${DROPIN_DIR}/iptables.conf

echo "[1/4] Fix logrotate postrotate service name (credential-proxy-telegram -> credential-proxy)"
if [[ -f "$LOGROTATE_FILE" ]]; then
  sudo sed -i 's/credential-proxy-telegram/credential-proxy/g' "$LOGROTATE_FILE"
else
  echo "WARN: $LOGROTATE_FILE not found; skipping"
fi

echo "[2/4] Remove legacy proxy file (telegram_proxy.py)"
sudo rm -f /opt/credential-proxy/telegram_proxy.py || true

echo "[3/4] Ensure hosts dir permissions/ownership"
sudo chmod 0750 /etc/openclaw-secrets/certs/hosts 2>/dev/null || true
sudo chown openclaw-secrets:openclaw-secrets /etc/openclaw-secrets/certs/hosts 2>/dev/null || true

echo "[4/4] Install systemd drop-in for DNS refresh + iptables apply on service start"
sudo mkdir -p "$DROPIN_DIR"
# This drop-in runs ExecStartPre as root (PermissionsStartOnly) even though the service user is openclaw-secrets
sudo tee "$DROPIN_FILE" >/dev/null <<'EOF'
[Service]
# Run ExecStartPre as root even though main service runs as openclaw-secrets
PermissionsStartOnly=true

# Regenerate rules from current DNS, then apply (v4 + v6)
ExecStartPre=/usr/local/sbin/gen-credential-proxy-iptables /etc/credential-proxy/iptables.rules
ExecStartPre=/sbin/iptables-restore --noflush /etc/credential-proxy/iptables.rules
ExecStartPre=/sbin/ip6tables-restore --noflush /etc/credential-proxy/iptables.v6.rules
EOF

sudo systemctl daemon-reload
# Restart so the ExecStartPre rules are applied immediately
sudo systemctl restart credential-proxy

echo "Done. Check status with: sudo systemctl status credential-proxy"
