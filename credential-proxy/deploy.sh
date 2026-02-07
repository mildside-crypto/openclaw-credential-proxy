#!/usr/bin/env bash
set -euo pipefail

# Deploy credential-proxy (multi-service SNI) + iptables persistence.
# Run this script with sudo:
#   sudo ./deploy.sh

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need install
need systemctl
need python3
need openssl
need iptables-restore
need ip6tables-restore
# DNS resolver tool: prefer dig (dnsutils), but we can fall back to getent.
if ! command -v dig >/dev/null 2>&1 && ! command -v getent >/dev/null 2>&1; then
  echo "Missing dependency: dig (dnsutils) or getent (libc-bin)." >&2
  exit 1
fi

# Ensure PyYAML exists (proxy config loader)
python3 -c 'import yaml' >/dev/null 2>&1 || {
  echo "Missing python dependency: PyYAML. Install with: sudo apt-get install -y python3-yaml" >&2
  exit 1
}

echo "==> Creating directories"
install -d -m 0755 /opt/credential-proxy
install -d -m 0755 /etc/credential-proxy
install -d -m 0755 /var/log/credential-proxy
# Allow openclaw-secrets to create/write logs (directory is shared with legacy telegram.log)
chown root:openclaw-secrets /var/log/credential-proxy
chmod 2775 /var/log/credential-proxy

# Ensure cert host cache dir exists and is writable by openclaw-secrets
if [[ -d /etc/openclaw-secrets/certs ]]; then
  install -d -m 0750 /etc/openclaw-secrets/certs/hosts
  chown openclaw-secrets:openclaw-secrets /etc/openclaw-secrets/certs/hosts
  # Serial file for host cert signing (openssl -CAserial writes here)
  touch /etc/openclaw-secrets/certs/hosts/ca.srl
  chown openclaw-secrets:openclaw-secrets /etc/openclaw-secrets/certs/hosts/ca.srl
  chmod 0640 /etc/openclaw-secrets/certs/hosts/ca.srl
fi

echo "==> Installing proxy code"
install -m 0755 "${ROOT_DIR}/credential_proxy.py" /opt/credential-proxy/credential_proxy.py

# Pre-create the log file with the right ownership (avoids permission errors on first start)
touch /var/log/credential-proxy/credential-proxy.log
chown openclaw-secrets:openclaw-secrets /var/log/credential-proxy/credential-proxy.log
chmod 0644 /var/log/credential-proxy/credential-proxy.log

# Clean any previously broken host cert artefacts (e.g., zero-byte .crt)
if [[ -d /etc/openclaw-secrets/certs/hosts ]]; then
  find /etc/openclaw-secrets/certs/hosts -maxdepth 1 -type f -name '*.crt' -size 0 -print -delete || true
fi

echo "==> NOTE: If you see 'Reject source=<public-ip> sni=' in logs, add your VPS public IP to listen.allowed_sources in /etc/openclaw-secrets/credential-proxy.yaml"

echo "==> Installing config (only if missing)"
if [[ ! -f /etc/openclaw-secrets/credential-proxy.yaml ]]; then
  install -m 0640 "${ROOT_DIR}/config.example.yaml" /etc/openclaw-secrets/credential-proxy.yaml
  chown root:openclaw-secrets /etc/openclaw-secrets/credential-proxy.yaml
  echo "   Wrote /etc/openclaw-secrets/credential-proxy.yaml (edit as needed)"
else
  echo "   Keeping existing /etc/openclaw-secrets/credential-proxy.yaml"
fi

echo "==> Installing systemd units"
install -m 0644 "${ROOT_DIR}/units/credential-proxy.service" /etc/systemd/system/credential-proxy.service
install -m 0644 "${ROOT_DIR}/units/credential-proxy-iptables.service" /etc/systemd/system/credential-proxy-iptables.service

echo "==> Generating iptables rules"
install -m 0755 "${ROOT_DIR}/gen-iptables-rules.sh" /usr/local/sbin/gen-credential-proxy-iptables
/usr/local/sbin/gen-credential-proxy-iptables /etc/credential-proxy/iptables.rules
# Install generated removal scripts (for clean rollback)
if [[ -f /etc/credential-proxy/iptables.remove.sh ]]; then chmod +x /etc/credential-proxy/iptables.remove.sh; fi
if [[ -f /etc/credential-proxy/iptables.v6.remove.sh ]]; then chmod +x /etc/credential-proxy/iptables.v6.remove.sh; fi

echo "==> Reloading systemd"
systemctl daemon-reload

echo "==> Enabling services"
systemctl enable --now credential-proxy-iptables.service
systemctl enable --now credential-proxy.service

echo "==> Status"
systemctl --no-pager status credential-proxy.service || true
systemctl --no-pager status credential-proxy-iptables.service || true

printf "\nNOTE: ensure OpenClaw trusts the proxy CA (NODE_EXTRA_CA_CERTS=/etc/openclaw-secrets/certs/ca.crt).\n"
