#!/usr/bin/env bash
set -euo pipefail

# Deploy host-header routing fix for credential-proxy.
# Run with sudo on the VPS:
#   sudo /home/moluser/clawd/openclaw-credential-proxy/credential-proxy/deploy-host-header-fallback.sh

ROOT_DIR="/home/moluser/clawd/openclaw-credential-proxy/credential-proxy"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need install
need systemctl
need python3

echo "==> Installing updated proxy code"
install -m 0755 "$ROOT_DIR/credential_proxy.py" /opt/credential-proxy/credential_proxy.py

echo "==> Restarting service"
systemctl restart credential-proxy

echo "==> Status"
systemctl --no-pager status credential-proxy.service || true

echo "==> Tip: tail logs"
echo "sudo tail -n 60 /var/log/credential-proxy/credential-proxy.log"
