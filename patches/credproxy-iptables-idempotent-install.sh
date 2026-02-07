#!/usr/bin/env bash
set -euo pipefail

# Run as Todd with sudo privileges on the host.
# Installs idempotent credproxy iptables management + updates systemd drop-in.

ROOT=/usr/local/sbin

echo "Installing apply/cleanup helpers into $ROOT" >&2
sudo install -m 0755 /home/moluser/clawd/scripts/apply-credential-proxy-iptables.sh "$ROOT/apply-credential-proxy-iptables"
sudo install -m 0755 /home/moluser/clawd/scripts/cleanup-credproxy-legacy-rules.sh "$ROOT/cleanup-credproxy-legacy-rules"

echo "Updating systemd drop-in to use apply helper" >&2
sudo mkdir -p /etc/systemd/system/credential-proxy.service.d
sudo tee /etc/systemd/system/credential-proxy.service.d/iptables.conf >/dev/null <<'EOF'
[Service]
PermissionsStartOnly=true
ExecStartPre=/usr/local/sbin/apply-credential-proxy-iptables
EOF

sudo systemctl daemon-reload

echo "Done installing. Next: maintenance window steps:" >&2
cat <<'NEXT'
1) Stop OpenClaw gateway (brief window):
   openclaw gateway stop

2) Cleanup legacy OUTPUT rules:
   sudo /usr/local/sbin/cleanup-credproxy-legacy-rules

3) Restart credential proxy (will re-apply ordered rules via ExecStartPre):
   sudo systemctl restart credential-proxy

4) Start OpenClaw gateway:
   openclaw gateway start

5) Verify:
   sudo iptables -t nat -L OUTPUT -n -v --line-numbers | sed -n '1,40p'
   sudo iptables -t nat -L CREDPROXY -n -v --line-numbers
   sudo ip6tables -t nat -L OUTPUT -n -v --line-numbers | sed -n '1,40p'
   sudo ip6tables -t nat -L CREDPROXY -n -v --line-numbers
   openclaw status --deep

Restart credential-proxy a couple times and confirm OUTPUT/CREDPROXY rule counts don't grow.
NEXT
