#!/usr/bin/env bash
# Setup iptables rules for credential proxy
#
# NOTE (2026-02-07): We no longer hardcode Telegram IPs.
# Telegram's A/AAAA records can change, which can silently bypass interception.
# Use the generator + iptables-restore inputs instead.

set -euo pipefail

echo "Generating iptables rules for credential proxy from current DNS..."

sudo /usr/local/sbin/gen-credential-proxy-iptables /etc/credential-proxy/iptables.rules
sudo iptables-restore --noflush /etc/credential-proxy/iptables.rules
sudo ip6tables-restore --noflush /etc/credential-proxy/iptables.v6.rules

echo "✅ iptables rules applied (v4 + v6)"
echo ""
echo "Verify with: sudo iptables -t nat -L OUTPUT -v --line-numbers"
