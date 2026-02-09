#!/usr/bin/env bash
# Setup iptables rules for credential proxy
#
# NOTE (2026-02-07): We no longer hardcode Telegram IPs.
# Telegram's A/AAAA records can change, which can silently bypass interception.
# Use the generator + iptables-restore inputs instead.

set -euo pipefail

echo "Applying iptables rules for credential proxy from current DNS (chain-based, ordered rules)..."

# Canonical apply path: dedicated nat chain + ordered OUTPUT rules.
# Supports multiple hosts via HOSTS (comma/space separated).
# Examples:
#   HOSTS="api.telegram.org api.search.brave.com" sudo /usr/local/sbin/apply-credential-proxy-iptables
sudo /usr/local/sbin/apply-credential-proxy-iptables

echo "✅ iptables rules applied (v4 + v6) via apply-credential-proxy-iptables"
echo ""
echo "Verify with: sudo iptables -t nat -L OUTPUT -v --line-numbers"
