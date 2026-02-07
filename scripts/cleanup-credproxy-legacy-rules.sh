#!/usr/bin/env bash
set -euo pipefail

# One-time cleanup helper to remove legacy/duplicated rules from nat/OUTPUT.
# Does NOT flush the nat table.
#
# After running this, run apply-credential-proxy-iptables.sh (as root) to install the new ordered rules + chain.

PORT=${PORT:-18443}
PROXY_UID=${PROXY_UID:-openclaw-secrets}

UID_NUM=$(id -u "$PROXY_UID")

echo "Cleaning up legacy credproxy rules (uid=$UID_NUM port=$PORT)" >&2

# Remove any OUTPUT bypass rules for this UID (loop until none)
# Historically these were RETURN; we also saw ACCEPT in some legacy installs.
while iptables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j RETURN 2>/dev/null; do :; done
while iptables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j ACCEPT 2>/dev/null; do :; done
while ip6tables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j RETURN 2>/dev/null; do :; done
while ip6tables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j ACCEPT 2>/dev/null; do :; done

# Remove any legacy REDIRECT rules in OUTPUT to our proxy port (broad but constrained by to-ports)
while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$PORT" 2>/dev/null; do :; done
while ip6tables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$PORT" 2>/dev/null; do :; done

# Remove any old jump rules to CREDPROXY in OUTPUT (if present)
while iptables -t nat -D OUTPUT -p tcp --dport 443 -j CREDPROXY 2>/dev/null; do :; done
while ip6tables -t nat -D OUTPUT -p tcp --dport 443 -j CREDPROXY 2>/dev/null; do :; done

echo "Legacy OUTPUT rules removed (best-effort)." >&2
