#!/usr/bin/env bash
set -euo pipefail

# Idempotent iptables apply for credential proxy interception.
# Creates a dedicated nat chain (CREDPROXY), flushes it, repopulates from current DNS,
# and ensures nat/OUTPUT has two ordered rules:
#  1) bypass for proxy user (RETURN)
#  2) jump to CREDPROXY restricted to tcp/443
#
# Safe alongside Docker: does NOT flush nat table; flushes only CREDPROXY chain.

PORT=${PORT:-18443}
PROXY_UID=${PROXY_UID:-openclaw-secrets}
HOST=${HOST:-api.telegram.org}
CHAIN=${CHAIN:-CREDPROXY}
LOCK=${LOCK:-/var/lock/credproxy-iptables.lock}

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need id
need flock

resolve_v4() {
  local host="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$host" | awk 'NF'
  else
    getent ahostsv4 "$host" | awk '{print $1}' | sort -u
  fi
}

resolve_v6() {
  local host="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short AAAA "$host" | awk 'NF'
  else
    getent ahostsv6 "$host" | awk '{print $1}' | sort -u
  fi
}

UID_NUM=$(id -u "$PROXY_UID")

apply_v4() {
  exec 200>"$LOCK"
  flock -x 200

  iptables -t nat -N "$CHAIN" 2>/dev/null || true
  iptables -t nat -F "$CHAIN"

  # OUTPUT rule #1: bypass for proxy user
  iptables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j RETURN 2>/dev/null || true
  iptables -t nat -I OUTPUT 1 -m owner --uid-owner "$UID_NUM" -j RETURN

  # OUTPUT rule #2: jump to CHAIN for tcp/443 only
  iptables -t nat -D OUTPUT -p tcp --dport 443 -j "$CHAIN" 2>/dev/null || true
  iptables -t nat -I OUTPUT 2 -p tcp --dport 443 -j "$CHAIN"

  # Populate chain
  local ips
  ips=$(resolve_v4 "$HOST" || true)
  if [[ -z "$ips" ]]; then
    echo "WARN: no A records for $HOST (v4 chain left empty)" >&2
    return 0
  fi
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    iptables -t nat -A "$CHAIN" -p tcp -d "$ip" --dport 443 -j REDIRECT --to-ports "$PORT"
  done <<< "$ips"
}

apply_v6() {
  exec 201>"${LOCK}.v6"
  flock -x 201

  ip6tables -t nat -N "$CHAIN" 2>/dev/null || true
  ip6tables -t nat -F "$CHAIN"

  ip6tables -t nat -D OUTPUT -m owner --uid-owner "$UID_NUM" -j RETURN 2>/dev/null || true
  ip6tables -t nat -I OUTPUT 1 -m owner --uid-owner "$UID_NUM" -j RETURN

  ip6tables -t nat -D OUTPUT -p tcp --dport 443 -j "$CHAIN" 2>/dev/null || true
  ip6tables -t nat -I OUTPUT 2 -p tcp --dport 443 -j "$CHAIN"

  local ips
  ips=$(resolve_v6 "$HOST" || true)
  if [[ -z "$ips" ]]; then
    echo "INFO: no AAAA records for $HOST (v6 chain left empty)" >&2
    return 0
  fi
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    ip6tables -t nat -A "$CHAIN" -p tcp -d "$ip" --dport 443 -j REDIRECT --to-ports "$PORT"
  done <<< "$ips"
}

apply_v4
apply_v6

echo "Applied credproxy rules: chain=$CHAIN host=$HOST port=$PORT proxy_uid=$PROXY_UID(uid=$UID_NUM)" >&2
