#!/usr/bin/env bash
set -euo pipefail

# Generates an iptables-restore rules file for transparent interception.
# You can re-run this whenever upstream IPs change.
#
# Output: /etc/credential-proxy/iptables.rules (by default)

OUT=${1:-/etc/credential-proxy/iptables.rules}
PORT=${PORT:-18443}
PROXY_UID=${PROXY_UID:-openclaw-secrets}

# Hostnames to intercept (add more as you expand services)
HOSTS=(
  api.telegram.org
)

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need id

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

OUT_V6="${OUT%.rules}.v6.rules"
OUT_RM="${OUT%.rules}.remove.sh"
OUT_V6_RM="${OUT%.rules}.v6.remove.sh"

# ---------- IPv4 rules ----------
{
  echo "# Generated on $(date -u +%FT%TZ)"
  echo "*nat"
  echo ":OUTPUT ACCEPT [0:0]"
  echo "# Bypass for proxy user (prevents infinite loop)"
  echo "-A OUTPUT -m owner --uid-owner ${UID_NUM} -j RETURN"
  echo "# Redirect selected upstream IPv4s to local proxy port ${PORT}"
  for h in "${HOSTS[@]}"; do
    ips=$(resolve_v4 "$h")
    if [[ -z "$ips" ]]; then
      echo "# WARN: no A records resolved for ${h}"
      continue
    fi
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      echo "-A OUTPUT -p tcp -d ${ip} --dport 443 -j REDIRECT --to-ports ${PORT}"
    done <<< "$ips"
  done
  echo "COMMIT"
} > "$OUT"

# ---------- IPv4 removal script ----------
{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "PORT=${PORT}"
  echo "# best-effort: remove redirects that were added"
  for h in "${HOSTS[@]}"; do
    ips=$(resolve_v4 "$h")
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      echo "iptables -t nat -D OUTPUT -p tcp -d ${ip} --dport 443 -j REDIRECT --to-ports ${PORT} 2>/dev/null || true"
    done <<< "$ips"
  done
} > "$OUT_RM"
chmod +x "$OUT_RM"

# ---------- IPv6 rules ----------
{
  echo "# Generated on $(date -u +%FT%TZ)"
  echo "*nat"
  echo ":OUTPUT ACCEPT [0:0]"
  echo "# Bypass for proxy user (prevents infinite loop)"
  echo "-A OUTPUT -m owner --uid-owner ${UID_NUM} -j RETURN"
  echo "# Redirect selected upstream IPv6s to local proxy port ${PORT}"
  for h in "${HOSTS[@]}"; do
    ips=$(resolve_v6 "$h")
    if [[ -z "$ips" ]]; then
      echo "# WARN: no AAAA records resolved for ${h}"
      continue
    fi
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      echo "-A OUTPUT -p tcp -d ${ip} --dport 443 -j REDIRECT --to-ports ${PORT}"
    done <<< "$ips"
  done
  echo "COMMIT"
} > "$OUT_V6"

# ---------- IPv6 removal script ----------
{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "PORT=${PORT}"
  echo "# best-effort: remove redirects that were added"
  for h in "${HOSTS[@]}"; do
    ips=$(resolve_v6 "$h")
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      echo "ip6tables -t nat -D OUTPUT -p tcp -d ${ip} --dport 443 -j REDIRECT --to-ports ${PORT} 2>/dev/null || true"
    done <<< "$ips"
  done
} > "$OUT_V6_RM"
chmod +x "$OUT_V6_RM"

echo "Wrote $OUT (v4) and $OUT_V6 (v6)" >&2
