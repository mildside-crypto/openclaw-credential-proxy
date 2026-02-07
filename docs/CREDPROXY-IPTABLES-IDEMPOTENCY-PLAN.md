# Plan: Fix duplicate iptables REDIRECT accumulation (credential proxy)

## Problem
We currently apply interception rules via:
- `gen-credential-proxy-iptables` → writes `/etc/credential-proxy/iptables.rules` + `.v6.rules`
- systemd ExecStartPre: `iptables-restore --noflush` + `ip6tables-restore --noflush`

Because `--noflush` does not clear the nat table, repeated restarts of `credential-proxy` **append duplicate rules** to `nat/OUTPUT`.

### Why this matters
- Bloat + harder audits/ops
- Slight runtime overhead in OUTPUT traversal
- Makes it harder to reason about “what’s active”

## Constraints
- **Do not flush the whole nat table** (Docker and other tooling depend on it).
- Must remain robust to **DNS drift** for `api.telegram.org` (A/AAAA can change).
- Must work for **IPv4 and IPv6**.
- Should be **idempotent**: safe to run on every service start.

## Proposed solution (recommended): Dedicated chain + idempotent apply script

### Design
Create a dedicated chain in `nat` table, e.g.:
- IPv4: `CREDPROXY`
- IPv6: `CREDPROXY`

Keep `OUTPUT` minimal and **order-stable**:
1. **Rule #1**: bypass for proxy user to prevent loops:
   - `-m owner --uid-owner <openclaw-secrets-uid> -j RETURN`
2. **Rule #2**: jump to dedicated chain, restricted to HTTPS only:
   - `-p tcp --dport 443 -j CREDPROXY`

All redirect rules live inside the dedicated chain:
- For each resolved IP of `api.telegram.org`:
  - `-p tcp -d <ip> --dport 443 -j REDIRECT --to-ports 18443`

On each start:
- Create chain if missing
- **Flush only that chain** (safe) and repopulate from freshly-resolved DNS
- **Delete-then-insert** the OUTPUT bypass + jump rules at fixed positions to guarantee ordering (do not rely on `iptables -C` alone).

### Why this works
- No nat table flush.
- Redirect rules are fully replaced each run (flush chain → insert current IPs), so **DNS drift** is handled.
- OUTPUT doesn’t accumulate duplicates because we force a single ordered bypass + jump each run.
- Restricting the jump to `tcp/443` reduces the impact on unrelated traffic and improves audit clarity.

## Implementation steps

### 1) Add a new helper: apply script (v4 + v6)
Create `/usr/local/sbin/apply-credential-proxy-iptables` (or store in repo and install it) that:
- Resolves current A/AAAA for `api.telegram.org` (reuse existing resolve logic from `gen-credential-proxy-iptables`)
- Reads proxy UID (`id -u openclaw-secrets`) and port (default 18443)
- Uses a simple **lockfile** to avoid concurrent modifications during rapid restarts
- Uses **delete-then-insert** for OUTPUT rules to guarantee ordering
- Handles IPv6 gracefully when there are no AAAA records (empty chain is OK)

Pseudo-flow (IPv4):
```bash
# Optional: prevent races during fast restarts
exec 200>/var/lock/credproxy-iptables.lock
flock -x 200

iptables -t nat -N CREDPROXY 2>/dev/null || true
iptables -t nat -F CREDPROXY

# Ensure OUTPUT ordering is correct (delete-then-insert)
# Rule #1: bypass for proxy user
iptables -t nat -D OUTPUT -m owner --uid-owner "$UID" -j RETURN 2>/dev/null || true
iptables -t nat -I OUTPUT 1 -m owner --uid-owner "$UID" -j RETURN

# Rule #2: jump to CREDPROXY for HTTPS only
iptables -t nat -D OUTPUT -p tcp --dport 443 -j CREDPROXY 2>/dev/null || true
iptables -t nat -I OUTPUT 2 -p tcp --dport 443 -j CREDPROXY

# Populate chain with current Telegram IPs
for ip in $(resolve_v4 api.telegram.org); do
  iptables -t nat -A CREDPROXY -p tcp -d "$ip" --dport 443 -j REDIRECT --to-ports 18443
done
```

Repeat for IPv6 using `ip6tables`.

IPv6 note:
- If there are no AAAA records, still create+flush the `CREDPROXY` chain and install OUTPUT rules; just skip population.

### 2) Update systemd drop-in to call the apply script
Replace the current ExecStartPre restore calls with a single idempotent apply step.
Example drop-in:
```ini
[Service]
PermissionsStartOnly=true
ExecStartPre=/usr/local/sbin/apply-credential-proxy-iptables
```

(We can keep the generator for auditability, but it won’t be the mechanism that mutates OUTPUT anymore.)

### 3) Migration / cleanup (one-time)
Because duplicates already exist, we should remove them once.

Avoid “delete by line number” (fragile). Prefer loop-based deletes of **only** the rules we own, then let the new apply script rebuild the dedicated chain.

Suggested cleanup strategy (no nat flush):
1. Stop gateway (or at least stop Telegram polling) for a brief maintenance window.
2. Remove legacy rules (loop until none remain). Examples:
   - Remove OUTPUT bypass duplicates:
     - `while sudo iptables -t nat -D OUTPUT -m owner --uid-owner <UID> -j RETURN 2>/dev/null; do :; done`
   - Remove legacy REDIRECT rules to 18443 targeting Telegram IPs:
     - `while sudo iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 18443 2>/dev/null; do :; done`
   (Repeat for `ip6tables`.)
3. Run the new apply script to install ordered OUTPUT rules and repopulate `CREDPROXY` chain from current DNS.
4. Restart gateway.

Note: make the cleanup script specific (e.g. `cleanup-credproxy-legacy-rules`) so it’s auditable and repeatable.

### 4) Verification
- Confirm OUTPUT contains exactly (and in this order):
  1) `RETURN` for proxy UID (rule #1)
  2) `-p tcp --dport 443 -j CREDPROXY` (rule #2)
- Confirm `CREDPROXY` chain exists and contains redirects for current A/AAAA (IPv6 may be empty if no AAAA).
- Confirm proxy works:
  - OpenClaw Telegram polling continues
  - Send/receive message + attachment
- Confirm repeated `sudo systemctl restart credential-proxy` does not grow rule count.
- Docker sanity: after Docker restart (if applicable), re-check rule ordering is still correct.

## Rollback
- Remove/disable the drop-in ExecStartPre apply script.
- Remove our rules and chain (best-effort):
  ```bash
  sudo iptables  -t nat -D OUTPUT -p tcp --dport 443 -j CREDPROXY 2>/dev/null || true
  sudo iptables  -t nat -D OUTPUT -m owner --uid-owner <UID> -j RETURN 2>/dev/null || true
  sudo iptables  -t nat -F CREDPROXY 2>/dev/null || true
  sudo iptables  -t nat -X CREDPROXY 2>/dev/null || true

  sudo ip6tables -t nat -D OUTPUT -p tcp --dport 443 -j CREDPROXY 2>/dev/null || true
  sudo ip6tables -t nat -D OUTPUT -m owner --uid-owner <UID> -j RETURN 2>/dev/null || true
  sudo ip6tables -t nat -F CREDPROXY 2>/dev/null || true
  sudo ip6tables -t nat -X CREDPROXY 2>/dev/null || true
  ```
- Restore previous generator + `iptables-restore --noflush` approach.

## Open questions (resolved)
- Restrict the OUTPUT jump to **`-p tcp --dport 443`**: **Yes** (clearer intent, smaller blast radius).
- Keep `.rules` files for audit visibility even if not used to apply: **Yes** (useful artefact / debugging), but treat them as reference, not the mutation mechanism.

