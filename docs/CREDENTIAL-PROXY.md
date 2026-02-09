# Credential Proxy for OpenClaw

**Purpose:** Isolate sensitive API credentials from the OpenClaw process to defend against prompt injection attacks.

This document reflects the **current deployed state** on this host (Telegram via transparent credential proxy + iptables REDIRECT).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  OpenClaw (moluser)                                     │
│  Makes API calls with placeholder/fake tokens           │
└────────────────────┬────────────────────────────────────┘
                     │
          iptables REDIRECT (localhost:18443)
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Credential Proxy (openclaw-secrets user)               │
│  • Terminates TLS with self-signed cert                 │
│  • Extracts path/headers containing token placeholders  │
│  • Injects real token from secure storage               │
│  • Forwards to real API endpoint                        │
│  • Logs all requests (no credentials)                   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
              Real API (e.g., api.telegram.org)
```

## Current Status (Telegram + Brave)

**Implemented:**
- ✅ Telegram bot credential isolation
- ✅ Brave Search credential isolation (header injection)
- ✅ Transparent HTTPS proxy with TLS termination
- ✅ iptables traffic interception (IPv4 + IPv6)
- ✅ systemd service management (`credential-proxy.service`)
- ✅ Log rotation (7-day retention)
- ✅ Credential storage with proper permissions
- ✅ **DNS drift mitigation:** iptables rules are regenerated/applied on proxy service start
- ✅ **Missing SNI mitigation:** when TLS SNI is missing, proxy routes by HTTP `Host` header
- ✅ Telegram `getUpdates` long-polling supported (higher upstream timeout)

**Known gaps / TODO:**
- ✅ (fixed) iptables idempotency: interception now uses a dedicated `CREDPROXY` chain so restarts do not accumulate duplicate rules
- 🔜 Phase 2: OpenAI API isolation
- 🔜 Phase 3: GitHub Copilot isolation
- 💡 Future: Generic credential proxy framework

## Files & Locations

### Proxy Code
- `/opt/credential-proxy/credential_proxy.py` - Main proxy implementation
- `/etc/openclaw-secrets/credential-proxy.yaml` - Runtime config
- `~/clawd/docs/CREDENTIAL-PROXY.md` - This file

### Credentials (owned by openclaw-secrets:openclaw-secrets, mode 600)
- `/etc/openclaw-secrets/telegram_token` - Real Telegram bot token
- `/etc/openclaw-secrets/certs/ca.crt` - Self-signed CA certificate
- `/etc/openclaw-secrets/certs/ca.key` - CA private key
- `/etc/openclaw-secrets/certs/server.crt` - Proxy TLS certificate
- `/etc/openclaw-secrets/certs/server.key` - Proxy TLS private key

### System Services
- `/etc/systemd/system/credential-proxy.service` - Proxy systemd unit
- `/etc/systemd/system/credential-proxy.service.d/iptables.conf` - **ExecStartPre** DNS refresh + apply rules
- `/usr/local/sbin/gen-credential-proxy-iptables` - Rule generator (writes restore files)
- `/etc/credential-proxy/iptables.rules` + `/etc/credential-proxy/iptables.v6.rules` - Generated restore inputs
- `/etc/systemd/system/openclaw-gateway.service.d/credential-proxy.conf` - Environment override (CA trust)
- `/etc/logrotate.d/credential-proxy` - Log rotation config

### Logs
- `/var/log/credential-proxy/credential-proxy.log` - Request/response audit trail

## How It Works

### 1. User Isolation
```bash
# Separate user owns real credentials
sudo useradd --system --no-create-home openclaw-secrets
```

The `moluser` account (running OpenClaw) **cannot read** files owned by `openclaw-secrets`.

### 2. Traffic Interception (iptables)

```bash
# Redirect Telegram API traffic to local proxy
sudo iptables -t nat -A OUTPUT \
  -p tcp \
  -d 149.154.166.110 \
  --dport 443 \
  -m owner --uid-owner moluser \
  -j REDIRECT --to-port 18443

# Allow proxy's own traffic to bypass (avoid loop)
sudo iptables -t nat -A OUTPUT \
  -p tcp \
  -d 149.154.166.110 \
  --dport 443 \
  -m owner --uid-owner openclaw-secrets \
  -j ACCEPT
```

### 3. TLS Termination

The proxy uses a self-signed CA certificate that OpenClaw trusts via:

```bash
# /etc/systemd/system/openclaw-gateway.service.d/credential-proxy.conf
[Service]
Environment=NODE_EXTRA_CA_CERTS=/etc/openclaw-secrets/certs/ca.crt
```

### 4. Token Injection

The proxy extracts Telegram paths like `/bot<TOKEN>/method` and replaces `<TOKEN>` with the real token before forwarding.

## Setup (from scratch)

> Note: this doc focuses on **Telegram**. OpenClaw uses **polling** (`getUpdates`), and this setup has been validated for **messages and attachments** end-to-end through the credential proxy.

### 1. Create User & Directories

```bash
sudo useradd --system --no-create-home openclaw-secrets
sudo mkdir -p /etc/openclaw-secrets/certs
sudo mkdir -p /var/log/credential-proxy
sudo chown openclaw-secrets:openclaw-secrets /etc/openclaw-secrets
sudo chown openclaw-secrets:openclaw-secrets /var/log/credential-proxy
```

### 2. Generate Certificates

```bash
# Generate CA
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/openclaw-secrets/certs/ca.key \
  -out /etc/openclaw-secrets/certs/ca.crt \
  -days 3650 -nodes \
  -subj "/CN=OpenClaw Credential Proxy CA"

# Generate server cert signed by CA
sudo openssl req -newkey rsa:4096 -nodes \
  -keyout /etc/openclaw-secrets/certs/server.key \
  -out /tmp/server.csr \
  -subj "/CN=api.telegram.org"

sudo openssl x509 -req -in /tmp/server.csr \
  -CA /etc/openclaw-secrets/certs/ca.crt \
  -CAkey /etc/openclaw-secrets/certs/ca.key \
  -CAcreateserial \
  -out /etc/openclaw-secrets/certs/server.crt \
  -days 3650 \
  -extfile <(echo "subjectAltName=DNS:api.telegram.org")

# Set permissions
sudo chown -R openclaw-secrets:openclaw-secrets /etc/openclaw-secrets/certs
sudo chmod 600 /etc/openclaw-secrets/certs/*.key
sudo chmod 644 /etc/openclaw-secrets/certs/*.crt
sudo rm /tmp/server.csr
```

### 3. Store Telegram Token

```bash
# Replace with your real token
echo "123456789:YOUR_REAL_TOKEN_HERE" | sudo tee /etc/openclaw-secrets/telegram_token
sudo chown openclaw-secrets:openclaw-secrets /etc/openclaw-secrets/telegram_token
sudo chmod 600 /etc/openclaw-secrets/telegram_token
```

### 4. Install Proxy Code

Copy `credential_proxy.py` to `/opt/credential-proxy/` and create `/etc/openclaw-secrets/credential-proxy.yaml` (already done on this system).

### 5. Create systemd Service

On this host the unit is **`credential-proxy.service`** and runs the unified proxy:

```bash
sudo systemctl status credential-proxy
```

(If you’re recreating from scratch, prefer copying the existing unit from this machine rather than following the old `credential-proxy-telegram.service` instructions.)

### 6. Configure iptables (DNS drift safe + idempotent)

We **do not hardcode** Telegram IPs anymore.

Current approach:
- Use a dedicated `nat` chain (`CREDPROXY`)
- On proxy start, flush/repopulate **only that chain** from fresh DNS
- Keep `nat/OUTPUT` stable with exactly two ordered rules:
  1) bypass for proxy UID (prevents loops)
  2) jump to `CREDPROXY` restricted to `tcp/443`

Helper (installed into `/usr/local/sbin`):
- `apply-credential-proxy-iptables`

Systemd drop-in:
- `/etc/systemd/system/credential-proxy.service.d/iptables.conf`

Expected contents:
```ini
[Service]
PermissionsStartOnly=true
ExecStartPre=/usr/local/sbin/apply-credential-proxy-iptables
```

Reference artefacts (optional but useful for audit/debug):
- `/usr/local/sbin/gen-credential-proxy-iptables` (writes restore files)
- `/etc/credential-proxy/iptables.rules` + `/etc/credential-proxy/iptables.v6.rules`

### 7. Trust CA in OpenClaw

```bash
sudo mkdir -p /etc/systemd/system/openclaw-gateway.service.d
sudo tee /etc/systemd/system/openclaw-gateway.service.d/credential-proxy.conf > /dev/null <<'EOF'
[Service]
Environment=NODE_EXTRA_CA_CERTS=/etc/openclaw-secrets/certs/ca.crt
EOF

sudo systemctl daemon-reload
openclaw gateway restart
```

### 8. Configure Log Rotation

Ensure the `postrotate` references the correct service name (`credential-proxy`, not the old `credential-proxy-telegram`).

```bash
sudo tee /etc/logrotate.d/credential-proxy > /dev/null <<'EOF'
/var/log/credential-proxy/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 openclaw-secrets openclaw-secrets
    postrotate
        systemctl reload credential-proxy >/dev/null 2>&1 || true
    endscript
}
EOF
```

## Operations

### Check Status
```bash
sudo systemctl status credential-proxy
```

### View Logs
```bash
sudo tail -f /var/log/credential-proxy/credential-proxy.log
```

### Restart Proxy
```bash
sudo systemctl restart credential-proxy
```

### Check iptables Rules
```bash
sudo iptables -t nat -L OUTPUT -v --line-numbers
```

### Test Token Isolation
```bash
# Should FAIL - moluser cannot read the token
cat /etc/openclaw-secrets/telegram_token

# Should show process owned by openclaw-secrets
ps aux | grep telegram_proxy
```

## Security Audit

**What's protected:**
- ✅ Real credentials never visible to OpenClaw process
- ✅ Credentials not in config files, env vars, or logs
- ✅ UID-based filesystem permissions prevent access
- ✅ All API calls logged for audit

**Remaining risks:**
- ⚠️ iptables rules not persistent (manual restore needed after reboot)
- ⚠️ Self-signed CA cert trusted system-wide (only affects OpenClaw process via NODE_EXTRA_CA_CERTS)
- ⚠️ Proxy runs on localhost (not a risk - internal only)

## Quick Fixes (security maintenance)

There’s an idempotent helper script in this repo that applies the hardening fixes we made during the audit:

```bash
./scripts/credential-proxy-security-fixes.sh
```

It covers:
- logrotate service name fix
- removing legacy proxy file (`telegram_proxy.py`)
- fixing cert hosts dir permissions
- ensuring systemd drop-in exists for DNS refresh + applying generated iptables rules on service start

## Troubleshooting

### Proxy not starting
```bash
sudo journalctl -u credential-proxy -e
```

### OpenClaw can't connect
Check CA trust:
```bash
cat /etc/systemd/system/openclaw-gateway.service.d/credential-proxy.conf
```

### Traffic not being intercepted
```bash
# Check iptables rules exist
sudo iptables -t nat -L OUTPUT -v

# Watch proxy log while sending test message
sudo tail -f /var/log/credential-proxy/credential-proxy.log
```

### After reboot - iptables rules missing
```bash
# Re-apply using the idempotent helper
sudo /usr/local/sbin/apply-credential-proxy-iptables
```

## Future Enhancements

### Generic Credential Proxy Framework
Create a config-driven system:
```yaml
# /etc/openclaw-secrets/proxy-config.yaml
proxies:
  telegram:
    intercept: 149.154.166.110:443
    secret_file: /etc/openclaw-secrets/telegram_token
    inject_pattern: "path"  # /bot{TOKEN}/method
    
  openai:
    intercept: api.openai.com:443
    secret_file: /etc/openclaw-secrets/openai_key
    inject_pattern: "header"  # Authorization: Bearer {TOKEN}
```

Single proxy daemon handles all services with dynamic configuration.

## References

- Built: 2026-02-03
- Debugged issues: duplicate Content-Length headers, case-sensitive header matching
- Tested: Send/receive messages via Telegram working ✅
- Production status: Stable, logs rotating, no credential leaks detected

---

**Last updated:** 2026-02-07 by George (OpenClaw assistant)
