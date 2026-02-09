# Plan: Generalise Credential Proxy for Multi-Service Secrets + Add Brave Search Key

Date: 2026-02-08 (UTC)
Owner: George (assistant)

## Goals

1. **Generic multi-service credential proxy** driven by config (not hard-coded Telegram-only).
2. Add **Brave Search API key** support (header injection) as the second upstream.
3. Keep **real secrets out of the OpenClaw Gateway process**; Gateway uses placeholders.
4. Preserve existing **DNS drift mitigation** (regenerate interception rules from DNS each proxy start).
5. Maintain the existing hardening properties:
   - Dedicated `nat/CREDPROXY` chain rebuilt idempotently
   - Rule ordering guarantees (bypass first, then jump)
   - Restrict jump to `tcp dport 443`
   - Do not log secrets (scrub headers/query)

## Non-goals

- Full UI/CLI for editing upstreams (config files + restart is fine)
- Per-request dynamic routing beyond host/SNI/Host header
- Supporting non-HTTPS credentials

## Status / Completed (as of 2026-02-09)

### Completed

**Multi-service proxy**
- ✅ Proxy supports multiple services via `/etc/openclaw-secrets/credential-proxy.yaml`.
- ✅ Routing works even when TLS SNI is missing by falling back to the HTTP `Host` header.

**iptables interception (DNS-drift safe, ordered, idempotent)**
- ✅ Canonical mechanism is chain-based `apply-credential-proxy-iptables`.
- ✅ `HOSTS=` is supported (comma/space separated) and applied on proxy start via systemd `ExecStartPre`.
- ✅ `nat/OUTPUT` ordering: (1) bypass for proxy UID, (2) jump to `CREDPROXY` restricted to `tcp/443`.
- ✅ `nat/CREDPROXY` contains REDIRECT rules derived from fresh DNS for:
  - `api.telegram.org`
  - `api.search.brave.com`

**Telegram**
- ✅ Telegram token remains isolated (`/etc/openclaw-secrets/telegram_token`).
- ✅ Proxy handles `getUpdates` long-polling safely (increased upstream timeout).

**Brave Search**
- ✅ OpenClaw uses placeholder: `tools.web.search.apiKey = PROXY_INJECT`.
- ✅ Real key stored at `/etc/openclaw-secrets/brave_api_key`.
- ✅ Brave Search requests are intercepted and successfully proxied (HTTP 200 observed in proxy logs).

### Not implemented (still optional)
- ⏳ A dedicated idempotent “one-shot patch/rollback” script for Brave.
- ⏳ A formal `/etc/credential-proxy/upstreams.json` registry (current implementation uses YAML directly).

## Verification Checklist (passed)

- ✅ `sudo systemctl status credential-proxy` OK
- ✅ `sudo iptables -t nat -S OUTPUT` shows:
  - bypass rule first
  - jump to `CREDPROXY` second
  - jump restricted to `tcp dport 443`
- ✅ `sudo iptables -t nat -S CREDPROXY` shows REDIRECT rules for Brave + Telegram IPs
- ✅ Proxy logs show:
  - Telegram: repeated `REQ/RESP telegram ... /getUpdates` (HTTP 200)
  - Brave: `REQ/RESP brave-search ... /search` (HTTP 200)
  - No secrets in logs (spot-check)
- ✅ `web_search` works (Brave)
- ✅ Telegram polling still works
