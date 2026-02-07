# Credential Proxy (multi-service, SNI)

This folder contains a cut-over plan + deployment scripts to move from the current Telegram-only transparent TLS proxy to a **single-port, SNI-routed** multi-service credential proxy.

Goals:
- OpenClaw never sees real credentials (tokens/API keys live in `/etc/openclaw-secrets/*`, readable by `openclaw-secrets` only).
- One daemon, many services (Telegram now; extendable later via config).
- Transparent interception via iptables REDIRECT (per-destination IP).
- Rules persist across reboot via `iptables-restore` under systemd.

## Files
- `credential_proxy.py` – new proxy daemon (TLS termination with SNI; per-service request transforms).
- `config.example.yaml` – example config.
- `deploy.sh` – copies files into place and installs systemd units (you run with sudo).
- `gen-iptables-rules.sh` – resolves hostnames to current A records and writes an `iptables-restore` rules file.
- `units/credential-proxy.service` – systemd unit for proxy.
- `units/credential-proxy-iptables.service` – systemd oneshot to restore rules at boot.

## Current state assumptions
- Existing token at `/etc/openclaw-secrets/telegram_token`.
- CA trust via `NODE_EXTRA_CA_CERTS=/etc/openclaw-secrets/certs/ca.crt` (or will be set).
- Proxy runs as `openclaw-secrets`.

## Rollback
1) Stop services:
- `sudo systemctl disable --now credential-proxy.service credential-proxy-iptables.service`

2) Remove redirect rules (best-effort):
- `sudo /etc/credential-proxy/iptables.remove.sh || true`
- `sudo /etc/credential-proxy/iptables.v6.remove.sh || true`

3) Re-enable old telegram-only proxy (if you had it):
- `sudo systemctl enable --now <old-unit-name>`
