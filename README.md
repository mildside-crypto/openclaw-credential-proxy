# openclaw-credential-proxy

Transparent, localhost-only HTTPS credential proxy used by OpenClaw to keep real API secrets out of the main OpenClaw process.

## What this repo contains

- `credential-proxy/` — the proxy implementation + unit templates + example config
- `scripts/` — helper scripts for:
  - generating/applying iptables interception rules safely (Docker-safe)
  - cleaning legacy rules
  - applying the set of security hardening fixes from the audit
- `docs/` — operational + design notes (Telegram is the reference integration)
- `patches/` — one-shot install helpers

## Threat model (why this exists)

OpenClaw runs as an unprivileged user and should never directly hold long-lived credentials where prompt injection, config leaks, or logs could expose them.

Instead:
- OpenClaw uses **placeholder** credentials (e.g. `PROXY_INJECT`).
- A separate `openclaw-secrets` OS user owns the real secrets under `/etc/openclaw-secrets/*`.
- Outbound HTTPS calls are intercepted via `iptables` and redirected to a local proxy.
- The proxy injects the real secret at egress and forwards to the real upstream.

## Status

- Telegram (Bot API) is confirmed working end-to-end through the proxy:
  - outbound `sendMessage` and media
  - inbound polling (`getUpdates`)
- iptables design is **idempotent** on restart (dedicated `CREDPROXY` chain).
- DNS drift is handled by regenerating/applying rules at proxy start.

## Quick start (high level)

See:
- `credential-proxy/README.md`
- `docs/CREDENTIAL-PROXY.md`

## Safety notes

This repo intentionally does **not** include any real secrets. Do not commit:
- `/etc/openclaw-secrets/*`
- `*.env` files with real keys
- private keys / tokens

## Licence

MIT — see `LICENSE`.
