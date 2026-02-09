#!/usr/bin/env python3
"""Credential Proxy (multi-service, SNI)

Purpose
- Transparent TLS termination + HTTP proxy for multiple upstream services.
- Keeps real credentials in /etc/openclaw-secrets, readable only by a dedicated user.
- Routes by SNI hostname.

Initial supported service modes:
- telegram_path_token: rewrite /bot<token>/ and /file/bot<token>/ segments using token from token_file.
- bearer_header: inject/replace an Authorization-style header with secret from secret_file.

Design notes
- One listening port.
- Per-SNI certificate via servername_callback.
- Forwards upstream using the same hostname (SNI) with normal TLS verification.

"""

import argparse
import asyncio
import logging
import os
import re
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


@dataclass
class Service:
    name: str
    match_sni: list[str]
    upstream_host: str
    upstream_port: int
    mode: str
    token_file: Optional[str] = None
    secret_file: Optional[str] = None
    header_name: str = "Authorization"
    header_value_prefix: str = "Bearer "


class Proxy:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.cfg = self._load_config(config_path)

        self.listen_host = self.cfg["listen"]["host"]
        self.listen_port = int(self.cfg["listen"]["port"])
        self.allowed_sources = set(self.cfg["listen"].get("allowed_sources", ["127.0.0.1", "::1"]))

        self.log_dir = Path(self.cfg["logging"]["dir"])
        self.log_file = self.cfg["logging"]["file"]
        self.log_level = self.cfg["logging"].get("level", "INFO").upper()

        self.certs_dir = Path(self.cfg["certs"]["dir"])
        self.ca_key = Path(self.cfg["certs"]["ca_key"])
        self.ca_crt = Path(self.cfg["certs"]["ca_crt"])
        self.hosts_dir = Path(self.cfg["certs"]["hosts_dir"])

        self.services = self._parse_services(self.cfg.get("services", {}))
        self.sni_map = self._build_sni_map(self.services)

        self.logger = self._setup_logging()

        self._ssl_ctx_default = None  # set in start()
        self._ssl_ctx_cache: dict[str, ssl.SSLContext] = {}

    def _setup_logging(self) -> logging.Logger:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("credential-proxy")
        logger.setLevel(getattr(logging, self.log_level, logging.INFO))

        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        fh = logging.FileHandler(self.log_dir / self.log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

        return logger

    def _load_config(self, path: str) -> Dict[str, Any]:
        if yaml is None:
            raise RuntimeError("PyYAML is required. Install with: sudo apt-get install -y python3-yaml")
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        return yaml.safe_load(p.read_text())

    def _parse_services(self, services_cfg: Dict[str, Any]) -> list[Service]:
        out: list[Service] = []
        for name, scfg in services_cfg.items():
            out.append(
                Service(
                    name=name,
                    match_sni=list(scfg.get("match_sni", [])),
                    upstream_host=str(scfg.get("upstream_host")),
                    upstream_port=int(scfg.get("upstream_port", 443)),
                    mode=str(scfg.get("mode")),
                    token_file=scfg.get("token_file"),
                    secret_file=scfg.get("secret_file"),
                    header_name=str(scfg.get("header_name", "Authorization")),
                    header_value_prefix=str(scfg.get("header_value_prefix", "Bearer ")),
                )
            )
        return out

    def _build_sni_map(self, services: list[Service]) -> dict[str, Service]:
        m: dict[str, Service] = {}
        for s in services:
            for host in s.match_sni:
                m[host.lower()] = s
        return m

    def _validate_hostname(self, host: str) -> str:
        """Validate and normalise hostnames used for SNI and cert generation."""
        host = (host or "").lower().strip().rstrip(".")
        if len(host) == 0 or len(host) > 253:
            raise ValueError(f"Invalid hostname length: {host!r}")
        # Conservative RFC 1035-ish pattern; enough to prevent weird injection/paths.
        if not re.match(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*$", host):
            raise ValueError(f"Invalid hostname: {host!r}")
        return host

    # ----- cert management -----

    def _ensure_ca(self) -> None:
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.hosts_dir.mkdir(parents=True, exist_ok=True)
        if self.ca_crt.exists() and self.ca_key.exists():
            return
        raise RuntimeError(
            f"CA files missing. Expected {self.ca_crt} and {self.ca_key}. "
            "(You can reuse the existing CA from the telegram-only proxy.)"
        )

    def _host_cert_paths(self, host: str) -> tuple[Path, Path]:
        safe = host.lower()
        return self.hosts_dir / f"{safe}.crt", self.hosts_dir / f"{safe}.key"

    def _ensure_host_cert(self, host: str) -> tuple[str, str]:
        host = self._validate_hostname(host)
        crt, key = self._host_cert_paths(host)
        if crt.exists() and key.exists():
            return str(crt), str(key)

        # Generate leaf cert signed by our CA (openssl).
        tmp_dir = self.hosts_dir / ".tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        csr = tmp_dir / f"{host}.csr"
        ext = tmp_dir / f"{host}.ext"

        ext.write_text(
            "\n".join(
                [
                    "basicConstraints=CA:FALSE",
                    f"subjectAltName=DNS:{host}",
                ]
            )
            + "\n"
        )

        crt_tmp = self.hosts_dir / f".{host}.crt.tmp"
        key_tmp = self.hosts_dir / f".{host}.key.tmp"

        def run(cmd: list[str]) -> None:
            p = subprocess.run(cmd, capture_output=True, text=True)
            if p.returncode != 0:
                raise RuntimeError(f"openssl failed: {' '.join(cmd)}\nstdout: {p.stdout}\nstderr: {p.stderr}")

        try:
            run(["openssl", "genrsa", "-out", str(key_tmp), "2048"])
            run(["openssl", "req", "-new", "-key", str(key_tmp), "-out", str(csr), "-subj", f"/CN={host}"])
            serial = self.hosts_dir / "ca.srl"
            run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(self.ca_crt),
                    "-CAkey",
                    str(self.ca_key),
                    "-CAserial",
                    str(serial),
                    "-CAcreateserial",
                    "-out",
                    str(crt_tmp),
                    "-days",
                    "825",
                    "-sha256",
                    "-extfile",
                    str(ext),
                ]
            )

            # Basic sanity checks: non-empty PEM files
            if crt_tmp.stat().st_size < 64:
                raise RuntimeError(f"generated cert too small: {crt_tmp}")
            if key_tmp.stat().st_size < 64:
                raise RuntimeError(f"generated key too small: {key_tmp}")

            os.replace(key_tmp, key)
            os.replace(crt_tmp, crt)
            os.chmod(key, 0o600)
            os.chmod(crt, 0o644)
            return str(crt), str(key)
        except Exception:
            # Clean up partials to avoid PEM lib errors on next boot
            for p in (crt_tmp, key_tmp, crt, key):
                try:
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
            raise

    def _ssl_ctx_for_host(self, host: str) -> ssl.SSLContext:
        host_l = self._validate_hostname(host)
        if host_l in self._ssl_ctx_cache:
            return self._ssl_ctx_cache[host_l]

        crt, key = self._ensure_host_cert(host_l)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self._ssl_ctx_cache[host_l] = ctx
        return ctx

    # ----- request transforms -----

    def _load_secret(self, path: str) -> str:
        p = Path(path)
        s = p.read_text().strip()
        return s

    def _telegram_inject_token_path(self, path: str, token: str) -> str:
        # /bot<TOKEN>/method
        path = re.sub(r"/bot([^/]+)/", f"/bot{token}/", path, count=1)
        # /file/bot<TOKEN>/...
        path = re.sub(r"/file/bot([^/]+)/", f"/file/bot{token}/", path, count=1)
        return path

    def _inject_bearer_header(self, headers: dict[str, str], header_name: str, prefix: str, secret: str) -> dict[str, str]:
        out = dict(headers)
        # Remove any existing header (case-insensitive)
        to_del = [k for k in out.keys() if k.lower() == header_name.lower()]
        for k in to_del:
            del out[k]
        out[header_name] = f"{prefix}{secret}"
        return out

    # ----- HTTP parsing/forwarding -----

    async def _read_http_request(self, reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str], bytes]:
        req_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        if not req_line:
            raise ValueError("empty request")
        req_line_s = req_line.decode("utf-8", errors="replace").strip()
        parts = req_line_s.split(" ")
        if len(parts) < 2:
            raise ValueError(f"bad request line: {req_line_s}")
        method, path = parts[0], parts[1]

        headers: dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                break
            line_s = line.decode("utf-8", errors="replace").strip()
            if not line_s:
                break
            if ":" in line_s:
                k, v = line_s.split(":", 1)
                headers[k.strip()] = v.strip()

        content_length: int | None = None
        chunked = False

        for k, v in headers.items():
            lk = k.lower()
            if lk == "content-length":
                content_length = int(v)
            elif lk == "transfer-encoding" and "chunked" in v.lower():
                chunked = True

        async def read_chunked_body() -> bytes:
            out = b""
            while True:
                # chunk size line (may include extensions after ;)
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not line:
                    break
                size_str = line.decode("ascii", errors="replace").strip().split(";", 1)[0]
                if not size_str:
                    continue
                size = int(size_str, 16)

                if size == 0:
                    # consume trailers (optional) until blank line
                    while True:
                        trailer = await asyncio.wait_for(reader.readline(), timeout=10.0)
                        if not trailer or trailer in (b"\r\n", b"\n"):
                            break
                    break

                chunk = await asyncio.wait_for(reader.readexactly(size), timeout=30.0)
                out += chunk
                # each chunk is followed by CRLF
                await asyncio.wait_for(reader.readexactly(2), timeout=10.0)

            return out

        body = b""
        if chunked:
            body = await read_chunked_body()
        elif content_length is not None and content_length > 0:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=30.0)

        return method, path, headers, body

    async def _forward(
        self,
        upstream_host: str,
        upstream_port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        *,
        timeout: float = 30.0,
    ) -> tuple[int, dict[str, str], bytes]:
        """Forward request upstream and return (status, headers, body).

        Note: some upstreams (notably Telegram getUpdates long-poll) hold the
        connection open for >30s. Callers should pass a higher timeout.
        """

        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(upstream_host, upstream_port, ssl=ssl_ctx, server_hostname=upstream_host),
            timeout=timeout,
        )
        try:
            # Build HTTP/1.1 request
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {upstream_host}",
            ]

            for k, v in headers.items():
                if k.lower() in ("host", "connection", "keep-alive", "transfer-encoding", "content-length"):
                    continue
                lines.append(f"{k}: {v}")

            if body:
                lines.append(f"Content-Length: {len(body)}")
            lines.append("Connection: close")
            lines.append("")
            lines.append("")

            data = "\r\n".join(lines).encode("utf-8") + body
            writer.write(data)
            await writer.drain()

            # Read until headers
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                resp += chunk

            header_end = resp.find(b"\r\n\r\n")
            if header_end == -1:
                raise ValueError("invalid upstream response")

            header_text = resp[:header_end].decode("utf-8", errors="replace")
            body_bytes = resp[header_end + 4 :]

            lines = header_text.split("\r\n")
            status_parts = lines[0].split(" ", 2)
            status_code = int(status_parts[1])

            resp_headers: dict[str, str] = {}
            content_length = None
            chunked = False
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip()] = v.strip()
            for k, v in resp_headers.items():
                if k.lower() == "content-length":
                    content_length = int(v)
                if k.lower() == "transfer-encoding" and v.lower() == "chunked":
                    chunked = True

            if chunked:
                # Read rest then dechunk
                more = await reader.read()
                body_bytes += more
                body_bytes = self._dechunk(body_bytes)
                # remove TE
                for k in list(resp_headers.keys()):
                    if k.lower() == "transfer-encoding":
                        del resp_headers[k]
            elif content_length is not None:
                # read remaining
                while len(body_bytes) < content_length:
                    chunk = await asyncio.wait_for(reader.read(min(65536, content_length - len(body_bytes))), timeout=timeout)
                    if not chunk:
                        break
                    body_bytes += chunk
            else:
                # no length; read to EOF
                more = await reader.read()
                body_bytes += more

            return status_code, resp_headers, body_bytes
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _dechunk(self, data: bytes) -> bytes:
        out = b""
        pos = 0
        while True:
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                break
            size_str = data[pos:line_end].decode("ascii", errors="replace").strip()
            try:
                size = int(size_str, 16)
            except Exception:
                break
            pos = line_end + 2
            if size == 0:
                break
            out += data[pos : pos + size]
            pos += size + 2
        return out

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"

        sslobj = writer.get_extra_info("ssl_object")
        sni = None
        try:
            if sslobj is not None:
                # NOTE: On some transparent interception paths, SNI may be missing.
                # Python's server-side ssl_object often does not reliably expose the
                # client's SNI as `server_hostname`, so we treat this as best-effort.
                sni = getattr(sslobj, "server_hostname", None)
        except Exception:
            sni = None
        sni_l = (sni or "").lower()

        try:
            if peer_ip not in self.allowed_sources:
                self.logger.warning(f"Reject source={peer_ip} sni={sni_l}")
                writer.close(); await writer.wait_closed(); return

            # Read HTTP request first so we can route by Host header when SNI is missing.
            method, path, headers, body = await self._read_http_request(reader)

            host_hdr = ""
            for k, v in headers.items():
                if k.lower() == "host":
                    host_hdr = v.split(":", 1)[0].strip().lower()
                    break

            svc = None
            if sni_l:
                svc = self.sni_map.get(sni_l)
            if svc is None and host_hdr:
                svc = self.sni_map.get(host_hdr)

            # Final fallback: only if exactly one service is configured.
            if svc is None and len(self.services) == 1:
                svc = self.services[0]
                self.logger.info(f"SNI missing; falling back to service={svc.name}")

            if svc is None:
                self.logger.warning(f"No service for sni={sni_l} host={host_hdr}; closing")
                writer.close(); await writer.wait_closed(); return

            # Sanitised log
            method_name = path.split("/")[-1].split("?")[0]
            self.logger.info(f"REQ {svc.name} {method} /{method_name}")

            # Transform
            if svc.mode == "telegram_path_token":
                if not svc.token_file:
                    raise RuntimeError("token_file required for telegram_path_token")
                token = self._load_secret(svc.token_file)
                path = self._telegram_inject_token_path(path, token)
            elif svc.mode == "bearer_header":
                if not svc.secret_file:
                    raise RuntimeError("secret_file required for bearer_header")
                secret = self._load_secret(svc.secret_file)
                headers = self._inject_bearer_header(headers, svc.header_name, svc.header_value_prefix, secret)
            else:
                raise RuntimeError(f"Unknown mode: {svc.mode}")

            # Telegram getUpdates uses long-polling (can hold the connection open for a while).
            # Use a higher timeout so we don't abort healthy long-poll requests.
            fwd_timeout = 90.0 if (svc.name == "telegram" and "/getUpdates" in path) else 30.0
            status, resp_headers, resp_body = await self._forward(
                svc.upstream_host,
                svc.upstream_port,
                method,
                path,
                headers,
                body,
                timeout=fwd_timeout,
            )

            # Build response
            resp_lines = [f"HTTP/1.1 {status} OK"]
            for k, v in resp_headers.items():
                if k.lower() in ("transfer-encoding", "connection", "content-length"):
                    continue
                resp_lines.append(f"{k}: {v}")
            resp_lines.append(f"Content-Length: {len(resp_body)}")
            resp_lines.append("Connection: close")
            resp_lines.append("")
            resp_lines.append("")

            writer.write("\r\n".join(resp_lines).encode("utf-8") + resp_body)
            await writer.drain()

            self.logger.info(f"RESP {svc.name} {status} /{method_name}")
        except Exception as e:
            # Some exceptions (notably asyncio.TimeoutError) have empty str().
            msg = (str(e) or repr(e)).strip()

            # Avoid leaking token-shaped path segments into logs (even if fake).
            msg = re.sub(r"/bot[^/]+/", "/bot<TOKEN>/", msg)
            msg = re.sub(r"/file/bot[^/]+/", "/file/bot<TOKEN>/", msg)

            # Sanitisation can erase the entire message; ensure it's never blank.
            msg = msg.strip()
            if not msg:
                msg = repr(e)

            # Always include the exception type for easier debugging.
            msg = f"{type(e).__name__}: {msg}"

            self.logger.error(f"ERR source={peer_ip} sni={sni_l}: {msg}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self._ensure_ca()

        # Default context: use a "fallback" cert (first service) to start the server,
        # then swap per SNI in callback.
        if not self.services:
            raise RuntimeError("No services configured")

        first_host = self.services[0].match_sni[0]
        default_ctx = self._ssl_ctx_for_host(first_host)

        def sni_cb(sslobj: ssl.SSLObject, servername: str, initial_ctx: ssl.SSLContext):
            try:
                host = self._validate_hostname(servername or "")
                if host in self.sni_map:
                    sslobj.context = self._ssl_ctx_for_host(host)
            except Exception as e:
                self.logger.error(f"SNI callback error for {servername}: {e}")

        default_ctx.set_servername_callback(sni_cb)
        self._ssl_ctx_default = default_ctx

        server = await asyncio.start_server(self.handle_client, self.listen_host, self.listen_port, ssl=default_ctx)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
        self.logger.info(f"Listening on {addrs} (TLS, SNI routing)")

        async with server:
            await server.serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    proxy = Proxy(args.config)
    asyncio.run(proxy.start())


if __name__ == "__main__":
    main()
