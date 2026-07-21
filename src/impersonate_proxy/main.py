#!/usr/bin/env python3
"""HTTP/HTTPS proxy that impersonates browser TLS fingerprints.

Uses curl_cffi to re-issue every request with a browser TLS fingerprint
(JA3/JA4), defeating CDN fingerprint-based blocking of non-browser clients.

Supports both plain HTTP proxy requests and HTTPS CONNECT tunnels via
MITM with an auto-generated CA certificate stored in --ca-dir
(default: ~/.config/impersonate-proxy).

Usage:
    impersonate-proxy [--port PORT] [--host HOST] [--impersonate BROWSER]

    # As an HTTP proxy for curl:
    curl -x http://127.0.0.1:8899 https://example.com

    # As an HTTP proxy for ffmpeg:
    ffmpeg -http_proxy http://127.0.0.1:8899 -i https://stream.example.com/live.m3u8 output.mp4

Environment variables:
    IMPERSONATE_PROXY_PORT          Port to listen on (default: 8899)
    IMPERSONATE_PROXY_HOST          Host to bind to (default: 127.0.0.1)
    IMPERSONATE_PROXY_IMPERSONATE   Browser to impersonate (default: chrome)
"""

import argparse
import contextlib
import datetime
import http.client
import importlib.metadata
import ipaddress
import logging
import os
import queue
import select
import signal
import socket
import ssl
import sys
import tempfile
import threading
import urllib.parse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from curl_cffi import requests as cffi_requests

CHUNK_SIZE: int = 65536

_CA_KEY: ec.EllipticCurvePrivateKey | None = None
_CA_CERT: x509.Certificate | None = None
_LEAF_KEY: ec.EllipticCurvePrivateKey | None = None
_HOST_CERT_CACHE: OrderedDict[str, ssl.SSLContext] = OrderedDict()
_HOST_CERT_LOCK: threading.Lock = threading.Lock()
_HOST_CERT_MAX: int = 256
_SESSION_POOL_MAX: int = 32
_SESSION_POOL: queue.Queue[cffi_requests.Session] = queue.Queue(maxsize=_SESSION_POOL_MAX)
_IMPERSONATE: str = os.environ.get("IMPERSONATE_PROXY_IMPERSONATE", "chrome")
_HEADER_MODE: str = os.environ.get("IMPERSONATE_PROXY_HEADER_MODE", "enrich").lower()
if _HEADER_MODE not in ("passthrough", "enrich", "override"):
    _HEADER_MODE = "enrich"
_STRIP_CLIENT_LEAK_HEADERS: bool = os.environ.get("IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS", "false").lower() in (
    "true",
    "1",
    "yes",
)
_DEBUG: bool = False
_QUIET: bool = os.environ.get("IMPERSONATE_PROXY_QUIET", "false").lower() in ("true", "1", "yes")
logger: logging.Logger = logging.getLogger("impersonate-proxy")

_SENSITIVE_HEADERS: set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "token",
    "x-api-key",
}

# Header names dropped from client requests when --strip-client-leak-headers is active.
# These are middlebox-chain or app-tracing signals a client may realistically forward:
#   * X-Forwarded-* / Forwarded / Via  — added by reverse proxies; a client that sits
#     behind its own nginx may forward them onward.
#   * X-Request-ID / X-Correlation-ID  — added by app/framework tracing middleware.
# Applied in addition to the hop-by-hop skip list.
_CLIENT_LEAK_HEADERS: set[str] = {
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-server",
    "forwarded",
    "via",
    "x-request-id",
    "x-correlation-id",
}

# Headers that are normally inserted by a CDN/edge layer on ingress to the CDN
# (Cloudflare, Fastly, Akamai, etc.), not by clients. If one of these appears in a
# client request it indicates a misconfiguration (or replay of captured traffic).
# We surface it with a warning rather than silently stripping, so the misconfig is
# visible to the operator.
_CDN_INGRESS_HEADERS: set[str] = {
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
}

# Browser-default header values per impersonation profile. Used by both enrich
# (fill-if-absent) and override (replace) modes.
_BROWSER_HEADER_DEFAULTS: dict[str, dict[str, str]] = {
    "chrome": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
            "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    "firefox": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
}

# Non-browser User-Agent substrings that trigger UA replacement in enrich/override modes.
_NON_BROWSER_UA_MARKERS: tuple[str, ...] = (
    "curl",
    "python",
    "requests",
    "urllib",
    "wget",
    "httpclient",
    "go-http-client",
    "postman",
    "httpx",
    "aiohttp",
)

# Headers dropped entirely in override mode (browser navigation requests do not send
# these, so their presence is a bot telltale signal).
_OVERRIDE_DROP_HEADERS: set[str] = {
    "cache-control",
    "dnt",
    "connection",
}


def _show_identifying(val: str) -> str:
    """Return val if debug mode is active, otherwise '[redacted]'."""
    return val if _DEBUG else "[redacted]"


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with sensitive headers redacted."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADERS:
            sanitized[k] = "[redacted-sensitive]"
        else:
            sanitized[k] = v
    return sanitized


def _get_client_netblock(ip_str: str) -> str:
    """Return the /24 netblock for IPv4 or /64 netblock for IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        else:
            return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
    except Exception:
        return ip_str


def _init_ca(ca_dir: str | None = None) -> None:
    """Load or generate self-signed CA files in ca_dir for MITM CONNECT handling."""
    global _CA_KEY, _CA_CERT
    with _HOST_CERT_LOCK:
        _HOST_CERT_CACHE.clear()
    _clear_session_pool()
    if ca_dir is None:
        ca_dir = os.environ.get("IMPERSONATE_PROXY_CA_DIR") or os.path.expanduser("~/.config/impersonate-proxy")

    os.makedirs(ca_dir, exist_ok=True)

    key_path = os.path.join(ca_dir, "ca.key")
    cert_path = os.path.join(ca_dir, "ca.crt")

    try:
        # Try loading existing key and cert
        if os.path.exists(key_path) and os.path.exists(cert_path):
            with open(key_path, "rb") as f:
                _CA_KEY = serialization.load_pem_private_key(f.read(), password=None)  # type: ignore
            with open(cert_path, "rb") as f:
                _CA_CERT = x509.load_pem_x509_certificate(f.read())
            logger.info(f"Loaded existing CA key and certificate from {_show_identifying(ca_dir)}")
            return

        # Generate new key and cert
        _CA_KEY = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Impersonate Proxy CA"),
            ]
        )
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(_CA_KEY.public_key())
        _CA_CERT = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(_CA_KEY.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(subject_key_id, critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(_CA_KEY, hashes.SHA256())
        )

        # Save private key
        key_bytes = _CA_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Write key with owner-only permissions (mode 0o600)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key_bytes)

        # Save certificate
        cert_bytes = _CA_CERT.public_bytes(serialization.Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Generated and saved new CA key and certificate in {_show_identifying(ca_dir)}")

    except Exception as e:
        logger.warning(f"MITM CA init failed ({e}) — CONNECT will fall back to raw tunnel")


def _get_cert_for_host(hostname: str) -> ssl.SSLContext:
    """Get or create a cached SSL context for the given hostname."""
    with _HOST_CERT_LOCK:
        ctx = _HOST_CERT_CACHE.get(hostname)
        if ctx is not None:
            logger.debug(f"SSLContext cache hit for: {_show_identifying(hostname)}")
            return ctx

    try:
        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    global _LEAF_KEY
    if _LEAF_KEY is None:
        _LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
    key = _LEAF_KEY
    logger.debug(f"Generating dynamic host certificate for: {_show_identifying(hostname)}")
    cn = hostname[:64] if len(hostname) > 64 else hostname
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_CA_CERT.subject)  # type: ignore
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_CA_KEY.public_key()),  # type: ignore
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(_CA_KEY, hashes.SHA256())  # type: ignore
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = key_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_pem)
            cert_file = cf.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
            kf.write(key_pem)
            key_file = kf.name
        ctx.load_cert_chain(cert_file, key_file)
    finally:
        if cert_file:
            with contextlib.suppress(OSError):
                os.unlink(cert_file)
        if key_file:
            with contextlib.suppress(OSError):
                os.unlink(key_file)

    with _HOST_CERT_LOCK:
        # Double-check: another thread may have inserted while we generated
        existing = _HOST_CERT_CACHE.get(hostname)
        if existing is not None:
            return existing
        _HOST_CERT_CACHE[hostname] = ctx
        while len(_HOST_CERT_CACHE) > _HOST_CERT_MAX:
            evicted, _ = _HOST_CERT_CACHE.popitem(last=False)
            logger.debug(f"Evicted host from certificate cache: {_show_identifying(evicted)}")
    return ctx


def _clear_session_pool() -> None:
    """Clear all sessions in the pool."""
    while not _SESSION_POOL.empty():
        try:
            sess = _SESSION_POOL.get_nowait()
            sess.close()
        except queue.Empty:
            break


def _get_session() -> cffi_requests.Session:
    """Get a reused curl_cffi session from the pool or create a new one."""
    try:
        return _SESSION_POOL.get_nowait()
    except queue.Empty:
        return cffi_requests.Session(impersonate=_IMPERSONATE)


def _release_session(session: cffi_requests.Session, *, healthy: bool = True) -> None:
    """Release a session back to the pool if healthy; otherwise close and discard."""
    if healthy and not _SESSION_POOL.full():
        _SESSION_POOL.put_nowait(session)
    else:
        with contextlib.suppress(Exception):
            session.close()


def _profile_defaults(impersonate: str) -> dict[str, str]:
    """Return the browser-header defaults dict for the given impersonation profile."""
    if impersonate.startswith("firefox"):
        return _BROWSER_HEADER_DEFAULTS["firefox"]
    return _BROWSER_HEADER_DEFAULTS["chrome"]


def _is_non_browser_ua(ua: str) -> bool:
    """Return True if the User-Agent string looks like a non-browser client."""
    if not ua:
        return True
    ua_lower = ua.lower()
    return any(marker in ua_lower for marker in _NON_BROWSER_UA_MARKERS)


def _prepare_headers(
    headers: dict[str, str],
    impersonate: str,
    mode: str | None = None,
) -> dict[str, str]:
    """Prepare outgoing headers according to the active header mode.

    Modes (mutually exclusive):
      - "passthrough": forward client headers untouched.
      - "enrich":     fill missing browser headers; replace non-browser UA.
      - "override":   replace the curated browser-header set; drop nav-mismatch
                      tells (Cache-Control, DNT, Connection); preserve cookies,
                      auth, referer, content-type, cache-conditionals, etc.
    """
    if mode is None:
        mode = _HEADER_MODE
    if mode == "passthrough":
        return dict(headers)

    if mode not in ("enrich", "override"):
        # Defensive: unknown modes fall back to enrich semantics.
        mode = "enrich"

    defaults = _profile_defaults(impersonate)
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}
    out: dict[str, str] = dict(headers)

    # ---- User-Agent handling ----
    # enrich:   replace only when UA looks non-browser (curl, python, etc.).
    # override: always replace with the profile default UA.
    ua_key, ua_val = headers_lower.get("user-agent", ("User-Agent", ""))
    replace_ua = mode == "override" or _is_non_browser_ua(ua_val)
    if replace_ua:
        if "user-agent" in headers_lower:
            out[ua_key] = defaults["User-Agent"]
        else:
            out["User-Agent"] = defaults["User-Agent"]

    if mode == "enrich":
        # Additive: only inject headers that are absent.
        for k, v in defaults.items():
            if k.lower() == "user-agent":
                continue  # already handled above
            if k.lower() not in headers_lower:
                out[k] = v
        return out

    # mode == "override"
    # Replace the curated browser-header set with profile defaults.
    for k, v in defaults.items():
        if k.lower() == "user-agent":
            continue  # already handled above
        if k in out:
            out[k] = v
        elif k.lower() in headers_lower:
            # Replace using the client's original casing.
            client_key = headers_lower[k.lower()][0]
            out[client_key] = v
        else:
            out[k] = v

    # Drop navigation-mismatch tells. Connection is dropped with a warning, since
    # curl_cffi manages its own Connection header and a client-supplied value may
    # conflict with HTTP/2 semantics.
    for drop_lower in _OVERRIDE_DROP_HEADERS:
        if drop_lower in headers_lower:
            client_key = headers_lower[drop_lower][0]
            if drop_lower == "connection":
                logger.warning(
                    "override-headers: dropping client '%s' header — curl_cffi manages "
                    "Connection state; client-supplied value would conflict with HTTP/2.",
                    client_key,
                )
            else:
                logger.debug(
                    "override-headers: dropping client '%s' header (browser navigation requests do not send it).",
                    client_key,
                )
            out.pop(client_key, None)

    return out


def _strip_leak_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop middlebox-chain / tracing leak headers when --strip-client-leak-headers is active.

    Headers in :data:`_CLIENT_LEAK_HEADERS` are dropped. Headers in
    :data:`_CDN_INGRESS_HEADERS` are *not* stripped — their presence in a client
    request indicates a misconfiguration (or replay of captured traffic), so we
    log a warning and forward them unchanged to make the misconfig visible to the
    operator.
    """
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in _CLIENT_LEAK_HEADERS:
            continue
        if kl in _CDN_INGRESS_HEADERS:
            logger.warning(
                "strip-client-leak-headers: client sent '%s' — this CDN-ingress header is "
                "normally added by a CDN/edge layer, not by a client; its presence indicates "
                "a misconfiguration or replay of captured traffic. Forwarding as-is.",
                k,
            )
        out[k] = v
    return out


def _do_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    allow_redirects: bool = False,
) -> cffi_requests.Response | None:
    """Issue a request via curl_cffi with TLS impersonation."""
    session = _get_session()
    try:
        out_headers = _prepare_headers(headers, _IMPERSONATE, _HEADER_MODE)
        if _STRIP_CLIENT_LEAK_HEADERS:
            out_headers = _strip_leak_headers(out_headers)
        logger.debug(
            f"Issuing request: {method} {_show_identifying(url)} "
            f"(header_mode={_HEADER_MODE}, strip_leak={_STRIP_CLIENT_LEAK_HEADERS}, "
            f"headers={_sanitize_headers(out_headers)})"
        )
        resp = session.request(
            method=method,
            url=url,
            headers=out_headers,
            data=body,
            timeout=(10, 300),
            allow_redirects=allow_redirects,
            stream=True,
        )
        orig_close = resp.close
        session_released = False

        def custom_close():
            nonlocal session_released
            orig_close()
            if not session_released:
                _release_session(session)
                session_released = True

        resp.close = custom_close
        return resp
    except Exception as e:
        logger.error(f"Upstream request failed for {_show_identifying(url)}: {e}")
        _release_session(session, healthy=False)
        return None


def _raw_tunnel(client_sock: socket.socket, host: str, port: int) -> None:
    """Relay bytes between client and upstream without inspection."""
    logger.info(f"Establishing raw tunnel to: {_show_identifying(f'{host}:{port}')}")
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        logger.error(f"Raw tunnel connect failed for {_show_identifying(f'{host}:{port}')}: {e}")
        return
    try:
        while True:
            readable, _, _ = select.select([client_sock, upstream], [], [], 30)
            if not readable:
                break
            for sock in readable:
                data = sock.recv(CHUNK_SIZE)
                if not data:
                    raise ConnectionError("closed")
                if sock is client_sock:
                    upstream.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            upstream.shutdown(socket.SHUT_RDWR)
        upstream.close()


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_CONNECT(self) -> None:
        host, _, port_str = self.path.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            logger.warning(f"CONNECT bad host:port: {_show_identifying(self.path[:120])}")
            self.send_error(400, "Bad host:port")
            return

        client_ip = self.client_address[0]
        netblock = _get_client_netblock(client_ip)
        if not _QUIET:
            logger.info(f"CONNECT request from {netblock} to {host}")

        self.send_response(200, "Connection established")
        self.end_headers()

        if _CA_KEY is None:
            if not _QUIET:
                logger.info(f"CONNECT {_show_identifying(f'{host}:{port}')} (raw tunnel, no impersonation)")
            _raw_tunnel(self.connection, host, port)
            self.close_connection = True
            return

        # MITM: wrap the client socket with TLS using a cached forged cert
        try:
            ctx = _get_cert_for_host(host)
            client_tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            logger.error(f"MITM TLS wrap error for {_show_identifying(host)}: {e}")
            self.close_connection = True
            return

        # Read HTTP requests from the decrypted TLS stream and proxy via curl_cffi
        rfile = wfile = None
        try:
            rfile = client_tls.makefile("rb")
            wfile = client_tls.makefile("wb")

            while True:
                req_line = rfile.readline(8193)
                if not req_line or req_line.strip() == b"":
                    break

                parts = req_line.decode("latin-1").strip().split(" ", 2)
                if len(parts) < 2:
                    break
                method = parts[0]
                path = parts[1]

                # Read headers
                headers = {}
                while True:
                    hline = rfile.readline(8193)
                    if hline in (b"\r\n", b"\n", b""):
                        break
                    if b":" in hline:
                        k, v = hline.decode("latin-1").split(":", 1)
                        headers[k.strip()] = v.strip()

                # Read body if present
                body = None
                cl = headers.get("Content-Length")
                if cl:
                    try:
                        body = rfile.read(int(cl))
                    except ValueError:
                        logger.warning("CONNECT-MITM: invalid Content-Length header, ignoring body")

                # Build full URL
                scheme = "https"
                if port == 443:
                    url = f"{scheme}://{host}{path}"
                else:
                    url = f"{scheme}://{host}:{port}{path}"

                # Filter hop-by-hop headers
                skip = {
                    "host",
                    "proxy-connection",
                    "connection",
                    "keep-alive",
                    "transfer-encoding",
                    "te",
                    "trailer",
                    "upgrade",
                    "proxy-authorization",
                    "proxy-authenticate",
                }
                fwd_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

                logger.debug(
                    f"CONNECT-MITM proxying request: {method} {_show_identifying(url)} (headers={_sanitize_headers(fwd_headers)})"
                )

                r = _do_request(method, url, fwd_headers, body, allow_redirects=False)
                if r is None:
                    wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    wfile.flush()
                    break

                try:
                    skip_h = {"transfer-encoding", "content-encoding", "content-length", "connection", "keep-alive"}
                    resp_headers = [(k, v) for k, v in r.headers.items() if k.lower() not in skip_h]
                    status_code = r.status_code
                    reason = http.client.responses.get(status_code, "Unknown")
                    wfile.write(f"HTTP/1.1 {status_code} {reason}\r\n".encode())
                    for k, v in resp_headers:
                        wfile.write(f"{k}: {v}\r\n".encode())
                    wfile.write(b"Transfer-Encoding: chunked\r\n")
                    wfile.write(b"Connection: close\r\n\r\n")
                    for chunk in r.iter_content():
                        if chunk:
                            wfile.write(f"{len(chunk):x}\r\n".encode())
                            wfile.write(chunk)
                            wfile.write(b"\r\n")
                    wfile.write(b"0\r\n\r\n")
                    wfile.flush()
                    if (status_code >= 400 or _DEBUG) and not _QUIET:
                        logger.info(f"CONNECT-MITM {method} {_show_identifying(url)} -> {status_code}")
                finally:
                    r.close()
                # Connection: close was sent — break so the TLS socket
                # closes and the client sees EOF (end-of-body).
                break

        except Exception as e:
            logger.error(f"MITM handler error: {e}")
        finally:
            if rfile:
                with contextlib.suppress(Exception):
                    rfile.close()
            if wfile:
                with contextlib.suppress(Exception):
                    wfile.close()
            with contextlib.suppress(Exception):
                client_tls.shutdown(socket.SHUT_RDWR)
            client_tls.close()

        self.close_connection = True

    def _proxy(self) -> None:
        url = self.path
        if not url.startswith("http"):
            logger.warning(f"HTTP Proxy bad request: {_show_identifying(url)}")
            self.send_error(400, "Absolute URL required")
            return

        client_ip = self.client_address[0]
        netblock = _get_client_netblock(client_ip)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if not _QUIET:
            logger.info(f"{self.command} request from {netblock} to {host}")

        skip = {
            "host",
            "proxy-connection",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
            "proxy-authenticate",
        }
        headers = {}
        for key, val in self.headers.items():
            if key.lower() not in skip:
                headers[key] = val

        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        logger.debug(
            f"HTTP Proxy proxying request: {self.command} {_show_identifying(url)} (headers={_sanitize_headers(headers)})"
        )

        resp = _do_request(self.command, url, headers, body)
        if resp is None:
            logger.error(f"HTTP Proxy upstream request failed for: {_show_identifying(url)}")
            self.send_error(502, "Upstream request failed")
            return

        try:
            is_head = self.command == "HEAD"
            skip_resp = {"transfer-encoding", "content-encoding", "content-length"}
            resp_headers = [(k, v or "") for k, v in resp.headers.items() if k.lower() not in skip_resp]
            if is_head:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                cl = resp.headers.get("content-length")
                if cl:
                    self.send_header("Content-Length", cl)
                self.end_headers()
            else:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in resp.iter_content():
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            if not _QUIET:
                logger.info(f"HTTP Proxy {self.command} {_show_identifying(url)} -> {resp.status_code}")
        finally:
            resp.close()

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_HEAD = _proxy
    do_OPTIONS = _proxy


def run(
    host: str = "127.0.0.1",
    port: int = 8899,
    impersonate: str = "chrome",
    ca_dir: str | None = None,
    header_mode: str = "enrich",
    strip_client_leak_headers: bool = False,
    debug: bool = False,
    quiet: bool = False,
) -> None:
    global _IMPERSONATE, _HEADER_MODE, _STRIP_CLIENT_LEAK_HEADERS, _DEBUG, _QUIET
    _IMPERSONATE = impersonate
    _HEADER_MODE = header_mode
    _STRIP_CLIENT_LEAK_HEADERS = strip_client_leak_headers
    _DEBUG = debug
    _QUIET = quiet

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,  # Overwrites default pytest handler config in tests
    )

    _init_ca(ca_dir)

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadingHTTPServer((host, port), ProxyHandler)
    try:
        curl_cffi_version = importlib.metadata.version("curl_cffi")
    except importlib.metadata.PackageNotFoundError:
        curl_cffi_version = "unknown"

    logger.info(
        f"impersonate-proxy listening on {host}:{port} "
        f"(impersonating {impersonate}, header_mode={header_mode}, "
        f"strip_client_leak_headers={strip_client_leak_headers}, debug={debug}, "
        f"curl_cffi={curl_cffi_version})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    finally:
        server.server_close()


def main() -> None:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    parser = argparse.ArgumentParser(description="HTTP/HTTPS proxy that impersonates browser TLS fingerprints")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_PORT", "8899")),
        help="Port to listen on (default: 8899 or IMPERSONATE_PROXY_PORT)",
    )
    parser.add_argument(
        "--host",
        "-H",
        default=os.environ.get("IMPERSONATE_PROXY_HOST", "127.0.0.1"),
        help="Host to bind to (default: 127.0.0.1 or IMPERSONATE_PROXY_HOST)",
    )
    parser.add_argument(
        "--impersonate",
        "-i",
        default=os.environ.get("IMPERSONATE_PROXY_IMPERSONATE", "chrome"),
        help="Browser to impersonate (chrome, firefox, etc. Default: chrome or IMPERSONATE_PROXY_IMPERSONATE)",
    )
    header_mode_group = parser.add_mutually_exclusive_group()
    header_mode_group.add_argument(
        "--passthrough-headers",
        action="store_const",
        dest="header_mode",
        const="passthrough",
        default=os.environ.get("IMPERSONATE_PROXY_HEADER_MODE", "enrich").lower(),
        help="Forward client headers untouched; curl_cffi only sets TLS-impersonation "
        "headers. Equivalent to the previous --no-enrich-headers behaviour.",
    )
    header_mode_group.add_argument(
        "--enrich-headers",
        action="store_const",
        dest="header_mode",
        const="enrich",
        help="Fill missing browser headers and replace non-browser User-Agents. [DEFAULT]",
    )
    header_mode_group.add_argument(
        "--override-headers",
        action="store_const",
        dest="header_mode",
        const="override",
        help="Replace the curated browser-header set (Accept, Sec-*, etc.) with the "
        "impersonation profile defaults and drop nav-mismatch tells (Cache-Control, "
        "DNT, Connection). Use for clients that leak non-browser signals (e.g. SearXNG).",
    )
    parser.add_argument(
        "--strip-client-leak-headers",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS", "false").lower() in ("true", "1", "yes"),
        help="Drop middlebox/identity-leak headers (X-Forwarded-*, Forwarded, Via, "
        "X-Real-IP, True-Client-IP, CF-Connecting-IP, X-Cluster-Client-IP, "
        "Fastly-Client-IP, X-Request-ID, X-Correlation-ID). Combinable with any "
        "header mode. Or IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS=true",
    )
    parser.add_argument(
        "--ca-dir",
        "-c",
        default=os.environ.get("IMPERSONATE_PROXY_CA_DIR"),
        help="Directory to store/load CA certificate and key (default: ~/.config/impersonate-proxy or IMPERSONATE_PROXY_CA_DIR)",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_DEBUG", "").lower() in ("true", "1", "yes"),
        help="Enable verbose debug logging (unredacts URLs/hosts in logs) or IMPERSONATE_PROXY_DEBUG=true",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_QUIET", "false").lower() in ("true", "1", "yes"),
        help="Disable logging of request traffic or IMPERSONATE_PROXY_QUIET=true",
    )
    args = parser.parse_args()
    header_mode = args.header_mode if args.header_mode in ("passthrough", "enrich", "override") else "enrich"
    run(
        host=args.host,
        port=args.port,
        impersonate=args.impersonate,
        ca_dir=args.ca_dir,
        header_mode=header_mode,
        strip_client_leak_headers=args.strip_client_leak_headers,
        debug=args.debug,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()
