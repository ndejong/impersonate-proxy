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
import importlib.metadata
import logging
import os
import signal
import sys
import types

from impersonate_proxy import cert_manager, session_pool
from impersonate_proxy.cert_manager import get_cert_for_host, init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.header_filter import (
    cffi_defaults_headers,
    sanitize_headers,
    strip_leak_headers,
)
from impersonate_proxy.server import (
    ProxyRequestHandler,
    ThreadingHTTPServer,
    create_handler_class,
    get_client_netblock,
    raw_tunnel,
)

logger: logging.Logger = logging.getLogger("impersonate-proxy")

# Global singleton context for backward-compatibility with tests & direct module references
_GLOBAL_CONTEXT: ProxyContext = ProxyContext()

# Global references for direct backward-compatibility
_HOST_CERT_CACHE = _GLOBAL_CONTEXT.host_cert_cache
_HOST_CERT_LOCK = _GLOBAL_CONTEXT.host_cert_lock


class _ImpersonateProxyModule(types.ModuleType):
    """Custom module class mapping module-level attributes to _GLOBAL_CONTEXT."""

    @property
    def _DEBUG(self) -> bool:
        return _GLOBAL_CONTEXT.config.debug

    @_DEBUG.setter
    def _DEBUG(self, val: bool) -> None:
        _GLOBAL_CONTEXT.config.debug = val

    @property
    def _QUIET(self) -> bool:
        return _GLOBAL_CONTEXT.config.quiet

    @_QUIET.setter
    def _QUIET(self, val: bool) -> None:
        _GLOBAL_CONTEXT.config.quiet = val

    @property
    def _IMPERSONATE(self) -> str:
        return _GLOBAL_CONTEXT.config.impersonate

    @_IMPERSONATE.setter
    def _IMPERSONATE(self, val: str) -> None:
        _GLOBAL_CONTEXT.config.impersonate = val

    @property
    def _HEADER_MODE(self) -> str:
        return _GLOBAL_CONTEXT.config.header_mode

    @_HEADER_MODE.setter
    def _HEADER_MODE(self, val: str) -> None:
        _GLOBAL_CONTEXT.config.header_mode = val

    @property
    def _STRIP_CLIENT_LEAK_HEADERS(self) -> bool:
        return _GLOBAL_CONTEXT.config.strip_client_leak_headers

    @_STRIP_CLIENT_LEAK_HEADERS.setter
    def _STRIP_CLIENT_LEAK_HEADERS(self, val: bool) -> None:
        _GLOBAL_CONTEXT.config.strip_client_leak_headers = val

    @property
    def _HOST_CERT_MAX(self) -> int:
        return _GLOBAL_CONTEXT.host_cert_max

    @_HOST_CERT_MAX.setter
    def _HOST_CERT_MAX(self, val: int) -> None:
        _GLOBAL_CONTEXT.host_cert_max = val

    @property
    def _SESSION_POOL_MAX(self) -> int:
        return _GLOBAL_CONTEXT.session_pool_max

    @_SESSION_POOL_MAX.setter
    def _SESSION_POOL_MAX(self, val: int) -> None:
        _GLOBAL_CONTEXT.session_pool_max = val

    @property
    def _SESSION_POOL(self):
        return _GLOBAL_CONTEXT.session_pool

    @property
    def _CA_KEY(self):
        return _GLOBAL_CONTEXT.ca_key

    @_CA_KEY.setter
    def _CA_KEY(self, val) -> None:
        _GLOBAL_CONTEXT.ca_key = val

    @property
    def _CA_CERT(self):
        return _GLOBAL_CONTEXT.ca_cert

    @_CA_CERT.setter
    def _CA_CERT(self, val) -> None:
        _GLOBAL_CONTEXT.ca_cert = val

    @property
    def _LEAF_KEY(self):
        return _GLOBAL_CONTEXT.leaf_key

    @_LEAF_KEY.setter
    def _LEAF_KEY(self, val) -> None:
        _GLOBAL_CONTEXT.leaf_key = val


# Functions maintaining backward-compatibility signature
def _show_identifying(val: str) -> str:
    return _GLOBAL_CONTEXT.show_identifying(val)


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return sanitize_headers(headers)


def _get_client_netblock(ip_str: str) -> str:
    return get_client_netblock(ip_str)


def _init_ca(ca_dir: str | None = None) -> None:
    init_ca(_GLOBAL_CONTEXT, ca_dir)


def _get_cert_for_host(hostname: str):
    return get_cert_for_host(_GLOBAL_CONTEXT, hostname)


def _clear_session_pool() -> None:
    _GLOBAL_CONTEXT.clear_session_pool()


def _get_session():
    return session_pool.get_session(_GLOBAL_CONTEXT)


def _release_session(session, *, healthy: bool = True) -> None:
    session_pool.release_session(_GLOBAL_CONTEXT, session, healthy=healthy)


def _cffi_defaults_headers(headers: dict[str, str]) -> dict[str, str]:
    return cffi_defaults_headers(headers)


def _strip_leak_headers(headers: dict[str, str]) -> dict[str, str]:
    return strip_leak_headers(headers)


def _do_request(method: str, url: str, headers: dict[str, str], body: bytes | None, allow_redirects: bool = False):
    return session_pool.do_request(_GLOBAL_CONTEXT, method, url, headers, body, allow_redirects=allow_redirects)


def _raw_tunnel(client_sock, host: str, port: int) -> None:
    raw_tunnel(_GLOBAL_CONTEXT, client_sock, host, port)


class ProxyHandler(ProxyRequestHandler):
    """Backward-compatible ProxyHandler bound to _GLOBAL_CONTEXT."""

    ctx = _GLOBAL_CONTEXT


def run(
    host: str = "127.0.0.1",
    port: int = 8899,
    impersonate: str = "chrome",
    ca_dir: str | None = None,
    header_mode: str = "cffi-defaults",
    strip_client_leak_headers: bool = False,
    debug: bool = False,
    quiet: bool = False,
    upstream_proxy: str | None = None,
    session_pool_max: int = 32,
    connect_timeout: float = 10.0,
    read_timeout: float = 300.0,
    ctx: ProxyContext | None = None,
) -> None:
    target_ctx = ctx or _GLOBAL_CONTEXT
    target_ctx.config = ProxyConfig(
        host=host,
        port=port,
        impersonate=impersonate,
        ca_dir=ca_dir,
        header_mode=header_mode,
        strip_client_leak_headers=strip_client_leak_headers,
        debug=debug,
        quiet=quiet,
        upstream_proxy=upstream_proxy,
        session_pool_max=session_pool_max,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )
    target_ctx.session_pool_max = session_pool_max

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,  # Overwrites default pytest handler config in tests
    )

    cert_manager.init_ca(target_ctx, ca_dir)

    handler_cls = create_handler_class(target_ctx)
    server = ThreadingHTTPServer((host, port), handler_cls, target_ctx)
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
        logger.info("Shutting down proxy server and clearing session pool...")
        server.server_close()
        target_ctx.clear_session_pool()


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
        "--cffi-defaults",
        action="store_const",
        dest="header_mode",
        const="cffi-defaults",
        default=os.environ.get("IMPERSONATE_PROXY_HEADER_MODE", "cffi-defaults").lower(),
        help="Strip browser-shape headers (User-Agent, Sec-Ch-Ua-*, Accept-Encoding, "
        "Priority, TE, Upgrade-Insecure-Requests, Sec-Fetch-User) from the client and "
        "drop bot-tell headers (Cache-Control, DNT, Connection) so curl_cffi injects "
        "the correct current browser values from its impersonation profile. [DEFAULT]",
    )
    header_mode_group.add_argument(
        "--passthrough-headers",
        action="store_const",
        dest="header_mode",
        const="passthrough",
        help="Forward client headers untouched; curl_cffi only sets TLS-impersonation headers. For advanced users.",
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
        "--upstream-proxy",
        default=os.environ.get("IMPERSONATE_PROXY_UPSTREAM_PROXY"),
        help="Upstream egress proxy URL (e.g. http://127.0.0.1:8080 or IMPERSONATE_PROXY_UPSTREAM_PROXY)",
    )
    parser.add_argument(
        "--session-pool-max",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_SESSION_POOL_MAX", "32")),
        help="Maximum reusable curl_cffi sessions in pool (default: 32 or IMPERSONATE_PROXY_SESSION_POOL_MAX)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=float(os.environ.get("IMPERSONATE_PROXY_CONNECT_TIMEOUT", "10.0")),
        help="Upstream TCP/TLS connect timeout in seconds (default: 10.0 or IMPERSONATE_PROXY_CONNECT_TIMEOUT)",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=float(os.environ.get("IMPERSONATE_PROXY_READ_TIMEOUT", "300.0")),
        help="Upstream HTTP read timeout in seconds (default: 300.0 or IMPERSONATE_PROXY_READ_TIMEOUT)",
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
    header_mode = args.header_mode if args.header_mode in ("passthrough", "cffi-defaults") else "cffi-defaults"
    run(
        host=args.host,
        port=args.port,
        impersonate=args.impersonate,
        ca_dir=args.ca_dir,
        header_mode=header_mode,
        strip_client_leak_headers=args.strip_client_leak_headers,
        debug=args.debug,
        quiet=args.quiet,
        upstream_proxy=args.upstream_proxy,
        session_pool_max=args.session_pool_max,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
    )


# Apply custom module class to intercept module-level property access/mutation
sys.modules[__name__].__class__ = _ImpersonateProxyModule

if __name__ == "__main__":
    main()
