"""Session pool management for upstream curl_cffi requests."""

import contextlib
import logging
import queue

from curl_cffi import requests as cffi_requests

from impersonate_proxy.context import ProxyContext
from impersonate_proxy.header_filter import (
    cffi_defaults_headers,
    sanitize_headers,
    strip_leak_headers,
)

logger: logging.Logger = logging.getLogger("impersonate-proxy")


def get_session(ctx: ProxyContext) -> cffi_requests.Session:
    """Get a reused curl_cffi session from the pool or create a new one."""
    try:
        return ctx.session_pool.get_nowait()
    except queue.Empty:
        return cffi_requests.Session(impersonate=ctx.config.impersonate)


def release_session(ctx: ProxyContext, session: cffi_requests.Session, *, healthy: bool = True) -> None:
    """Release a session back to the pool if healthy; otherwise close and discard."""
    if healthy and not ctx.session_pool.full():
        ctx.session_pool.put_nowait(session)
    else:
        with contextlib.suppress(Exception):
            session.close()


def do_request(
    ctx: ProxyContext,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    allow_redirects: bool = False,
) -> cffi_requests.Response | None:
    """Issue a request via curl_cffi with TLS impersonation using ProxyContext."""
    session = get_session(ctx)
    try:
        if ctx.config.header_mode == "passthrough":
            out_headers = dict(headers)
        else:
            out_headers = cffi_defaults_headers(headers)
        if ctx.config.strip_client_leak_headers:
            out_headers = strip_leak_headers(out_headers)
        logger.debug(
            f"Issuing request: {method} {ctx.show_identifying(url)} "
            f"(header_mode={ctx.config.header_mode}, strip_leak={ctx.config.strip_client_leak_headers}, "
            f"headers={sanitize_headers(out_headers)})"
        )
        proxies = (
            {"http": ctx.config.upstream_proxy, "https": ctx.config.upstream_proxy}
            if ctx.config.upstream_proxy
            else None
        )
        timeout = (ctx.config.connect_timeout, ctx.config.read_timeout)
        resp = session.request(
            method=method,
            url=url,
            headers=out_headers,
            data=body,
            timeout=timeout,
            proxies=proxies,
            allow_redirects=allow_redirects,
            stream=True,
        )
        orig_close = resp.close
        session_released = False

        def custom_close():
            nonlocal session_released
            orig_close()
            if not session_released:
                release_session(ctx, session)
                session_released = True

        resp.close = custom_close
        return resp
    except Exception as e:
        logger.error(f"Upstream request failed for {ctx.show_identifying(url)}: {e}")
        release_session(ctx, session, healthy=False)
        return None
