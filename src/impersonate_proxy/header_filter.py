"""Header adaptation, filtering, and leak stripping utilities."""

import logging

logger: logging.Logger = logging.getLogger("impersonate-proxy")

_SENSITIVE_HEADERS: set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "token",
    "x-api-key",
}

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

_CDN_INGRESS_HEADERS: set[str] = {
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
}

_STRIP_FOR_CFFI_DEFAULTS: set[str] = {
    "user-agent",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "accept-encoding",
    "upgrade-insecure-requests",
    "sec-fetch-user",
    "priority",
    "te",
}

_DROP_HEADERS: set[str] = {
    "cache-control",
    "dnt",
    "connection",
}


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with sensitive values redacted."""
    sanitized = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_HEADERS:
            sanitized[k] = "[redacted-sensitive]"
        else:
            sanitized[k] = v
    return sanitized


def cffi_defaults_headers(headers: dict[str, str]) -> dict[str, str]:
    """Prepare outgoing headers for cffi-defaults mode.

    Strip browser-shape headers that curl_cffi injects from its impersonation
    profile (UA, Sec-Ch-Ua-*, Accept-Encoding, Priority, TE, Upgrade-Insecure-Requests,
    Sec-Fetch-User) so the client cannot silently override them. Drop bot-tell
    headers (Cache-Control, DNT, Connection). Special-case ``Accept-Language: *``
    (a bot tell) by stripping it; preserve real Accept-Language values. Preserve
    everything else — request-specific headers (Cookie, Authorization, Referer,
    Content-Type, If-*, Range, Host) and shape-dependent headers (Accept,
    Sec-Fetch-Dest/Mode/Site) that curl_cffi cannot infer.

    Returns a new dict; the input is not mutated.
    """
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in _STRIP_FOR_CFFI_DEFAULTS:
            continue
        if kl in _DROP_HEADERS:
            if kl == "connection":
                logger.warning(
                    "cffi-defaults: dropping client '%s' header — curl_cffi manages "
                    "Connection state; client-supplied value would conflict with HTTP/2.",
                    k,
                )
            else:
                logger.debug(
                    "cffi-defaults: dropping client '%s' header (browser navigation requests do not send it).",
                    k,
                )
            continue
        if kl == "accept-language" and v.strip() == "*":
            logger.debug(
                "cffi-defaults: stripping client '%s' header — literal '*' is a bot tell; "
                "curl_cffi injects a real browser Accept-Language.",
                k,
            )
            continue
        out[k] = v
    return out


def strip_leak_headers(headers: dict[str, str]) -> dict[str, str]:
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
