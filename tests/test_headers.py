"""Unit tests for header preparation modes and client-leak stripping."""

import logging
from typing import Any

import pytest

from impersonate_proxy import main as proxy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client_headers_minimal() -> dict[str, str]:
    """A bare client request with only the required headers."""
    return {
        "Host": "example.com",
        "User-Agent": "python-httpx/0.27.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }


@pytest.fixture
def client_headers_searxng_like() -> dict[str, str]:
    """Headers resembling a SearXNG outgoing request (with bot-tell signals)."""
    return {
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Connection": "keep-alive",
        "Accept-Language": "en-US,en;q=0.9",
    }


@pytest.fixture
def client_headers_with_proxy_leak() -> dict[str, str]:
    """Client headers carrying middlebox/identity-leak signals."""
    return {
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "X-Forwarded-For": "10.0.0.1",
        "X-Forwarded-Host": "internal.example",
        "X-Real-IP": "10.0.0.1",
        "Via": "1.1 some-proxy",
        "Forwarded": "for=10.0.0.1;proto=https",
        "X-Request-ID": "abc-123",
        "X-Correlation-ID": "sess-456",
        "True-Client-IP": "10.0.0.1",
        "CF-Connecting-IP": "10.0.0.1",
        "Fastly-Client-IP": "10.0.0.1",
        "X-Cluster-Client-IP": "10.0.0.1",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Server": "front.example",
        "Authorization": "Bearer my-token",
        "Cookie": "session=abc",
        "Referer": "https://ref.example/",
        "Content-Type": "application/json",
        "If-None-Match": '"v1"',
    }


# ---------------------------------------------------------------------------
# passthrough mode
# ---------------------------------------------------------------------------


class TestPassthroughMode:
    def test_returns_headers_untouched(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="passthrough")
        assert out == client_headers_minimal
        # Should be a copy, not the same object
        assert out is not client_headers_minimal

    def test_does_not_replace_non_browser_ua(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="passthrough")
        assert out["User-Agent"] == "python-httpx/0.27.0"

    def test_does_not_inject_sec_headers(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="passthrough")
        assert "Sec-Fetch-Dest" not in out
        assert "Sec-Ch-Ua" not in out


# ---------------------------------------------------------------------------
# enrich mode
# ---------------------------------------------------------------------------


class TestEnrichMode:
    def test_replaces_non_browser_ua(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="enrich")
        assert out["User-Agent"] != "python-httpx/0.27.0"
        assert "Chrome/120" in out["User-Agent"]

    def test_preserves_client_accept(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="enrich")
        # Accept was already set — additive mode must preserve it
        assert out["Accept"] == "*/*"

    def test_preserves_client_accept_encoding(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="enrich")
        # Accept-Encoding was already set — must NOT be replaced in enrich mode
        assert out["Accept-Encoding"] == "gzip, deflate"

    def test_injects_missing_sec_headers(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "chrome", mode="enrich")
        assert out["Sec-Fetch-Dest"] == "document"
        assert out["Sec-Fetch-Mode"] == "navigate"
        assert out["Sec-Fetch-Site"] == "none"
        assert out["Sec-Ch-Ua"].startswith('"Not_A Brand"')

    def test_firefox_profile_no_sec_ch_ua(self, client_headers_minimal):
        out = proxy._prepare_headers(client_headers_minimal, "firefox", mode="enrich")
        # Firefox does not send Sec-Ch-Ua
        assert "Sec-Ch-Ua" not in out
        assert "Firefox/119" in out["User-Agent"]

    def test_firefox_accept_encoding_no_zstd(self, client_headers_minimal):
        # Remove client Accept-Encoding to verify firefox default is injected
        headers = {k: v for k, v in client_headers_minimal.items() if k != "Accept-Encoding"}
        out = proxy._prepare_headers(headers, "firefox", mode="enrich")
        assert out["Accept-Encoding"] == "gzip, deflate, br"

    def test_chrome_accept_encoding_includes_zstd_when_missing(self):
        headers = {"Host": "example.com", "User-Agent": "curl/8.0"}
        out = proxy._prepare_headers(headers, "chrome", mode="enrich")
        assert out["Accept-Encoding"] == "gzip, deflate, br, zstd"

    def test_real_browser_ua_is_preserved(self):
        """A real browser UA must not be replaced."""
        headers = {"Host": "example.com", "User-Agent": "Mozilla/5.0 (Macintosh) Safari/605"}
        out = proxy._prepare_headers(headers, "chrome", mode="enrich")
        assert out["User-Agent"] == "Mozilla/5.0 (Macintosh) Safari/605"

    def test_does_not_drop_client_cache_control(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="enrich")
        # enrich mode is additive only — must NOT drop nav-mismatch tells
        assert out.get("Cache-Control") == "no-cache"
        assert out.get("DNT") == "1"
        assert out.get("Connection") == "keep-alive"


# ---------------------------------------------------------------------------
# override mode
# ---------------------------------------------------------------------------


class TestOverrideMode:
    def test_replaces_accept(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        # '*/*' must be overwritten with the browser Accept value
        assert out["Accept"] != "*/*"
        assert "text/html" in out["Accept"]

    def test_replaces_accept_encoding_chrome(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        assert out["Accept-Encoding"] == "gzip, deflate, br, zstd"

    def test_replaces_accept_encoding_firefox(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "firefox", mode="override")
        assert out["Accept-Encoding"] == "gzip, deflate, br"

    def test_drops_cache_control(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        assert "Cache-Control" not in out
        assert "cache-control" not in {k.lower() for k in out}

    def test_drops_dnt(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        assert "DNT" not in out
        assert "dnt" not in {k.lower() for k in out}

    def test_drops_connection(self, client_headers_searxng_like, caplog):
        with caplog.at_level(logging.WARNING):
            out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        assert "Connection" not in out
        assert "connection" not in {k.lower() for k in out}
        # A warning should have been logged
        assert any("Connection" in rec.getMessage() for rec in caplog.records)

    def test_replaces_sec_headers(self, client_headers_searxng_like):
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        assert out["Sec-Fetch-Dest"] == "document"
        assert out["Sec-Ch-Ua"].startswith('"Not_A Brand"')

    def test_preserves_authorization_cookie_referer(self, client_headers_with_proxy_leak):
        out = proxy._prepare_headers(client_headers_with_proxy_leak, "chrome", mode="override")
        assert out["Authorization"] == "Bearer my-token"
        assert out["Cookie"] == "session=abc"
        assert out["Referer"] == "https://ref.example/"

    def test_preserves_content_type_and_cache_conditionals(self, client_headers_with_proxy_leak):
        out = proxy._prepare_headers(client_headers_with_proxy_leak, "chrome", mode="override")
        assert out["Content-Type"] == "application/json"
        assert out["If-None-Match"] == '"v1"'

    def test_replaces_real_browser_ua_with_profile(self, client_headers_searxng_like):
        """Override mode replaces even valid browser UAs to match the impersonated profile."""
        out = proxy._prepare_headers(client_headers_searxng_like, "chrome", mode="override")
        # The original was Firefox 115; override mode must install Chrome 120 UA
        assert "Chrome/120" in out["User-Agent"]
        assert "Firefox/115" not in out["User-Agent"]

    def test_override_preserves_custom_x_headers(self):
        headers = {
            "Host": "example.com",
            "User-Agent": "python-requests/2.31",
            "X-API-Key": "sk-foo",
            "X-Custom-Header": "value",
        }
        out = proxy._prepare_headers(headers, "chrome", mode="override")
        assert out["X-API-Key"] == "sk-foo"
        assert out["X-Custom-Header"] == "value"


# ---------------------------------------------------------------------------
# strip-client-leak-headers
# ---------------------------------------------------------------------------


class TestStripClientLeakHeaders:
    @pytest.mark.parametrize(
        "header_name",
        [
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Forwarded-Server",
            "Forwarded",
            "Via",
            "X-Request-ID",
            "X-Correlation-ID",
        ],
    )
    def test_each_leak_header_is_dropped(self, header_name):
        headers = {"Host": "example.com", header_name: "leak-value"}
        out = proxy._strip_leak_headers(headers)
        assert header_name not in out
        assert header_name.lower() not in {k.lower() for k in out}

    @pytest.mark.parametrize(
        "header_name",
        [
            "X-Real-IP",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Cluster-Client-IP",
            "Fastly-Client-IP",
        ],
    )
    def test_cdn_ingress_header_is_forwarded_with_warning(self, header_name, caplog):
        """CDN-ingress headers are not stripped — their presence in a client request is
        surfaced as a warning so the operator can diagnose the misconfig."""
        headers = {"Host": "example.com", header_name: "10.0.0.1"}
        with caplog.at_level(logging.WARNING):
            out = proxy._strip_leak_headers(headers)
        assert out[header_name] == "10.0.0.1", f"{header_name} should be forwarded, not stripped"
        # A warning should have been logged mentioning the header
        assert any(header_name in rec.getMessage() and "CDN-ingress" in rec.getMessage() for rec in caplog.records), (
            f"expected CDN-ingress warning for {header_name}; got: {[r.getMessage() for r in caplog.records]}"
        )

    def test_preserves_non_leak_headers(self, client_headers_with_proxy_leak):
        out = proxy._strip_leak_headers(client_headers_with_proxy_leak)
        assert out["Host"] == "example.com"
        assert out["User-Agent"] != ""
        assert out["Authorization"] == "Bearer my-token"
        assert out["Cookie"] == "session=abc"
        assert out["Referer"] == "https://ref.example/"
        assert out["Content-Type"] == "application/json"
        assert out["If-None-Match"] == '"v1"'

    def test_case_insensitive_match(self):
        headers = {
            "host": "example.com",
            "x-forwarded-for": "1.2.3.4",
            "X-Forwarded-Host": "internal",
            "VIA": "1.1 proxy",
        }
        out = proxy._strip_leak_headers(headers)
        assert "x-forwarded-for" not in out
        assert "X-Forwarded-Host" not in out
        assert "VIA" not in out
        assert "Via" not in out
        assert out["host"] == "example.com"

    def test_preserves_custom_x_headers(self):
        headers = {
            "Host": "example.com",
            "X-API-Key": "sk-foo",
            "X-Custom-App-Header": "value",
            "X-Request-ID": "should-be-dropped",
        }
        out = proxy._strip_leak_headers(headers)
        assert out["X-API-Key"] == "sk-foo"
        assert out["X-Custom-App-Header"] == "value"
        assert "X-Request-ID" not in out

    def test_cdn_ingress_case_insensitive_warning(self, caplog):
        """CDN-ingress detection is case-insensitive."""
        headers = {"Host": "example.com", "x-real-ip": "10.0.0.1"}
        with caplog.at_level(logging.WARNING):
            out = proxy._strip_leak_headers(headers)
        assert out["x-real-ip"] == "10.0.0.1"
        assert any("x-real-ip" in rec.getMessage() for rec in caplog.records)


# ---------------------------------------------------------------------------
# end-to-end: _prepare_headers + _strip_leak_headers
# ---------------------------------------------------------------------------


class TestCombinedModesAndStrip:
    def test_override_plus_strip(self, client_headers_with_proxy_leak):
        prepared = proxy._prepare_headers(client_headers_with_proxy_leak, "chrome", mode="override")
        out = proxy._strip_leak_headers(prepared)
        # Override replaced Accept and Accept-Encoding
        assert "text/html" in out["Accept"]
        assert out["Accept-Encoding"] == "gzip, deflate, br, zstd"
        # Strip removed middlebox-chain + tracing leak headers
        for leak in [
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "Via",
            "Forwarded",
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Forwarded-Proto",
            "X-Forwarded-Server",
        ]:
            assert leak not in out, f"leak header {leak} not stripped"
        # CDN-ingress headers are forwarded (not stripped) — their presence is a misconfig
        # that should surface, not be silently dropped.
        for cdn_h in ["X-Real-IP", "True-Client-IP", "CF-Connecting-IP", "Fastly-Client-IP", "X-Cluster-Client-IP"]:
            assert out.get(cdn_h) == "10.0.0.1", f"CDN-ingress header {cdn_h} should be forwarded, not stripped"
        # Sensitive auth + cookie preserved by strip + override
        assert out["Authorization"] == "Bearer my-token"
        assert out["Cookie"] == "session=abc"

    def test_enrich_plus_strip_preserves_client_accept(self, client_headers_with_proxy_leak):
        prepared = proxy._prepare_headers(client_headers_with_proxy_leak, "chrome", mode="enrich")
        out = proxy._strip_leak_headers(prepared)
        # Enrich must preserve client Accept (was missing → browser default injected)
        # The fixture had no Accept, so enrich injects the default
        assert "text/html" in out["Accept"]
        # Strip removed leak headers
        assert "X-Forwarded-For" not in out
        assert "Via" not in out

    def test_passthrough_plus_strip_only_drops_leak(self, client_headers_with_proxy_leak):
        prepared = proxy._prepare_headers(client_headers_with_proxy_leak, "chrome", mode="passthrough")
        out = proxy._strip_leak_headers(prepared)
        # Passthrough: no browser headers injected
        assert "Sec-Fetch-Dest" not in out
        # Strip still removes leak signals
        assert "X-Forwarded-For" not in out
        assert "Via" not in out
        # Client UA preserved (passthrough mode)
        assert "Chrome/120" in out["User-Agent"]


# ---------------------------------------------------------------------------
# _is_non_browser_ua
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ua,expected",
    [
        ("", True),
        ("Mozilla/5.0 (X11) Gecko/20100101 Firefox/119.0", False),
        ("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36", False),
        ("curl/8.0", True),
        ("python-requests/2.31", True),
        ("python-httpx/0.27.0", True),
        ("aiohttp/3.9", True),
        ("Wget/1.21", True),
        ("Go-http-client/1.1", True),
        ("PostmanRuntime/7.32", True),
        ("okhttp/4.10", False),
        ("MyCustomApp/1.0", False),
    ],
)
def test_is_non_browser_ua(ua: str, expected: bool):
    assert proxy._is_non_browser_ua(ua) is expected


# ---------------------------------------------------------------------------
# _profile_defaults
# ---------------------------------------------------------------------------


def test_profile_defaults_chrome():
    defaults = proxy._profile_defaults("chrome")
    assert "Sec-Ch-Ua" in defaults
    assert defaults["Accept-Encoding"] == "gzip, deflate, br, zstd"


def test_profile_defaults_fireix():
    defaults = proxy._profile_defaults("firefox131")
    # Any firefox-prefixed profile resolves to the firefox defaults
    assert "Sec-Ch-Ua" not in defaults
    assert defaults["Accept-Encoding"] == "gzip, deflate, br"


def test_profile_defaults_unknown_falls_back_to_chrome():
    defaults: dict[str, Any] = proxy._profile_defaults("safari")
    assert "Sec-Ch-Ua" in defaults  # chrome set returned
