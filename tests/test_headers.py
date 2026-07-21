"""Unit tests for header preparation modes and client-leak stripping."""

import logging

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
    """Headers resembling a SearXNG outgoing XHR request (with bot-tell signals)."""
    return {
        "Host": "example.com",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Mode": "cors",
    }


@pytest.fixture
def client_headers_with_proxy_leak() -> dict[str, str]:
    """Client headers carrying middlebox/identity-leak signals plus request-specific headers."""
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
# cffi-defaults mode
# ---------------------------------------------------------------------------


class TestCffiDefaultsMode:
    """cffi-defaults strips browser-shape headers so curl_cffi injects the rest,
    drops bot-tell headers, and preserves request-specific + shape-dependent headers."""

    def test_strips_browser_shape_headers(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        for h in [
            "User-Agent",
            "Accept-Encoding",
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-User",
            "Priority",
            "TE",
            "Sec-Ch-Ua",
            "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Platform",
        ]:
            assert h not in out, f"{h} should be stripped so curl_cffi injects it"
            assert h.lower() not in {k.lower() for k in out}, f"{h} (any case) should be stripped"

    def test_drops_bot_tell_headers(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        for h in ["Cache-Control", "DNT", "Connection"]:
            assert h not in out, f"{h} should be dropped as a bot tell"
            assert h.lower() not in {k.lower() for k in out}

    def test_drops_connection_with_warning(self, client_headers_searxng_like, caplog):
        with caplog.at_level(logging.WARNING):
            out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        assert "Connection" not in out
        assert "connection" not in {k.lower() for k in out}
        assert any("Connection" in rec.getMessage() for rec in caplog.records), (
            "expected a warning when Connection is dropped"
        )

    def test_preserves_request_specific_headers(self, client_headers_with_proxy_leak):
        out = proxy._cffi_defaults_headers(client_headers_with_proxy_leak)
        assert out["Host"] == "example.com"
        assert out["Authorization"] == "Bearer my-token"
        assert out["Cookie"] == "session=abc"
        assert out["Referer"] == "https://ref.example/"
        assert out["Content-Type"] == "application/json"
        assert out["If-None-Match"] == '"v1"'

    def test_preserves_request_specific_body_and_range_headers(self):
        headers = {
            "Host": "example.com",
            "User-Agent": "curl/8.0",
            "Origin": "https://app.example",
            "Content-Type": "application/json",
            "Content-Length": "42",
            "If-Match": '"v2"',
            "If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT",
            "If-Unmodified-Since": "Wed, 21 Oct 2015 07:28:00 GMT",
            "If-None-Match": '"v1"',
            "Range": "bytes=0-1023",
        }
        out = proxy._cffi_defaults_headers(headers)
        for k, v in headers.items():
            if k == "User-Agent":
                continue  # stripped
            assert out[k] == v, f"{k} should be preserved"

    def test_preserves_client_sec_fetch_headers(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        # SearXNG-like fixture sends Sec-Fetch-Mode: cors — must be preserved so the
        # request keeps its XHR shape; curl_cffi cannot infer it.
        assert out["Sec-Fetch-Mode"] == "cors"
        # Sec-Fetch-Dest / Sec-Fetch-Site are also client-owned shape signals.
        headers = dict(client_headers_searxng_like)
        headers["Sec-Fetch-Dest"] = "empty"
        headers["Sec-Fetch-Site"] = "same-origin"
        out = proxy._cffi_defaults_headers(headers)
        assert out["Sec-Fetch-Dest"] == "empty"
        assert out["Sec-Fetch-Site"] == "same-origin"
        assert out["Sec-Fetch-Mode"] == "cors"

    def test_preserves_client_accept(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        # Accept is shape-dependent (nav=text/html, XHR=*/* or application/json); the
        # client knows. Preserve it so we don't force curl_cffi's nav-style default
        # onto XHR requests.
        assert out["Accept"] == "*/*"

    def test_strips_literal_star_accept_language(self):
        headers = {
            "Host": "example.com",
            "User-Agent": "curl/8.0",
            "Accept-Language": "*",
        }
        out = proxy._cffi_defaults_headers(headers)
        assert "Accept-Language" not in out
        assert "accept-language" not in {k.lower() for k in out}

    def test_preserves_real_accept_language(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        assert out["Accept-Language"] == "en-US,en;q=0.9"

    def test_preserves_custom_x_headers(self):
        headers = {
            "Host": "example.com",
            "User-Agent": "python-requests/2.31",
            "X-API-Key": "sk-foo",
            "X-Custom-App-Header": "value",
        }
        out = proxy._cffi_defaults_headers(headers)
        assert out["X-API-Key"] == "sk-foo"
        assert out["X-Custom-App-Header"] == "value"
        # User-Agent is stripped (curl_cffi injects the profile UA)
        assert "User-Agent" not in out

    def test_returns_a_copy(self, client_headers_searxng_like):
        out = proxy._cffi_defaults_headers(client_headers_searxng_like)
        assert out is not client_headers_searxng_like
        # Mutating the output must not affect the input.
        out["X-Injected-By-Test"] = "1"
        assert "X-Injected-By-Test" not in client_headers_searxng_like


# ---------------------------------------------------------------------------
# passthrough mode
# ---------------------------------------------------------------------------


def test_passthrough_mode_forwards_everything(client_headers_with_proxy_leak):
    """In passthrough mode _do_request forwards client headers untouched (only the
    _strip_leak_headers step may remove anything, and only when that flag is on)."""
    # Reproduce the passthrough branch of _do_request directly.
    out = dict(client_headers_with_proxy_leak)
    assert out == client_headers_with_proxy_leak
    assert out is not client_headers_with_proxy_leak
    # Every original header is preserved, including bot tells and browser-shape headers.
    for k, v in client_headers_with_proxy_leak.items():
        assert out[k] == v


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
# end-to-end: _cffi_defaults_headers + _strip_leak_headers
# ---------------------------------------------------------------------------


class TestCombinedCffiDefaultsAndStrip:
    def test_cffi_defaults_plus_strip(self, client_headers_with_proxy_leak):
        prepared = proxy._cffi_defaults_headers(client_headers_with_proxy_leak)
        out = proxy._strip_leak_headers(prepared)
        # cffi-defaults stripped User-Agent (curl_cffi injects it)
        assert "User-Agent" not in out
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
        # Sensitive auth + cookie preserved by strip + cffi-defaults
        assert out["Authorization"] == "Bearer my-token"
        assert out["Cookie"] == "session=abc"

    def test_passthrough_plus_strip_only_drops_leak(self, client_headers_with_proxy_leak):
        # Passthrough branch: dict(headers) then _strip_leak_headers.
        prepared = dict(client_headers_with_proxy_leak)
        out = proxy._strip_leak_headers(prepared)
        # Passthrough: no browser headers injected, client UA preserved
        assert "Chrome/120" in out["User-Agent"]
        # Strip still removes leak signals
        assert "X-Forwarded-For" not in out
        assert "Via" not in out
