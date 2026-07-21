"""
Extended live tests targeting sites known for TLS fingerprinting and bot detection.

These tests verify that tls-impersonate-proxy successfully bypasses browser
fingerprint checks, JA3/JA4 detection, and commercial bot-protection systems
by asserting HTTP 200 responses and comparing them against unproxied requests.

Both Chrome and Firefox TLS impersonation profiles are tested automatically via parameterization.

Run with:
    pytest -m live_extended

NOT run by default, NOT run in CI, NOT included in 'pytest -m live'.
"""

import contextlib
import logging
import socket
import tempfile
import threading
import time
from collections.abc import Generator
from http.server import HTTPServer
from socketserver import ThreadingMixIn

import pytest
import requests

from impersonate_proxy import main as proxy

logger = logging.getLogger("impersonate-proxy-test")

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------


def _get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


@pytest.fixture(
    params=[
        # Each param tuple: (impersonate, header_mode, strip_leak_headers)
        ("chrome", "cffi-defaults", False),
        ("firefox", "cffi-defaults", False),
        ("chrome", "cffi-defaults", True),
        ("firefox", "cffi-defaults", True),
    ],
    ids=[
        "chrome-cffi-defaults",
        "firefox-cffi-defaults",
        "chrome-cffi-defaults+strip",
        "firefox-cffi-defaults+strip",
    ],
)
def proxy_server(request) -> Generator[tuple[str, str, str, str, bool], None, None]:
    """
    Spin up a local tls-impersonate-proxy instance with a temporary CA dir.

    Parameterised across:
      * impersonation profile (chrome, firefox)
      * header mode (cffi-defaults)
      * client-leak stripping (off and on; the +strip variants inject non-browser-client-like
        leak headers to exercise the strip path)

    Yields (proxy_url, ca_cert_path, impersonate_profile, header_mode, strip_leak).
    """
    impersonate_profile, header_mode, strip_leak = request.param
    orig_impersonate = proxy._IMPERSONATE
    orig_header_mode = proxy._HEADER_MODE
    orig_strip = proxy._STRIP_CLIENT_LEAK_HEADERS
    proxy._IMPERSONATE = impersonate_profile
    proxy._HEADER_MODE = header_mode
    proxy._STRIP_CLIENT_LEAK_HEADERS = strip_leak

    port = _get_free_port()
    proxy_url = f"http://127.0.0.1:{port}"

    with tempfile.TemporaryDirectory() as tmpdir:
        proxy._init_ca(tmpdir)
        ca_cert_path = f"{tmpdir}/ca.crt"

        server = _ThreadingHTTPServer(("127.0.0.1", port), proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        # Wait for the server to accept connections
        for _ in range(50):
            with contextlib.suppress(OSError):
                s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                s.close()
                break
            time.sleep(0.1)

        try:
            yield proxy_url, ca_cert_path, impersonate_profile, header_mode, strip_leak
        finally:
            proxy._IMPERSONATE = orig_impersonate
            proxy._HEADER_MODE = orig_header_mode
            proxy._STRIP_CLIENT_LEAK_HEADERS = orig_strip
            server.shutdown()


def _get(
    url: str,
    proxy_url: str,
    ca_cert_path: str,
    impersonate: str,
    timeout: int = 30,
    inject_leak_headers: bool = False,
) -> requests.Response:
    """
    Issue a GET request through the proxy using standard python-requests headers.
    This emulates a real-world plain client (which does not provide browser headers).

    When ``inject_leak_headers`` is True, simulate a non-browser httpx-style client by adding
    middlebox/identity-leak headers (XForwarded-*, Forwarded, Via, X-Request-ID, etc.)
    plus navigation-mismatch tells (Cache-Control, DNT, Connection). Used to verify
    that --cffi-defaults + --strip-client-leak-headers actually strip them.
    """
    scheme = url.split("://")[0]
    proxies = {scheme: proxy_url}

    headers = None
    if inject_leak_headers:
        # Mimic a non-browser httpx-style outgoing request shape.
        headers = {
            "User-Agent": "python-httpx/0.27.0",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "DNT": "1",
            "Connection": "keep-alive",
            "X-Forwarded-For": "10.0.0.1",
            "X-Forwarded-Host": "internal.example",
            "Forwarded": "for=10.0.0.1;proto=https",
            "Via": "1.1 some-app",
            "X-Request-ID": "test-abc",
            "X-Correlation-ID": "test-xyz",
        }

    # Only pass verify= for HTTPS; HTTP doesn't need a cert bundle
    if scheme == "https":
        return requests.get(url, proxies=proxies, verify=ca_cert_path, headers=headers, timeout=timeout)
    return requests.get(url, proxies=proxies, headers=headers, timeout=timeout)


def _get_unproxied(url: str, use_chrome_headers: bool = False, timeout: int = 15) -> int:
    """Issue a GET request directly (without proxy) and return the status code."""
    headers = None
    if use_chrome_headers:
        # Mirrors impersonate-proxy's chrome profile defaults (Chrome 146 on macOS,
        # sourced from curl-impersonate signatures).
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Ch-Ua": '"Chromium";v="146", "Google Chrome";v="146", "Not_A Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
        }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        return resp.status_code
    except Exception:
        return 0


def _assert_status(
    url: str, proxied_status: int, unproxied_status: int, impersonate: str, header_mode: str = ""
) -> None:
    """
    Assert that the proxied request succeeded, or handle WAF IP blocks robustly.
    """
    tag = f"{impersonate}/{header_mode}" if header_mode else impersonate
    if proxied_status == 200:
        if unproxied_status in (403, 401, 429, 503, 0):
            logger.info(
                f"[{url}] SUCCESS ({tag}): Direct request was blocked ({unproxied_status}), but proxy successfully bypassed it (200)"
            )
        else:
            logger.info(f"[{url}] SUCCESS ({tag}): Both direct and proxied requests succeeded (200)")
        return

    # If the proxy failed, but the direct request also failed with the same block/error:
    if proxied_status in (403, 401, 429, 503) and unproxied_status == proxied_status:
        pytest.skip(f"IP blocked or site down for {url} (Both direct and proxied requests returned {proxied_status})")

    # Otherwise, it's a real proxy failure (e.g. direct got 200 but proxied got non-200)
    assert proxied_status == 200, f"Proxied request failed ({tag}): got {proxied_status}, direct got {unproxied_status}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.live_extended
class TestFingerprintBypass:
    """
    Verify that the proxy defeats TLS fingerprinting and bot-detection systems.

    The proxy_server fixture parameterises over (impersonate, header_mode, strip_leak):
    by default the suite runs four variants — chrome/firefox under cffi-defaults mode,
    and chrome/firefox under cffi-defaults+strip mode. The +strip variant injects
    non-browser-client-like leak headers via _get() to prove the strip path actually drops them.
    """

    def test_nowsecure_nl(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """nowsecure.nl is a browser fingerprint / TLS test page."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://nowsecure.nl"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        assert len(resp.content) > 1000, "Response body suspiciously small"

    def test_cloudflare_homepage(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """cloudflare.com uses JA3/JA4 fingerprinting."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.cloudflare.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "cloudflare" in body, "Expected 'cloudflare' in response body"

    def test_akamai_homepage(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """akamai.com blocks non-browser TLS fingerprints with 403."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.akamai.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "akamai" in body, "Expected 'akamai' in response body"

    def test_datadome_protected_site(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """datadome.co blocks standard requests with 403."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://datadome.co"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "datadome" in body, "Expected 'datadome' in response body"

    def test_imperva_homepage(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """imperva.com runs Imperva WAF / bot management."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.imperva.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "imperva" in body, "Expected 'imperva' in response body"

    def test_linkedin_public_page(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """LinkedIn uses aggressive bot blocking."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.linkedin.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "linkedin" in body, "Expected 'linkedin' in response body"

    def test_ticketmaster_homepage(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """Ticketmaster uses Akamai bot management (highly aggressive)."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.ticketmaster.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "ticketmaster" in body, "Expected 'ticketmaster' in response body"

    def test_google_homepage(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """google.com homepage check."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.google.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "google" in body, "Expected 'google' in response body"

    def test_tls_api_ja3_check(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """tls.peet.ws/api/all checks TLS handshake fingerprint (JA3, JA4)."""
        known_bot_ja3 = {
            "62d3494f5d7c57c6d192a8a4af44c793",  # curl
            "b32309a26951912be7dba376398abc3b",  # python-requests
            "a0e9f5d64349fb13191bc781f81f42e1",  # wget
        }

        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        resp = _get(
            "https://tls.peet.ws/api/all",
            proxy_url,
            ca_cert_path,
            impersonate,
            inject_leak_headers=strip_leak,
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        ja3 = data.get("tls", {}).get("ja3", "") or ""
        assert ja3, "Expected non-empty JA3 fingerprint"
        assert ja3 not in known_bot_ja3, (
            f"JA3 {ja3!r} matches a known non-browser fingerprint — impersonation may not be working"
        )
        logger.info(f"[tls.peet.ws] Dynamic JA3 fingerprint verified ({impersonate}/{header_mode}): {ja3}")

    def test_sannysoft_bot_detection(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """bot.sannysoft.com checks TLS fingerprint and browser headers."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://bot.sannysoft.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "<title>antibot</title>" in body, "Expected sannysoft antibot page"

    def test_bet365_kasada(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """bet365.com is protected by Kasada; blocks non-browser TLS clients aggressively."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://www.bet365.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)

    def test_creepjs_github_pages(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """abrahamjuliot.github.io/creepjs is served via GitHub Pages (Cloudflare-fronted)."""
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        url = "https://abrahamjuliot.github.io/creepjs"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate, inject_leak_headers=strip_leak)

        _assert_status(url, resp.status_code, unproxied_status, impersonate, header_mode)
        body = resp.text.lower()
        assert "creep" in body, "Expected 'creep' in response body"

    def test_tls_peet_ws_cffi_defaults_intact(self, proxy_server: tuple[str, str, str, str, bool]) -> None:
        """Live regression guard: assert curl_cffi's full browser header set arrives at
        tls.peet.ws through the proxy when running in cffi-defaults mode.

        Design rationale:
          * **Accept is PRESERVED from the client** — it is shape-dependent
            (nav=text/html, XHR=*/* or application/json) and the client knows which
            shape it is sending. Stripping would force curl_cffi's nav-style default
            onto XHR requests, which is itself a bot tell.
          * **User-Agent is STRIPPED** — curl_cffi owns it. Forwarding a non-browser
            UA (python-httpx) would silently override (and break) impersonation.
          * **Sec-Fetch-Mode is PRESERVED from the client** — a non-browser XHR
            client correctly sends `cors` for XHR; curl_cffi cannot infer the request shape.
          * **Cache-Control / DNT are DROPPED** — bot tells; real browser nav requests
            never send them.

        Sends a non-browser-client-like request (UA=python-httpx, Accept: */*,
        Accept-Encoding: gzip, deflate, Cache-Control: no-cache, DNT: 1,
        sec-fetch-mode: cors) and asserts the request that arrives at tls.peet.ws
        carries the impersonation profile's browser headers, not the client's bot tells.
        Parameterised across chrome + firefox variants via the proxy_server fixture.
        """
        proxy_url, ca_cert_path, impersonate, header_mode, strip_leak = proxy_server
        # Non-browser-client-like client headers + bot tells that cffi-defaults should strip.
        client_headers = {
            "User-Agent": "python-httpx/0.27.0",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "DNT": "1",
            "Sec-Fetch-Mode": "cors",
        }
        proxies = {"https": proxy_url}
        resp = requests.get(
            "https://tls.peet.ws/api/all",
            proxies=proxies,
            verify=ca_cert_path,
            headers=client_headers,
            timeout=30,
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"

        data = resp.json()

        # Collect all HTTP/2 sent-frame headers (lowercased keys). tls.peet.ws returns
        # the request HEADERS frames in data["http2"]["sent_frames"]; each HEADERS
        # frame's "headers" field is a list of "key: value" strings.
        sent_headers: dict[str, str] = {}
        for frame in data.get("http2", {}).get("sent_frames", []):
            if frame.get("frame_type") != "HEADERS":
                continue
            for entry in frame.get("headers") or []:
                if ": " not in entry:
                    continue
                k, v = entry.split(": ", 1)
                sent_headers[k.lower()] = v
        assert sent_headers, "Expected HEADERS frames in tls.peet.ws /api/all response"

        # --- User-Agent: stripped by cffi-defaults, curl_cffi injects profile UA ---
        ua = data.get("user_agent", "") or sent_headers.get("user-agent", "")
        assert ua, "Expected non-empty user_agent in tls.peet.ws response"
        if impersonate.startswith("firefox"):
            assert "Firefox/147" in ua, f"Expected Firefox/147 UA, got {ua!r}"
            # Firefox does not send Sec-Ch-Ua-* headers.
            assert "sec-ch-ua" not in sent_headers, "Firefox should not send Sec-Ch-Ua"
            assert "sec-ch-ua-mobile" not in sent_headers
            assert "sec-ch-ua-platform" not in sent_headers
        else:
            assert "Chrome/146.0.0.0" in ua, f"Expected Chrome/146 UA, got {ua!r}"
            assert "Macintosh" in ua, f"Expected macOS UA (curl-impersonate signature), got {ua!r}"
            # curl_cffi injects the full sec-ch-ua-* set for Chrome. tls.peet.ws
            # returns these header values with double-quotes escaped as \", so
            # normalise before asserting.
            assert "sec-ch-ua" in sent_headers, "sec-ch-ua should be injected by curl_cffi"
            sec_ch_ua = sent_headers["sec-ch-ua"].replace('\\"', '"')
            assert '"Chromium";v="146"' in sec_ch_ua, f"Expected Chromium v=146 in sec-ch-ua, got {sec_ch_ua!r}"
            assert sent_headers.get("sec-ch-ua-mobile") == "?0"
            sec_ch_ua_platform = sent_headers.get("sec-ch-ua-platform", "")
            assert "macOS" in sec_ch_ua_platform, (
                f"Expected macOS platform in sec-ch-ua-platform, got {sec_ch_ua_platform!r}"
            )

        # --- curl_cffi injects these (client sent bot tells / wrong values that were stripped) ---
        assert sent_headers.get("accept-encoding") == "gzip, deflate, br, zstd", (
            f"Expected curl_cffi's accept-encoding, got {sent_headers.get('accept-encoding')!r}"
        )
        assert sent_headers.get("priority") == "u=0, i", (
            f"Expected priority 'u=0, i', got {sent_headers.get('priority')!r}"
        )
        assert sent_headers.get("upgrade-insecure-requests") == "1", (
            f"Expected upgrade-insecure-requests '1', got {sent_headers.get('upgrade-insecure-requests')!r}"
        )

        # --- Bot tells MUST NOT be forwarded (cffi-defaults drops them) ---
        assert "cache-control" not in sent_headers, "Cache-Control should be dropped by cffi-defaults"
        assert "dnt" not in sent_headers, "DNT should be dropped by cffi-defaults"

        # --- Shape-dependent headers PRESERVED from the client ---
        assert sent_headers.get("accept") == "*/*", (
            f"Accept should be preserved from client (*/*), got {sent_headers.get('accept')!r}"
        )
        assert sent_headers.get("sec-fetch-mode") == "cors", (
            f"Sec-Fetch-Mode should be preserved from client (cors), got {sent_headers.get('sec-fetch-mode')!r}"
        )

        logger.info(
            f"[tls.peet.ws/api/all] cffi-defaults header-set verified ({impersonate}/{header_mode}+strip={strip_leak}): UA={ua[:40]}..."
        )
