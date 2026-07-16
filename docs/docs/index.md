# PSA Intelligence Impersonate Proxy

[![pypi](https://img.shields.io/pypi/v/impersonate-proxy.svg)](https://pypi.org/project/impersonate-proxy/)
[![python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/psaintelligence/impersonate-proxy/)
[![build tests](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml/badge.svg)](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/psaintelligence/impersonate-proxy/blob/main/LICENSE)
<img src="assets/img/logo.jpg" align="right" width="140" style="margin-left: 20px; margin-bottom: 20px;" alt="impersonate-proxy logo">

**HTTP/HTTPS proxy that impersonates browser TLS fingerprints (JA3/JA4) using `curl_cffi` to manage CDN fingerprint-based blocking of non-browser clients.**

!!! note "Fork Attribution"
    This project is a fork of the original source project [hauxir/tls-impersonate-proxy](https://github.com/hauxir/tls-impersonate-proxy) maintained at [psaintelligence/impersonate-proxy](https://github.com/psaintelligence/impersonate-proxy).

---

## Features

- **TLS Impersonation**: Disguises client TLS fingerprints as standard browsers (Chrome or Firefox).
- **Centralized Header Enrichment**: Automatically decorates incoming requests from plain/command-line clients (e.g. `curl`, `requests`) with matching browser headers (User-Agent, Accept, Chromium Client Hints) corresponding to the active TLS profile.
- **Connection Keep-Alive & Session Pooling**: Reuses TLS sessions and upstream TCP connections to optimize latency and handle high-concurrency requests.
- **Fast Dynamic Cert Generation**: Dynamic certificate generation using fast Elliptic Curve (ECDSA P-256) cryptography with leaf key reuse.

---

## Quick Start (Docker)

Spin up the proxy container in one line:

```bash
docker run --rm -p 8899:8899 \
  -v impersonate-proxy-ca-certs:/root/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

Once started, configure your client to use the proxy:

```bash
# Export the generated CA cert to trust the proxy
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt

# Issue request through the proxy
curl -x http://127.0.0.1:8899 https://cloudflare.com
```

---

## Capabilities

| Capability | What it does | Benefit |
|---|---|---|
| **TLS Fingerprinting** | Matches JA3/JA4/HTTP2 fingerprints with real browsers | Defeats Cloudflare, Akamai, and Imperva WAF blocks |
| **MITM CONNECT Decryption** | Decrypts and re-signs HTTPS traffic using local CA | Allows inspection, headers modification, and proxying of TLS streams |
| **Header Enrichment** | Auto-injects appropriate browser headers & Client Hints | Ensures User-Agent and TLS fingerprint profiles align out-of-the-box |
| **Session Pooling** | Maintains queue-based reusable `curl_cffi` sessions | Boosts performance for concurrent request bursts to ~70+ RPS |
| **P-256 Cryptography** | Reuses a static leaf private key for ECDSA cert creation | Reduces leaf certificate dynamic issuance time to `<1ms` |

---

## Guided Tour

- **[Installation Guide](install.md)**: System setup, CLI parameters, and Docker integrations.
- **[How It Works](workflow.md)**: Deep dive into the interception pipeline, session pool, and header decoration mechanism.
