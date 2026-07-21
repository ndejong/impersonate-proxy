# Installation & CLI Guide

`impersonate-proxy` can be run either as a local Python application or containerized using Docker.

---

## Local Installation

### Prerequisites
- Python 3.12 or newer
- `pip` or `uv` package manager

```bash
# Install via pipx from pypi
pipx install impersonate-proxy

# Or install via uv from source
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git

# Start the proxy (default: 127.0.0.1:8899)
impersonate-proxy
```

---

## Docker Installation (Recommended)

Running the proxy via Docker is recommended for isolated operation and to persist certificate states easily.

```bash
docker run --rm -p 8899:8899 \
  -v /tmp/impersonate-certs:/root/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

### Docker Compose
You can spin up the service in the background using docker-compose:
```yaml
services:
  proxy:
    image: ghcr.io/psaintelligence/impersonate-proxy:latest
    ports:
      - "8899:8899"
    environment:
      - IMPERSONATE_PROXY_IMPERSONATE=chrome
      - IMPERSONATE_PROXY_DEBUG=false
    volumes:
      - impersonate-proxy-ca-certs:/root/.config/impersonate-proxy

volumes:
  impersonate-proxy-ca-certs:
```

---

## Command Line Interface (CLI)

Run `impersonate-proxy --help` to view all available parameters:

```text
usage: python3 -m impersonate_proxy.main [-h] [--port PORT] [--host HOST]
                                         [--impersonate IMPERSONATE]
                                         [--passthrough-headers | --enrich-headers | --override-headers]
                                         [--strip-client-leak-headers]
                                         [--ca-dir CA_DIR] [--debug] [--quiet]

HTTP/HTTPS proxy that impersonates browser TLS fingerprints

options:
  -h, --help            show this help message and exit
  --port, -p PORT       Port to listen on (default: 8899 or
                        IMPERSONATE_PROXY_PORT)
  --host, -H HOST       Host to bind to (default: 127.0.0.1 or
                        IMPERSONATE_PROXY_HOST)
  --impersonate, -i IMPERSONATE
                        Browser to impersonate (chrome, firefox, etc. Default:
                        chrome or IMPERSONATE_PROXY_IMPERSONATE)
  --passthrough-headers
                        Forward client headers untouched; curl_cffi only sets
                        TLS-impersonation headers. Equivalent to the previous
                        --no-enrich-headers behaviour.
  --enrich-headers      Fill missing browser headers and replace non-browser
                        User-Agents. [DEFAULT]
  --override-headers    Replace the curated browser-header set (Accept, Sec-*,
                        etc.) with the impersonation profile defaults and drop
                        nav-mismatch tells (Cache-Control, DNT, Connection).
                        Use for clients that leak non-browser signals (e.g.
                        SearXNG).
  --strip-client-leak-headers
                        Drop middlebox-chain / tracing leak headers (X-Forwarded-*,
                        Forwarded, Via, X-Request-ID, X-Correlation-ID).
                        CDN-ingress headers (X-Real-IP, True-Client-IP, etc.)
                        are forwarded with a warning when present. Combinable
                        with any header mode.
  --ca-dir, -c CA_DIR   Directory to store/load CA certificate and key (default:
                        ~/.config/impersonate-proxy or IMPERSONATE_PROXY_CA_DIR)
  --debug, -d           Enable verbose debug logging (unredacts URLs/hosts in
                        logs) or IMPERSONATE_PROXY_DEBUG=true
  --quiet, -q           Disable logging of request traffic or
                        IMPERSONATE_PROXY_QUIET=true
```

The three header-mode flags are mutually exclusive. The default mode is
`--enrich-headers`. Equivalent environment variables are
`IMPERSONATE_PROXY_HEADER_MODE` (one of `passthrough`, `enrich`, `override`) and
`IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS` (boolean).

---

## Trusting the Root CA

To allow client applications to perform HTTPS requests through the proxy without throwing SSL verification errors:

1. **Locate the Certificate**: By default, the root certificate is created at `~/.config/impersonate-proxy/ca.crt`.
2. **Set Environment Variables**: Many tools (like `curl`, `wget`, `python-requests`, `httpx`) respect specific environment variables for trust stores:

```bash
# Set CA trust path for curl
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt

# Set CA trust path for python-requests
export REQUESTS_CA_BUNDLE=~/.config/impersonate-proxy/ca.crt

# Test HTTPS request through the proxy
curl -x http://127.0.0.1:8899 https://example.com
```
