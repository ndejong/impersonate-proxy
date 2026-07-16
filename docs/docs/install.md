# Installation & CLI Guide

`impersonate-proxy` can be run either as a local Python application or containerized using Docker.

---

## Local Installation

### Prerequisites
- Python 3.12 or newer
- `pip` or `uv` package manager

### Install via git
```bash
pip install git+https://github.com/psaintelligence/impersonate-proxy.git
```

Or using [uv](https://github.com/astral-sh/uv):
```bash
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git
```

---

## Docker Installation (Recommended)

Running the proxy via Docker is recommended for isolated operation and to persist certificate states easily.

### Local Docker Build
```bash
# Build the Docker image
docker build -t impersonate-proxy .

# Run the proxy container (binding port 8899 and persisting CA certs)
docker run --rm -p 8899:8899 \
  -v impersonate-proxy-ca-certs:/root/.config/impersonate-proxy \
  impersonate-proxy
```

### Docker Compose
You can spin up the service in the background using docker-compose:
```yaml
services:
  proxy:
    build: .
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
usage: impersonate-proxy [-h] [--port PORT] [--host HOST] [--impersonate IMPERSONATE]
                         [--ca-dir CA_DIR] [--no-enrich-headers] [--debug]

options:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  Port to listen on (default: 8899 or IMPERSONATE_PROXY_PORT)
  --host HOST, -H HOST  Host to bind to (default: 127.0.0.1 or IMPERSONATE_PROXY_HOST)
  --impersonate IMPERSONATE, -i IMPERSONATE
                        Browser to impersonate (chrome, firefox, etc. Default: chrome or IMPERSONATE_PROXY_IMPERSONATE)
  --ca-dir CA_DIR, -c CA_DIR
                        Directory to store/load CA certificate and key (default: ~/.config/impersonate-proxy or IMPERSONATE_PROXY_CA_DIR)
  --no-enrich-headers   Disable automatic browser header enrichment (User-Agent, Sec-Fetch-*, etc.)
                        Can also be set via IMPERSONATE_PROXY_ENRICH_HEADERS=false
  --debug, -d           Enable verbose debug logging (unredacts URLs/hosts in logs)
```

---

## Trusting the Root CA

To allow client applications to perform HTTPS requests through the proxy without throwing SSL verification errors:

1. **Locate the Certificate**: By default, the root certificate is created at `~/.config/impersonate-proxy/ca.crt`.
2. **Set Environment Variables**: Many tools (like `curl`, `wget`, `python-requests`, `httpx`) respect specific environment variables for trust stores:

```bash
# Set CA trust path for curl/python
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt
export REQUESTS_CA_BUNDLE=~/.config/impersonate-proxy/ca.crt

# Test HTTPS request through the proxy
curl -x http://127.0.0.1:8899 https://example.com
```
