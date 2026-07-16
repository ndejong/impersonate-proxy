# impersonate-proxy

[![pypi](https://img.shields.io/pypi/v/impersonate-proxy.svg)](https://pypi.org/project/impersonate-proxy/)
[![python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/psaintelligence/impersonate-proxy/)
[![build tests](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml/badge.svg)](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/psaintelligence/impersonate-proxy/blob/main/LICENSE)
<img src="docs/docs/assets/img/logo.jpg" align="right" width="140" style="margin-left: 20px; margin-bottom: 20px;" alt="impersonate-proxy logo">

> [!NOTE]
> This project is a fork of the original source project [hauxir/tls-impersonate-proxy](https://github.com/hauxir/tls-impersonate-proxy) maintained at [psaintelligence/impersonate-proxy](https://github.com/psaintelligence/impersonate-proxy).

HTTP/HTTPS proxy that impersonates browser TLS fingerprints using [curl_cffi](https://github.com/lexiforest/curl_cffi). Defeats JA3/JA4 TLS fingerprinting used by CDNs to block non-browser clients.

---

## Quick Start (Docker)

Spin up the proxy container in one line:

```bash
docker run --rm -p 8899:8899 \
  -v impersonate-proxy-ca-certs:/root/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

Once started, configure your client to trust the CA and use the proxy:

```bash
# Export the generated CA cert to trust the proxy
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt

# Issue request through the proxy
curl -x http://127.0.0.1:8899 https://cloudflare.com
```

---

## Quick Start (pip / uv)

Install and start the proxy locally:

```bash
# Install via pipx from pypi
pipx install impersonate-proxy

# Or install via uv from source
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git

# Start the proxy (default: 127.0.0.1:8899)
impersonate-proxy
```

---

## Documentation

Full guides and configuration details are available at **[ndejong.github.io/impersonate-proxy](https://ndejong.github.io/impersonate-proxy/)**.

- **[Installation Guide](https://ndejong.github.io/impersonate-proxy/install/)**: Setup, CLI arguments, and Docker.
- **[How It Works](https://ndejong.github.io/impersonate-proxy/workflow/)**: Detailed information about TLS impersonation and HTTPS decryption.
- **[Development Guide](https://ndejong.github.io/impersonate-proxy/install/#development)**: Building, running benchmarks, and tests.
