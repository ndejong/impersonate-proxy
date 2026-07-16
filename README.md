# impersonate-proxy

> [!NOTE]
> This project is a fork of the original source project [hauxir/tls-impersonate-proxy](https://github.com/hauxir/tls-impersonate-proxy) maintained at [psaintelligence/impersonate-proxy](https://github.com/psaintelligence/impersonate-proxy).

HTTP/HTTPS proxy that impersonates browser TLS fingerprints using [curl_cffi](https://github.com/lexiforest/curl_cffi). Defeats JA3/JA4 TLS fingerprinting used by CDNs to block non-browser clients.

## How it works

Many CDNs use TLS fingerprinting (JA3/JA4) to distinguish real browsers from tools like ffmpeg, curl, wget, etc. This proxy sits between your client and the internet, re-issuing every request with a browser TLS fingerprint via curl_cffi.

- **HTTP requests**: Proxied directly with browser TLS fingerprint
- **HTTPS requests**: MITM (Man-in-the-Middle) with certificates signed by a local CA, then re-issued with browser TLS fingerprint

---

## Install

```bash
pip install git+https://github.com/psaintelligence/impersonate-proxy.git
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git
```

---

## Usage

```bash
# Start the proxy (default: 127.0.0.1:8899)
impersonate-proxy

# Custom port and host
impersonate-proxy --port 9000 --host 0.0.0.0

# Different browser fingerprint
impersonate-proxy --impersonate edge101

# Custom CA certificate storage directory
impersonate-proxy --ca-dir ~/.my-certs
```

### With ffmpeg

```bash
ffmpeg -http_proxy http://127.0.0.1:8899 -i https://stream.example.com/live.m3u8 output.mp4
```

### With curl

To use the proxy with HTTPS requests, you must pass the generated CA certificate to curl or install it in your system trust store:

```bash
curl --cacert ~/.config/impersonate-proxy/ca.crt -x http://127.0.0.1:8899 https://example.com
```

### With any HTTP client

Set the `http_proxy` / `https_proxy` environment variables:

```bash
export http_proxy=http://127.0.0.1:8899
export https_proxy=http://127.0.0.1:8899

# For Python HTTP clients (requests, httpx)
export REQUESTS_CA_BUNDLE=~/.config/impersonate-proxy/ca.crt
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt
```

---

## Configuration Options

| Command Line Option | Environment Variable | Default | Description |
|---|---|---|---|
| `--port` / `-p` | `IMPERSONATE_PROXY_PORT` | `8899` | Port to listen on |
| `--host` / `-H` | `IMPERSONATE_PROXY_HOST` | `127.0.0.1` | Host to bind to |
| `--impersonate` / `-i` | `IMPERSONATE_PROXY_IMPERSONATE` | `chrome` | Browser to impersonate |
| `--ca-dir` / `-c` | `IMPERSONATE_PROXY_CA_DIR` | `~/.config/impersonate-proxy` | Directory to load/store the CA files |
| `--no-enrich-headers` | `IMPERSONATE_PROXY_ENRICH_HEADERS=false` | *(enrichment on)* | Disable automatic browser header injection (User-Agent, Sec-Fetch-*, etc.) |
| `--debug` / `-d` | `IMPERSONATE_PROXY_DEBUG` | `false` | Enable verbose debug logging and show identifying details in logs |

---

## How HTTPS works

For HTTPS, the proxy uses MITM (Man-in-the-Middle):

1. On startup, the proxy loads or generates the CA private key (`ca.key`) and self-signed certificate (`ca.crt`) in the specified `--ca-dir`. Existing keys/certs in the directory are reused.
2. When a client sends a CONNECT request, the proxy wraps the connection with a dynamically generated site-specific certificate signed by the CA (generated quickly using ECDSA P-256 keys).
3. The proxy reads the decrypted HTTP requests inside the secure tunnel and forwards them using `curl_cffi` with browser TLS signatures.
4. If the CA files cannot be loaded or generated, the proxy falls back to a raw TCP tunnel (no TLS impersonation for HTTPS).

---

## Docker

You can run the proxy inside Docker using the provided `Dockerfile` and `docker-compose.yml`.

### Docker Compose

1. Start the container:
   ```bash
   docker compose up -d
   ```
2. Retrieve the generated CA certificate from the volume (to use in client requests):
   ```bash
   docker cp impersonate-proxy:/certs/ca.crt ./ca.crt
   ```
3. Test the proxy connection:
   ```bash
   curl --cacert ./ca.crt -x http://127.0.0.1:8899 https://example.com
   ```

---

## Development

Make targets are available for development tasks (utilizing an isolated `uv` virtual environment):

```bash
make setup          # Setup environment and dependencies
make sync           # Synchronize python dependencies
make lint           # Check code format and style
make lint-fix       # Automatically format and fix issues
make typecheck      # Run basedpyright static type checker
make test           # Run offline unit and integration tests
make test-verbose   # Run tests with verbose output
make test-live      # Run basic live tests (hit real URLs)
make test-extended  # Run extended bot-detection fingerprint tests
make benchmark      # Run concurrency performance benchmark
make docs-sync      # Sync documentation dependencies
make docs-build     # Build documentation site
make docs-serve     # Serve documentation locally
make build          # Build wheel and source distributions
make bump-patch     # Bump version patch number
make bump-minor     # Bump version minor number
make clean          # Remove build and cache directories
```
