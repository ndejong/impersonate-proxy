"""Proxy request handler and multithreaded HTTP server."""

import contextlib
import http.client
import ipaddress
import logging
import select
import socket
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from impersonate_proxy.cert_manager import get_cert_for_host
from impersonate_proxy.context import ProxyContext
from impersonate_proxy.header_filter import sanitize_headers
from impersonate_proxy.session_pool import do_request

CHUNK_SIZE: int = 65536
logger: logging.Logger = logging.getLogger("impersonate-proxy")


def get_client_netblock(ip_str: str) -> str:
    """Return the /24 netblock for IPv4 or /64 netblock for IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        else:
            return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
    except Exception:
        return ip_str


def raw_tunnel(ctx: ProxyContext, client_sock: socket.socket, host: str, port: int) -> None:
    """Relay bytes between client and upstream without inspection."""
    logger.info(f"Establishing raw tunnel to: {ctx.show_identifying(f'{host}:{port}')}")
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        logger.error(f"Raw tunnel connect failed for {ctx.show_identifying(f'{host}:{port}')}: {e}")
        return
    try:
        while True:
            readable, _, _ = select.select([client_sock, upstream], [], [], 30)
            if not readable:
                break
            for sock in readable:
                data = sock.recv(CHUNK_SIZE)
                if not data:
                    raise ConnectionError("closed")
                if sock is client_sock:
                    upstream.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            upstream.shutdown(socket.SHUT_RDWR)
        upstream.close()


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """HTTP/HTTPS proxy request handler using a ProxyContext."""

    ctx: ProxyContext

    def log_message(self, format, *args):
        pass

    def do_CONNECT(self) -> None:
        host, _, port_str = self.path.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            logger.warning(f"CONNECT bad host:port: {self.ctx.show_identifying(self.path[:120])}")
            self.send_error(400, "Bad host:port")
            return

        client_ip = self.client_address[0]
        netblock = get_client_netblock(client_ip)
        if not self.ctx.config.quiet:
            logger.info(f"CONNECT request from {netblock} to {host}")

        self.send_response(200, "Connection established")
        self.end_headers()

        if self.ctx.ca_key is None:
            if not self.ctx.config.quiet:
                logger.info(f"CONNECT {self.ctx.show_identifying(f'{host}:{port}')} (raw tunnel, no impersonation)")
            raw_tunnel(self.ctx, self.connection, host, port)
            self.close_connection = True
            return

        try:
            ssl_ctx = get_cert_for_host(self.ctx, host)
            client_tls = ssl_ctx.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            logger.error(f"MITM TLS wrap error for {self.ctx.show_identifying(host)}: {e}")
            self.close_connection = True
            return

        rfile = wfile = None
        try:
            rfile = client_tls.makefile("rb")
            wfile = client_tls.makefile("wb")

            while True:
                req_line = rfile.readline(8193)
                if not req_line or req_line.strip() == b"":
                    break

                parts = req_line.decode("latin-1").strip().split(" ", 2)
                if len(parts) < 2:
                    break
                method = parts[0]
                path = parts[1]

                headers = {}
                while True:
                    hline = rfile.readline(8193)
                    if hline in (b"\r\n", b"\n", b""):
                        break
                    if b":" in hline:
                        k, v = hline.decode("latin-1").split(":", 1)
                        headers[k.strip()] = v.strip()

                body = None
                cl = headers.get("Content-Length")
                if cl:
                    try:
                        body = rfile.read(int(cl))
                    except ValueError:
                        logger.warning("CONNECT-MITM: invalid Content-Length header, ignoring body")

                scheme = "https"
                if port == 443:
                    url = f"{scheme}://{host}{path}"
                else:
                    url = f"{scheme}://{host}:{port}{path}"

                skip = {
                    "host",
                    "proxy-connection",
                    "connection",
                    "keep-alive",
                    "transfer-encoding",
                    "te",
                    "trailer",
                    "upgrade",
                    "proxy-authorization",
                    "proxy-authenticate",
                }
                fwd_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

                logger.debug(
                    f"CONNECT-MITM proxying request: {method} {self.ctx.show_identifying(url)} (headers={sanitize_headers(fwd_headers)})"
                )

                r = do_request(self.ctx, method, url, fwd_headers, body, allow_redirects=False)
                if r is None:
                    wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    wfile.flush()
                    break

                try:
                    skip_h = {"transfer-encoding", "content-encoding", "content-length", "connection", "keep-alive"}
                    resp_headers = [(k, v) for k, v in r.headers.items() if k.lower() not in skip_h]
                    status_code = r.status_code
                    reason = http.client.responses.get(status_code, "Unknown")
                    wfile.write(f"HTTP/1.1 {status_code} {reason}\r\n".encode())
                    for k, v in resp_headers:
                        wfile.write(f"{k}: {v}\r\n".encode())
                    wfile.write(b"Transfer-Encoding: chunked\r\n")
                    wfile.write(b"Connection: close\r\n\r\n")
                    for chunk in r.iter_content():
                        if chunk:
                            wfile.write(f"{len(chunk):x}\r\n".encode())
                            wfile.write(chunk)
                            wfile.write(b"\r\n")
                    wfile.write(b"0\r\n\r\n")
                    wfile.flush()
                    if (status_code >= 400 or self.ctx.config.debug) and not self.ctx.config.quiet:
                        logger.info(f"CONNECT-MITM {method} {self.ctx.show_identifying(url)} -> {status_code}")
                finally:
                    r.close()
                break

        except Exception as e:
            err_msg = str(e)
            if isinstance(e, (BrokenPipeError, ConnectionResetError)) or "curl: (23)" in err_msg:
                logger.debug(f"MITM client disconnected mid-stream: {e}")
            else:
                logger.error(f"MITM handler error: {e}")
        finally:
            if rfile:
                with contextlib.suppress(Exception):
                    rfile.close()
            if wfile:
                with contextlib.suppress(Exception):
                    wfile.close()
            with contextlib.suppress(Exception):
                client_tls.shutdown(socket.SHUT_RDWR)
            client_tls.close()

        self.close_connection = True

    def _proxy(self) -> None:
        url = self.path
        if not url.startswith("http"):
            logger.warning(f"HTTP Proxy bad request: {self.ctx.show_identifying(url)}")
            self.send_error(400, "Absolute URL required")
            return

        client_ip = self.client_address[0]
        netblock = get_client_netblock(client_ip)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if not self.ctx.config.quiet:
            logger.info(f"{self.command} request from {netblock} to {host}")

        skip = {
            "host",
            "proxy-connection",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
            "proxy-authenticate",
        }
        headers = {}
        for key, val in self.headers.items():
            if key.lower() not in skip:
                headers[key] = val

        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        logger.debug(
            f"HTTP Proxy proxying request: {self.command} {self.ctx.show_identifying(url)} (headers={sanitize_headers(headers)})"
        )

        resp = do_request(self.ctx, self.command, url, headers, body)
        if resp is None:
            logger.error(f"HTTP Proxy upstream request failed for: {self.ctx.show_identifying(url)}")
            self.send_error(502, "Upstream request failed")
            return

        try:
            is_head = self.command == "HEAD"
            skip_resp = {"transfer-encoding", "content-encoding", "content-length"}
            resp_headers = [(k, v or "") for k, v in resp.headers.items() if k.lower() not in skip_resp]
            if is_head:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                cl = resp.headers.get("content-length")
                if cl:
                    self.send_header("Content-Length", cl)
                self.end_headers()
            else:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in resp.iter_content():
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            if not self.ctx.config.quiet:
                logger.info(f"HTTP Proxy {self.command} {self.ctx.show_identifying(url)} -> {resp.status_code}")
        except Exception as e:
            err_msg = str(e)
            if isinstance(e, (BrokenPipeError, ConnectionResetError)) or "curl: (23)" in err_msg:
                logger.debug(f"HTTP Proxy client disconnected mid-stream: {e}")
            else:
                logger.error(f"HTTP Proxy handler error for {self.ctx.show_identifying(url)}: {e}")
        finally:
            resp.close()

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_HEAD = _proxy
    do_OPTIONS = _proxy


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multithreaded HTTP server bound to a ProxyContext."""

    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, ctx: ProxyContext):
        self.ctx = ctx
        super().__init__(server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """Instantiate RequestHandlerClass with ctx attached."""
        self.RequestHandlerClass(request, client_address, self)


def create_handler_class(ctx: ProxyContext):
    """Return a ProxyRequestHandler subclass bound to the given ProxyContext."""

    class BoundProxyHandler(ProxyRequestHandler):
        pass

    BoundProxyHandler.ctx = ctx
    return BoundProxyHandler
