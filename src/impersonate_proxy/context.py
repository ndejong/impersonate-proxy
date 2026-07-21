"""Configuration dataclass and operational state container for impersonate-proxy."""

import logging
import queue
import ssl
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from curl_cffi import requests as cffi_requests

logger: logging.Logger = logging.getLogger("impersonate-proxy")


@dataclass
class ProxyConfig:
    """Holds proxy configuration settings."""

    host: str = "127.0.0.1"
    port: int = 8899
    impersonate: str = "chrome"
    ca_dir: str | None = None
    header_mode: str = "cffi-defaults"
    strip_client_leak_headers: bool = False
    debug: bool = False
    quiet: bool = False
    upstream_proxy: str | None = None
    session_pool_max: int = 32
    connect_timeout: float = 10.0
    read_timeout: float = 300.0

    def __post_init__(self) -> None:
        if self.header_mode not in ("passthrough", "cffi-defaults"):
            logger.warning(
                "Unknown header_mode=%r; falling back to 'cffi-defaults'.",
                self.header_mode,
            )
            self.header_mode = "cffi-defaults"


class ProxyContext:
    """Encapsulates runtime state and resources for a proxy server instance."""

    def __init__(
        self,
        config: ProxyConfig | None = None,
        host_cert_max: int = 256,
        session_pool_max: int | None = None,
    ) -> None:
        self.config: ProxyConfig = config or ProxyConfig()
        self.ca_key: ec.EllipticCurvePrivateKey | None = None
        self.ca_cert: x509.Certificate | None = None
        self.leaf_key: ec.EllipticCurvePrivateKey | None = None

        self.host_cert_max: int = host_cert_max
        self.host_cert_cache: OrderedDict[str, ssl.SSLContext] = OrderedDict()
        self.host_cert_lock: threading.Lock = threading.Lock()

        effective_pool_max = session_pool_max if session_pool_max is not None else self.config.session_pool_max
        self.session_pool_max: int = effective_pool_max
        self.session_pool: queue.Queue[cffi_requests.Session] = queue.Queue(maxsize=effective_pool_max)

    def show_identifying(self, val: str) -> str:
        """Return val if debug mode is active, otherwise '[redacted]'."""
        return val if self.config.debug else "[redacted]"

    def clear_session_pool(self) -> None:
        """Close and clear all idle sessions in the pool."""
        while not self.session_pool.empty():
            try:
                sess = self.session_pool.get_nowait()
                sess.close()
            except queue.Empty:
                break
