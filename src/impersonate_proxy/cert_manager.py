"""Certificate Authority initialization and dynamic host SSLContext caching."""

import contextlib
import datetime
import ipaddress
import logging
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from impersonate_proxy.context import ProxyContext

logger: logging.Logger = logging.getLogger("impersonate-proxy")


def init_ca(ctx: ProxyContext, ca_dir: str | None = None) -> None:
    """Load or generate self-signed CA files in ca_dir for MITM CONNECT handling."""
    with ctx.host_cert_lock:
        ctx.host_cert_cache.clear()
    ctx.clear_session_pool()

    if ca_dir is None:
        ca_dir = (
            ctx.config.ca_dir
            or os.environ.get("IMPERSONATE_PROXY_CA_DIR")
            or os.path.expanduser("~/.config/impersonate-proxy")
        )
    ctx.config.ca_dir = ca_dir

    os.makedirs(ca_dir, exist_ok=True)

    key_path = os.path.join(ca_dir, "ca.key")
    cert_path = os.path.join(ca_dir, "ca.crt")

    try:
        if os.path.exists(key_path) and os.path.exists(cert_path):
            with open(key_path, "rb") as f:
                ctx.ca_key = serialization.load_pem_private_key(f.read(), password=None)  # type: ignore
            with open(cert_path, "rb") as f:
                ctx.ca_cert = x509.load_pem_x509_certificate(f.read())
            logger.info(f"Loaded existing CA key and certificate from {ctx.show_identifying(ca_dir)}")
            return

        ctx.ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Impersonate Proxy CA"),
            ]
        )
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(ctx.ca_key.public_key())
        ctx.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ctx.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(subject_key_id, critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ctx.ca_key, hashes.SHA256())
        )

        key_bytes = ctx.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key_bytes)

        cert_bytes = ctx.ca_cert.public_bytes(serialization.Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)

        logger.info(f"Generated and saved new CA key and certificate in {ctx.show_identifying(ca_dir)}")

    except Exception as e:
        logger.warning(f"MITM CA init failed ({e}) — CONNECT will fall back to raw tunnel")


def get_cert_for_host(ctx: ProxyContext, hostname: str) -> ssl.SSLContext:
    """Get or create a cached SSL context for the given hostname."""
    with ctx.host_cert_lock:
        ssl_ctx = ctx.host_cert_cache.get(hostname)
        if ssl_ctx is not None:
            logger.debug(f"SSLContext cache hit for: {ctx.show_identifying(hostname)}")
            return ssl_ctx

    try:
        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    if ctx.leaf_key is None:
        ctx.leaf_key = ec.generate_private_key(ec.SECP256R1())
    key = ctx.leaf_key
    logger.debug(f"Generating dynamic host certificate for: {ctx.show_identifying(hostname)}")
    cn = hostname[:64] if len(hostname) > 64 else hostname
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ctx.ca_cert.subject)  # type: ignore
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ctx.ca_key.public_key()),  # type: ignore
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ctx.ca_key, hashes.SHA256())  # type: ignore
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = key_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(cert_pem)
            cert_file = cf.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
            kf.write(key_pem)
            key_file = kf.name
        ssl_ctx.load_cert_chain(cert_file, key_file)
    finally:
        if cert_file:
            with contextlib.suppress(OSError):
                os.unlink(cert_file)
        if key_file:
            with contextlib.suppress(OSError):
                os.unlink(key_file)

    with ctx.host_cert_lock:
        existing = ctx.host_cert_cache.get(hostname)
        if existing is not None:
            return existing
        ctx.host_cert_cache[hostname] = ssl_ctx
        while len(ctx.host_cert_cache) > ctx.host_cert_max:
            evicted, _ = ctx.host_cert_cache.popitem(last=False)
            logger.debug(f"Evicted host from certificate cache: {ctx.show_identifying(evicted)}")
    return ssl_ctx
