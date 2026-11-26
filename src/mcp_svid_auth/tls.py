"""TLS for the HTTP listeners and a private CA for outbound verification.

Listeners stay plain HTTP unless a certificate and key are given. With a client CA they also
require and verify a client certificate (mTLS). Outbound clients keep certificate and hostname
verification on; a CA file only replaces the trust store, it never disables checks.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Forward-secret AEAD suites for TLS 1.2; TLS 1.3 suites are not affected by this string.
TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"


def add_tls_server_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tls-cert", type=Path, help="PEM server certificate chain; enables HTTPS with --tls-key"
    )
    parser.add_argument("--tls-key", type=Path, help="PEM private key for --tls-cert")
    parser.add_argument(
        "--tls-client-ca",
        type=Path,
        help="PEM CA bundle; when set, every client must present a certificate it signed (mTLS)",
    )


def add_ca_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ca-file",
        type=Path,
        help="PEM CA bundle that replaces the system trust store for outbound HTTPS",
    )


def tls_server_kwargs(
    args: argparse.Namespace, parser: argparse.ArgumentParser, *, public_url: str
) -> dict[str, Any]:
    """uvicorn TLS settings from the parsed flags; refuses incomplete or inconsistent input."""
    cert, key, client_ca = args.tls_cert, args.tls_key, args.tls_client_ca
    if (cert is None) != (key is None):
        parser.error("--tls-cert and --tls-key must be given together")
    if client_ca is not None and cert is None:
        parser.error("--tls-client-ca needs --tls-cert and --tls-key")
    if cert is None:
        if not _loopback(args.host):
            print(json.dumps({"event": "plaintext_listener", "host": args.host}), file=sys.stderr)
        return {}
    if urlsplit(public_url).scheme != "https":
        parser.error("with --tls-cert the public URL must use https")
    kwargs: dict[str, Any] = {
        "ssl_certfile": str(cert),
        "ssl_keyfile": str(key),
        "ssl_ciphers": TLS12_CIPHERS,
    }
    if client_ca is not None:
        kwargs["ssl_ca_certs"] = str(client_ca)
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return kwargs


def client_context(ca_file: Path | None) -> ssl.SSLContext | bool:
    """Verification setting for outbound clients: system trust, or exactly `ca_file`."""
    if ca_file is None:
        return True
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
