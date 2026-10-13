"""Require an explicit TLS alert when a synthetic client omits its certificate."""

from __future__ import annotations

import socket
import ssl


def missing_certificate_is_rejected(
    context: ssl.SSLContext, address: str, hostname: str, port: int
) -> bool:
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        return False
    try:
        with (
            socket.create_connection((address, port), timeout=15) as connection,
            context.wrap_socket(connection, server_hostname=hostname) as secure,
        ):
            # TLS 1.3 can complete the client handshake before delivering the alert.
            request = f"GET / HTTP/1.1\r\nHost: {hostname}:{port}\r\nConnection: close\r\n\r\n"
            secure.sendall(request.encode("ascii"))
            secure.recv(1)
    except ssl.SSLError as error:
        return error.reason in {
            "TLSV13_ALERT_CERTIFICATE_REQUIRED",
            "SSLV3_ALERT_HANDSHAKE_FAILURE",
        }
    except OSError:
        return False
    return False
