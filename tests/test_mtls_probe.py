"""A missing client certificate is proved by a TLS alert, never by an outage."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Self

import pytest

from deploy import probe_mtls


class SocketStub:
    def __init__(self, error: OSError | None = None, response: bytes = b"H") -> None:
        self.error = error
        self.response = response

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def sendall(self, _request: bytes) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        if self.error is not None:
            raise self.error
        return self.response


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("TLSV13_ALERT_CERTIFICATE_REQUIRED", True),
        ("SSLV3_ALERT_HANDSHAKE_FAILURE", True),
        ("CERTIFICATE_VERIFY_FAILED", False),
        ("UNEXPECTED_EOF_WHILE_READING", False),
        ("WRONG_VERSION_NUMBER", False),
    ],
)
def test_only_explicit_peer_authentication_alerts_count(
    reason: str, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = ssl.SSLError("private failure details")
    error.reason = reason
    context = ssl.create_default_context()
    connection = SocketStub()
    secure = SocketStub(error)
    calls: list[tuple[tuple[str, int], int]] = []
    names: list[str] = []

    def connect(address: tuple[str, int], timeout: int) -> SocketStub:
        calls.append((address, timeout))
        return connection

    def wrap(_connection: SocketStub, *, server_hostname: str) -> SocketStub:
        names.append(server_hostname)
        return secure

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(context, "wrap_socket", wrap)
    assert (
        probe_mtls.missing_certificate_is_rejected(context, "192.0.2.10", "api.example.org", 8443)
        is expected
    )
    assert calls == [(("192.0.2.10", 8443), 15)]
    assert names == ["api.example.org"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


@pytest.mark.parametrize(
    "error", [ConnectionResetError(), TimeoutError(), ConnectionRefusedError()]
)
def test_network_failure_is_not_proof_of_denial(
    error: OSError, monkeypatch: pytest.MonkeyPatch
) -> None:
    def connect(*_args: object, **_kwargs: object) -> SocketStub:
        raise error

    monkeypatch.setattr(socket, "create_connection", connect)
    assert not probe_mtls.missing_certificate_is_rejected(
        ssl.create_default_context(), "192.0.2.10", "api.example.org", 8443
    )


@pytest.mark.parametrize("response", [b"H", b""])
def test_http_response_or_silent_close_is_not_tls_rejection(
    response: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = ssl.create_default_context()
    connection = SocketStub(response=response)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)
    monkeypatch.setattr(context, "wrap_socket", lambda *_args, **_kwargs: connection)
    assert not probe_mtls.missing_certificate_is_rejected(
        context, "192.0.2.10", "api.example.org", 8443
    )


@pytest.mark.parametrize("verify_mode", [ssl.CERT_REQUIRED, ssl.CERT_NONE])
def test_weakened_server_verification_prevents_any_connection(
    verify_mode: ssl.VerifyMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = verify_mode

    def connect(*_args: object, **_kwargs: object) -> SocketStub:
        pytest.fail("an unverified server cannot prove client-certificate enforcement")

    monkeypatch.setattr(socket, "create_connection", connect)
    assert not probe_mtls.missing_certificate_is_rejected(
        context, "192.0.2.10", "api.example.org", 8443
    )


def test_host_audit_does_not_require_the_container_tls_helper() -> None:
    probe = Path(__file__).resolve().parents[2] / "hipaa-fhir-mcp/deploy/kubernetes/probe_fhir.py"
    if not probe.is_file():
        pytest.skip("The optional FHIR lab repository is not present")
    result = subprocess.run(
        [sys.executable, "-I", str(probe), "audit"],
        input="",
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0 and not result.stderr
    assert json.loads(result.stdout) == {"event": "fhir_audit", "ok": False}
