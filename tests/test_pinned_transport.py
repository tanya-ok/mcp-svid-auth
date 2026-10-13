"""Address binding, TLS identity, separate origins and proxy bypass prevention."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_svid_auth.agent_client import UnsafeUrlError, UrlPolicy, default_http
from mcp_svid_auth.pinned_transport import PinnedTransport

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_rebinding_is_rechecked_before_credentials_leave(monkeypatch: Any) -> None:
    answers = iter([["8.8.8.8"], ["127.0.0.1"]])

    async def resolve(host: str) -> list[str]:
        return next(answers)

    policy = UrlPolicy(resolve=resolve)
    await policy.check("https://mcp.example.org/token")

    def forbidden_pool(**kwargs: Any) -> Any:
        pytest.fail("a socket must not open for a refused address")

    monkeypatch.setattr(httpx2, "AsyncHTTPTransport", forbidden_pool)
    async with default_http(url_policy=policy) as client:
        with pytest.raises(UnsafeUrlError):
            await client.post("https://mcp.example.org/token", content="never-sent-credential")


async def test_numeric_connection_preserves_origin_and_ignores_proxy(monkeypatch: Any) -> None:
    pools: list[Any] = []

    class Pool:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["trust_env"] is False
            self.requests: list[httpx2.Request] = []
            pools.append(self)

        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            self.requests.append(request)
            return httpx2.Response(200, content=b"ok")

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(httpx2, "AsyncHTTPTransport", Pool)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")

    async def resolve(host: str) -> list[str]:
        return ["8.8.8.8"]

    async with default_http(url_policy=UrlPolicy(resolve=resolve)) as client:
        for host in ("a.example.org", "b.example.org"):
            await client.get(f"https://{host}:8443/path")
    assert len(pools) == 2
    for pool, host in zip(pools, ("a.example.org", "b.example.org"), strict=True):
        request = pool.requests[0]
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == host + ":8443"
        assert request.extensions["sni_hostname"] == host


def tls_contexts(path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp.example.org")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mcp.example.org")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = path / "cert.pem", path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    assert client.check_hostname
    return server, client


async def test_actual_tls_checks_original_hostname(tmp_path: Path) -> None:
    server_context, client_context = tls_contexts(tmp_path)
    names: list[str | None] = []
    hosts: list[str] = []
    server_context.set_servername_callback(lambda socket, name, ctx: names.append(name))

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        hosts.append(headers.decode())
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    async def resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    policy = UrlPolicy(allow_private=True, resolve=resolve)
    async with await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context) as server:
        port = server.sockets[0].getsockname()[1]
        transport = PinnedTransport(policy.addresses, verify=client_context)
        async with httpx2.AsyncClient(transport=transport, trust_env=False) as client:
            assert (await client.get(f"https://mcp.example.org:{port}/")).text == "ok"
            with pytest.raises(httpx2.ConnectError):
                await client.get(f"https://wrong.example.org:{port}/")
    assert names == ["mcp.example.org", "wrong.example.org"]
    assert f"Host: mcp.example.org:{port}" in hosts[0]
    assert len(hosts) == 1
