"""Real TLS and mTLS on the uvicorn listeners, flag validation and health endpoints."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import socket
import ssl
import threading
import warnings
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mcp_svid_auth import agent_client, authz, mcp_server
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.mcp_server import JwksUnavailableError, create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from mcp_svid_auth.tls import client_context, tls_server_kwargs
from tests.conftest import ISSUER, POLICY, SERVER_A


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_key(key: ec.EllipticCurvePrivateKey, path: Path) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


@dataclass
class Authority:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate
    path: Path

    @classmethod
    def create(cls, directory: Path, label: str) -> Authority:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(f"{label} test CA"))
            .issuer_name(_name(f"{label} test CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
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
            .sign(key, hashes.SHA256())
        )
        path = directory / f"{label}-ca.pem"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cls(key, cert, path)

    def issue(self, directory: Path, label: str, *, server: bool) -> tuple[Path, Path]:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        usage = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(label))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
        cert = builder.sign(self.key, hashes.SHA256())
        cert_path = directory / f"{label}.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, _write_key(key, directory / f"{label}.key")


@dataclass
class Pki:
    ca: Authority
    other_ca: Authority
    server: tuple[Path, Path]
    client: tuple[Path, Path]
    foreign_client: tuple[Path, Path]


@pytest.fixture
def pki(tmp_path: Path) -> Pki:
    ca = Authority.create(tmp_path, "main")
    other = Authority.create(tmp_path, "other")
    return Pki(
        ca=ca,
        other_ca=other,
        server=ca.issue(tmp_path, "server", server=True),
        client=ca.issue(tmp_path, "client", server=False),
        foreign_client=other.issue(tmp_path, "foreign", server=False),
    )


def _authz() -> AuthzServer:
    return AuthzServer(
        issuer="https://localhost",
        policy=Policy.from_dict(POLICY),
        resolver=LocalSvidIssuer().resolver(),
        audit=AuditLog(path=None, component="authz"),
    )


def _authz_tls_kwargs(pki: Pki, *, mtls: bool) -> dict[str, Any]:
    argv = ["--issuer", "https://localhost", "--policy", "unused.yaml"]
    argv += ["--tls-cert", str(pki.server[0]), "--tls-key", str(pki.server[1])]
    if mtls:
        argv += ["--tls-client-ca", str(pki.ca.path)]
    parser = authz.build_parser()
    return tls_server_kwargs(parser.parse_args(argv), parser, public_url="https://localhost")


@contextlib.contextmanager
def serving(app: Any, tls: dict[str, Any]) -> Iterator[int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    config = uvicorn.Config(app, log_level="warning", lifespan="off", **tls)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve(sockets=[sock])))
    thread.start()
    try:
        for _ in range(500):
            if server.started:
                break
            threading.Event().wait(0.01)
        assert server.started
        yield port
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def _context(pki: Pki, client: tuple[Path, Path] | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(pki.ca.path))
    if client is not None:
        context.load_cert_chain(*client)
    return context


def _get(port: int, verify: ssl.SSLContext | bool, path: str = "/healthz") -> httpx2.Response:
    with httpx2.Client(verify=verify, trust_env=False, timeout=5) as client:
        return client.get(f"https://localhost:{port}{path}")


def test_authz_serves_https_with_a_verified_certificate(pki: Pki) -> None:
    with serving(_authz().app(), _authz_tls_kwargs(pki, mtls=False)) as port:
        response = _get(port, _context(pki))
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_server_certificate_from_an_untrusted_ca_is_refused(pki: Pki) -> None:
    with serving(_authz().app(), _authz_tls_kwargs(pki, mtls=False)) as port:
        wrong = ssl.create_default_context(cafile=str(pki.other_ca.path))
        with pytest.raises(httpx2.ConnectError):
            _get(port, wrong)


def test_plain_http_to_a_tls_listener_gets_no_response(pki: Pki) -> None:
    with (
        serving(_authz().app(), _authz_tls_kwargs(pki, mtls=False)) as port,
        httpx2.Client(trust_env=False, timeout=5) as client,
        pytest.raises(httpx2.HTTPError),
    ):
        response = client.get(f"http://localhost:{port}/healthz")
        assert response.status_code != 200


def test_tls_below_1_2_is_refused(pki: Pki) -> None:
    with serving(_authz().app(), _authz_tls_kwargs(pki, mtls=False)) as port:
        old = _context(pki)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                old.minimum_version = ssl.TLSVersion.TLSv1
                old.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            pytest.skip("local OpenSSL cannot offer TLS 1.1")
        with pytest.raises(httpx2.ConnectError):
            _get(port, old)


def test_mtls_requires_a_client_certificate_from_the_configured_ca(pki: Pki) -> None:
    with serving(_authz().app(), _authz_tls_kwargs(pki, mtls=True)) as port:
        assert _get(port, _context(pki, pki.client)).status_code == 200
        for verify in (_context(pki), _context(pki, pki.foreign_client)):
            with pytest.raises(httpx2.HTTPError):
                _get(port, verify)


def test_mcp_server_serves_https_with_mtls(pki: Pki) -> None:
    source = _authz()
    app = create_app(
        name="a",
        resource="https://localhost/mcp",
        issuer=source.issuer,
        jwks=source.jwks,
        audit=AuditLog(path=None),
    )
    parser = mcp_server.build_parser()
    argv = ["--resource", "https://localhost/mcp", "--issuer", source.issuer]
    argv += ["--tls-cert", str(pki.server[0]), "--tls-key", str(pki.server[1])]
    argv += ["--tls-client-ca", str(pki.ca.path)]
    tls = tls_server_kwargs(parser.parse_args(argv), parser, public_url="https://localhost/mcp")
    with serving(app, tls) as port:
        assert _get(port, _context(pki, pki.client), "/readyz").status_code == 200
        with pytest.raises(httpx2.HTTPError):
            _get(port, _context(pki), "/readyz")


@pytest.mark.parametrize(
    ("extra", "public_url"),
    [
        (["--tls-cert", "c.pem"], "https://localhost"),
        (["--tls-key", "k.pem"], "https://localhost"),
        (["--tls-client-ca", "ca.pem"], "https://localhost"),
        (["--tls-cert", "c.pem", "--tls-key", "k.pem"], "http://localhost"),
    ],
)
def test_incomplete_or_inconsistent_tls_flags_are_refused(
    extra: list[str], public_url: str
) -> None:
    parser = authz.build_parser()
    args = parser.parse_args(["--issuer", public_url, "--policy", "p.yaml", *extra])
    with pytest.raises(SystemExit):
        tls_server_kwargs(args, parser, public_url=public_url)


@pytest.mark.parametrize(("host", "warned"), [("127.0.0.1", False), ("0.0.0.0", True)])  # noqa: S104
def test_plaintext_listener_off_loopback_is_announced(
    host: str, warned: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = authz.build_parser()
    args = parser.parse_args(["--issuer", ISSUER, "--policy", "p.yaml", "--host", host])
    assert tls_server_kwargs(args, parser, public_url=ISSUER) == {}
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == ([{"event": "plaintext_listener", "host": host}] if warned else [])


def test_ca_file_replaces_trust_store_but_keeps_verification(pki: Pki) -> None:
    assert client_context(None) is True
    context = client_context(pki.ca.path)
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    args = agent_client.build_parser().parse_args(
        [
            *("--resource", SERVER_A, "--scope", "notes:read", "--trusted-issuer", ISSUER),
            *("--ca-file", str(pki.ca.path)),
        ]
    )
    policy = agent_client.url_policy_from_args(args)
    assert isinstance(policy.tls_verify, ssl.SSLContext)
    assert policy.tls_verify.check_hostname


def test_agent_with_private_ca_reaches_tls_listener(pki: Pki) -> None:
    async def fetch(port: int) -> int:
        policy = agent_client.UrlPolicy(allow_private=True, tls_verify=client_context(pki.ca.path))
        async with agent_client.default_http(policy) as client:
            return (await client.get(f"https://localhost:{port}/healthz")).status_code

    with serving(_authz().app(), _authz_tls_kwargs(pki, mtls=False)) as port:
        assert asyncio.run(fetch(port)) == 200


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_authz_readiness_fails_after_a_failed_policy_reload(anyio_backend: str) -> None:
    server = _authz()
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=server.app()), base_url="http://authz.test"
    ) as client:
        assert (await client.get("/readyz")).status_code == 200
        server.policy = Policy(trust_domain="example.org", grants={})
        response = await client.get("/readyz")
        assert (await client.get("/healthz")).status_code == 200
    assert response.status_code == 503
    assert response.json() == {"status": "policy_unavailable"}


class _BrokenJwks:
    async def get(self, *, refresh: bool = False) -> dict[str, Any]:
        raise JwksUnavailableError("down")


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_mcp_readiness_reflects_jwks_availability(anyio_backend: str) -> None:
    good = _authz()
    for jwks, status in ((good.jwks, 200), (_BrokenJwks(), 503)):
        app = create_app(
            name="a", resource=SERVER_A, issuer=ISSUER, jwks=jwks, audit=AuditLog(path=None)
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://notes-a.test"
        ) as client:
            assert (await client.get("/readyz")).status_code == status
            assert (await client.get("/healthz")).status_code == 200


def test_resource_path_may_not_shadow_health_endpoints() -> None:
    with pytest.raises(ValueError, match="health endpoint"):
        create_app(
            name="a",
            resource="http://notes-a.test/healthz",
            issuer=ISSUER,
            jwks=_authz().jwks,
            audit=AuditLog(path=None),
        )
