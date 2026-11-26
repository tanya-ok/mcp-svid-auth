"""Full flow over real HTTPS sockets: discovery, JWT-SVID exchange, DPoP, scoped tool calls."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn

from mcp_svid_auth.agent_client import UrlPolicy, call_tool, fetch_access_token
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.dpop import DPoPKey
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from mcp_svid_auth.tls import client_context
from tests.conftest import RESEARCH
from tests.test_tls_listeners import Pki, make_pki


def _socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    return sock, int(sock.getsockname()[1])


@contextlib.contextmanager
def _serve(app: Any, sock: socket.socket, pki: Pki) -> Iterator[None]:
    config = uvicorn.Config(
        app,
        log_level="warning",
        ssl_certfile=str(pki.server[0]),
        ssl_keyfile=str(pki.server[1]),
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve(sockets=[sock])))
    thread.start()
    try:
        for _ in range(500):
            if server.started:
                break
            threading.Event().wait(0.01)
        assert server.started
        yield
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


@contextlib.contextmanager
def _world(pki: Pki, tmp_path: Path) -> Iterator[tuple[str, str, LocalSvidIssuer, Path]]:
    authz_sock, authz_port = _socket()
    mcp_sock, mcp_port = _socket()
    issuer = f"https://localhost:{authz_port}"
    resource = f"https://localhost:{mcp_port}/mcp"
    spire = LocalSvidIssuer()
    policy = Policy.from_dict(
        {
            "trust_domain": "example.org",
            "clients": [{"spiffe_id": RESEARCH, "resources": {resource: ["notes:read"]}}],
        }
    )
    authz = AuthzServer(
        issuer=issuer,
        policy=policy,
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        dpop_required=True,
    )
    audit_path = tmp_path / "mcp.jsonl"
    app = create_app(
        name="a",
        resource=resource,
        issuer=issuer,
        jwks=authz.jwks,
        audit=AuditLog(path=audit_path),
        dpop_required=True,
    )
    with _serve(authz.app(), authz_sock, pki), _serve(app, mcp_sock, pki):
        yield issuer, resource, spire, audit_path


@pytest.fixture
def pki(tmp_path: Path) -> Pki:
    return make_pki(tmp_path)


def _policy(pki: Pki) -> UrlPolicy:
    return UrlPolicy(private_hosts=frozenset({"localhost"}), tls_verify=client_context(pki.ca.path))


def test_dpop_flow_over_https(pki: Pki, tmp_path: Path) -> None:
    async def flow(issuer: str, resource: str, spire: LocalSvidIssuer) -> list[str]:
        urls = _policy(pki)
        key = DPoPKey()
        token = await fetch_access_token(
            resource,
            spire.source_for(RESEARCH),
            scope="notes:read",
            trusted_issuers=[issuer],
            url_policy=urls,
            dpop=key,
        )
        assert token["token_type"] == "DPoP"
        access = str(token["access_token"])
        allowed = await call_tool(
            resource, access, "notes.search", {"query": "welcome"}, url_policy=urls, dpop=key
        )
        as_bearer = await call_tool(
            resource, access, "notes.search", {"query": "welcome"}, url_policy=urls
        )
        other_key = await call_tool(
            resource,
            access,
            "notes.search",
            {"query": "welcome"},
            url_policy=urls,
            dpop=DPoPKey(),
        )
        return [allowed, as_bearer, other_key]

    with _world(pki, tmp_path) as (issuer, resource, spire, _):
        allowed, as_bearer, other_key = asyncio.run(flow(issuer, resource, spire))
    assert "welcome" in allowed
    assert as_bearer.startswith("HTTP 401")
    assert other_key.startswith("HTTP 401")


def test_untrusted_server_certificate_stops_the_flow_before_any_svid(
    pki: Pki, tmp_path: Path
) -> None:
    fetched: list[str] = []

    class Source:
        def fetch(self, audience: str) -> str:
            fetched.append(audience)
            return ""

    async def flow(issuer: str, resource: str) -> None:
        wrong = UrlPolicy(
            private_hosts=frozenset({"localhost"}), tls_verify=client_context(pki.other_ca.path)
        )
        await fetch_access_token(
            resource, Source(), scope="notes:read", trusted_issuers=[issuer], url_policy=wrong
        )

    with (
        _world(pki, tmp_path) as (issuer, resource, _, _),
        pytest.raises(httpx2.ConnectError),
    ):
        asyncio.run(flow(issuer, resource))
    assert fetched == []
