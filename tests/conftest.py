"""In-process world: a stand-in SPIRE, the authz server and two notes MCP servers.

All HTTP goes through httpx2.ASGITransport, routed by host. No network, no SPIRE.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest
from starlette.applications import Starlette
from starlette.types import Receive, Scope, Send

from mcp_svid_auth.agent_client import UrlPolicy
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer

ISSUER = "http://authz.test"
SERVER_A = "http://notes-a.test/mcp"
SERVER_B = "http://notes-b.test/mcp"
RESEARCH = "spiffe://example.org/agent/research"
INTRUDER = "spiffe://example.org/agent/intruder"
READER = "spiffe://example.org/agent/reader"
# The in-process world uses http and .test hosts that do not resolve.
DEV_URLS = UrlPolicy(allow_http=True, allow_private=True)

POLICY = {
    "trust_domain": "example.org",
    "clients": [
        {
            "spiffe_id": RESEARCH,
            "resources": {SERVER_A: ["notes:read", "notes:write"], SERVER_B: ["notes:read"]},
        },
        {"spiffe_id": READER, "resources": {SERVER_A: ["notes:read"]}},
    ],
}


class HostRouter:
    def __init__(self, apps: dict[str, Any]) -> None:
        self.apps = apps

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode().split(":")[0]
        await self.apps[host](scope, receive, send)


@dataclass
class World:
    spire: LocalSvidIssuer
    authz: AuthzServer
    audit_path: Path
    router: HostRouter

    def http(self, **kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.router), **kwargs)

    def audit_lines(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        text = self.audit_path.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]


@pytest.fixture
def spire() -> LocalSvidIssuer:
    return LocalSvidIssuer()


@pytest.fixture
def authz(spire: LocalSvidIssuer, tmp_path: Path) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
    )


@contextlib.asynccontextmanager
async def _running(apps: list[Starlette]) -> AsyncIterator[None]:
    async with contextlib.AsyncExitStack() as stack:
        for app in apps:
            await stack.enter_async_context(app.router.lifespan_context(app))
        yield


@pytest.fixture
def world_factory(spire: LocalSvidIssuer, authz: AuthzServer, tmp_path: Path) -> Iterator[Any]:
    audit_path = tmp_path / "mcp.jsonl"

    @contextlib.asynccontextmanager
    async def make() -> AsyncIterator[World]:
        audit = AuditLog(path=audit_path)
        app_a = create_app(name="a", resource=SERVER_A, issuer=ISSUER, jwks=authz.jwks, audit=audit)
        app_b = create_app(name="b", resource=SERVER_B, issuer=ISSUER, jwks=authz.jwks, audit=audit)
        router = HostRouter(
            {"authz.test": authz.app(), "notes-a.test": app_a, "notes-b.test": app_b}
        )
        async with _running([app_a, app_b]):
            yield World(spire=spire, authz=authz, audit_path=audit_path, router=router)

    yield make
