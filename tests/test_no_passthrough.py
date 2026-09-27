"""Security invariant 3: a server never forwards the incoming token.

notes-a calls notes-b through `notes.search_upstream`. Every request that leaves notes-a is
recorded; none may carry the caller's token, and notes-b must see notes-a's own identity.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from starlette.types import Message, Receive, Scope, Send

from mcp_svid_auth.agent_client import call_tool, fetch_access_token
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.mcp_server import NotesStore, Upstream, build_mcp, create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import DEV_URLS, ISSUER, POLICY, RESEARCH, SERVER_A, SERVER_B

pytestmark = pytest.mark.anyio

NOTES_A = "spiffe://example.org/mcp/notes-a"
RELAY_POLICY = {
    "trust_domain": POLICY["trust_domain"],
    "clients": [
        *POLICY["clients"],
        {"spiffe_id": NOTES_A, "resources": {SERVER_B: ["notes:read"]}},
    ],
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Seen:
    host: str
    authorization: str
    raw: bytes


@dataclass
class RecordingRouter:
    """Routes by host like the conftest router and records every request with its body."""

    apps: dict[str, Any]
    seen: list[Seen] = field(default_factory=list)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode().split(":")[0]
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        raw = scope.get("path", "").encode() + scope.get("query_string", b"")
        raw += b"".join(k + b":" + v for k, v in scope.get("headers", [])) + body
        self.seen.append(Seen(host, headers.get(b"authorization", b"").decode(), raw))
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.apps[host](scope, replay, send)

    def http(self, **kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self), **kwargs)


@dataclass
class RelayWorld:
    router: RecordingRouter
    authz: AuthzServer
    spire: LocalSvidIssuer
    audit_path: Path

    def audit_lines(self, component: str) -> list[dict[str, Any]]:
        import json  # noqa: PLC0415

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        return [e for e in map(json.loads, lines) if e["component"] == component]


@contextlib.asynccontextmanager
async def relay_world(tmp_path: Path) -> AsyncIterator[RelayWorld]:
    spire = LocalSvidIssuer()
    authz = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(RELAY_POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
    )
    audit_path = tmp_path / "mcp.jsonl"
    router = RecordingRouter({})
    upstream = Upstream(
        resource=SERVER_B,
        scope="notes:read",
        trusted_issuers=[ISSUER],
        svid_source=spire.source_for(NOTES_A),
        url_policy=DEV_URLS,
        http=router.http,
    )
    app_a = create_app(
        name="a",
        resource=SERVER_A,
        issuer=ISSUER,
        jwks=authz.jwks,
        audit=AuditLog(path=audit_path, component="mcp_server:a"),
        upstream=upstream,
    )
    app_b = create_app(
        name="b",
        resource=SERVER_B,
        issuer=ISSUER,
        jwks=authz.jwks,
        audit=AuditLog(path=tmp_path / "b.jsonl", component="mcp_server:b"),
        store=NotesStore(["upstream note on notes-b"]),
    )
    router.apps.update({"authz.test": authz.app(), "notes-a.test": app_a, "notes-b.test": app_b})
    async with contextlib.AsyncExitStack() as stack:
        for app in (app_a, app_b):
            await stack.enter_async_context(app.router.lifespan_context(app))
        yield RelayWorld(router, authz, spire, tmp_path / "b.jsonl")


async def _caller_token(world: RelayWorld, who: str = RESEARCH) -> str:
    body = await fetch_access_token(
        SERVER_A,
        world.spire.source_for(who),
        scope="notes:read",
        trusted_issuers=[ISSUER],
        http=world.router.http,
        url_policy=DEV_URLS,
    )
    return str(body["access_token"])


async def test_upstream_call_never_carries_caller_token(tmp_path: Path) -> None:
    async with relay_world(tmp_path) as world:
        caller = await _caller_token(world)
        world.router.seen.clear()
        result = await call_tool(
            SERVER_A,
            caller,
            "notes.search_upstream",
            {"query": "upstream"},
            http=world.router.http,
            url_policy=DEV_URLS,
        )
    assert "upstream note on notes-b" in result
    inbound = [s for s in world.router.seen if s.authorization == f"Bearer {caller}"]
    outbound = [s for s in world.router.seen if s not in inbound]
    assert {s.host for s in inbound} == {"notes-a.test"}
    assert {s.host for s in outbound} >= {"authz.test", "notes-b.test"}
    assert all(caller.encode() not in s.raw for s in outbound)
    upstream_auth = {
        s.authorization for s in outbound if s.host == "notes-b.test" and s.authorization
    }
    assert len(upstream_auth) == 1
    claims = jwt.decode(
        upstream_auth.pop().removeprefix("Bearer "), options={"verify_signature": False}
    )
    assert (claims["sub"], claims["aud"], claims["scope"]) == (NOTES_A, SERVER_B, "notes:read")
    b_lines = world.audit_lines("mcp_server:b")
    assert [(e["spiffe_id"], e["tool"], e["decision"]) for e in b_lines] == [
        (NOTES_A, "notes.search", "allow")
    ]


async def test_upstream_token_is_reused_until_near_expiry(tmp_path: Path) -> None:
    async with relay_world(tmp_path) as world:
        caller = await _caller_token(world)
        world.router.seen.clear()
        for _ in range(2):
            await call_tool(
                SERVER_A,
                caller,
                "notes.search_upstream",
                {"query": "x"},
                http=world.router.http,
                url_policy=DEV_URLS,
            )
    token_requests = [s for s in world.router.seen if b"/token" in s.raw[:10]]
    assert len(token_requests) == 1


async def test_forwarded_caller_token_is_rejected_upstream(tmp_path: Path) -> None:
    """What passthrough would look like: the caller's token for notes-a presented at notes-b."""
    async with relay_world(tmp_path) as world:
        caller = await _caller_token(world)
        outcome = await call_tool(
            SERVER_B,
            caller,
            "notes.search",
            {"query": "x"},
            http=world.router.http,
            url_policy=DEV_URLS,
        )
    assert outcome.startswith("HTTP 401")
    assert "InvalidAudienceError" in world.audit_lines("mcp_server:b")[0]["reason"]


async def test_upstream_failure_is_a_fixed_tool_error(tmp_path: Path) -> None:
    async with relay_world(tmp_path) as world:
        world.authz.policy = Policy.from_dict(POLICY)  # notes-a loses its upstream grant
        caller = await _caller_token(world)
        outcome = await call_tool(
            SERVER_A,
            caller,
            "notes.search_upstream",
            {"query": "x"},
            http=world.router.http,
            url_policy=DEV_URLS,
        )
    assert outcome.startswith("tool error:")
    assert "upstream credential unavailable" in outcome
    assert "unauthorized_client" not in outcome


def test_upstream_tool_declares_a_scope() -> None:
    upstream = Upstream(
        resource=SERVER_B,
        scope="notes:read",
        trusted_issuers=[ISSUER],
        svid_source=LocalSvidIssuer().source_for(NOTES_A),
    )
    mcp, scopes = build_mcp("t", NotesStore(), upstream)
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert names == set(scopes)
    assert scopes["notes.search_upstream"] == "notes:read"


def test_server_never_reads_the_token_for_outbound_calls() -> None:
    """Static guard: the only outbound calls in mcp_server use Upstream.token()."""
    source = Path("src/mcp_svid_auth/mcp_server.py").read_text(encoding="utf-8")
    assert source.count("call_tool(") == 1
    assert "get_access_token().token" not in source
    assert ".access_token.token" not in source
