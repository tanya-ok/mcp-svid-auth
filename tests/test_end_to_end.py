"""Full path through real HTTP handling: discovery, token, MCP tool calls, audit."""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest

from mcp_svid_auth.agent_client import TokenRequestError, call_tool, fetch_access_token
from tests.conftest import INTRUDER, ISSUER, READER, RESEARCH, SERVER_A, SERVER_B

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_valid_flow_calls_both_tools(world_factory: Any) -> None:
    async with world_factory() as world:
        source = world.spire.source_for(RESEARCH)
        token = await fetch_access_token(SERVER_A, source, spiffe_id=RESEARCH, http=world.http)
        found = await call_tool(
            SERVER_A, token["access_token"], "notes.search", {"query": "welcome"}, http=world.http
        )
        wrote = await call_tool(
            SERVER_A, token["access_token"], "notes.write", {"text": "hi"}, http=world.http
        )
    assert "welcome to the notes server" in found
    assert wrote == "stored note #2"
    decisions = [(e["tool"], e["decision"]) for e in world.audit_lines()]
    assert decisions == [("notes.search", "allow"), ("notes.write", "allow")]
    assert all(e["spiffe_id"] == RESEARCH for e in world.audit_lines())


async def test_intruder_gets_no_token(world_factory: Any) -> None:
    async with world_factory() as world:
        with pytest.raises(TokenRequestError, match="unauthorized_client"):
            await fetch_access_token(SERVER_A, world.spire.source_for(INTRUDER), http=world.http)


async def test_token_for_a_is_rejected_by_b(world_factory: Any) -> None:
    async with world_factory() as world:
        token = await fetch_access_token(
            SERVER_A, world.spire.source_for(RESEARCH), http=world.http
        )
        outcome = await call_tool(
            SERVER_B, token["access_token"], "notes.search", {"query": "welcome"}, http=world.http
        )
    assert outcome.startswith("HTTP 401")
    assert 'error="invalid_token"' in outcome
    deny = [e for e in world.audit_lines() if e["decision"] == "deny"]
    assert deny
    assert "InvalidAudienceError" in deny[0]["reason"]
    assert deny[0]["spiffe_id"] == f"unverified:{RESEARCH}"


async def test_scope_enforced_per_tool(world_factory: Any) -> None:
    async with world_factory() as world:
        token = await fetch_access_token(SERVER_A, world.spire.source_for(READER), http=world.http)
        read = await call_tool(
            SERVER_A, token["access_token"], "notes.search", {"query": "welcome"}, http=world.http
        )
        write = await call_tool(
            SERVER_A, token["access_token"], "notes.write", {"text": "nope"}, http=world.http
        )
    assert "welcome" in read
    assert write.startswith("HTTP 403")
    assert 'error="insufficient_scope"' in write
    assert 'scope="notes:write"' in write
    assert "resource_metadata=" in write
    lines = world.audit_lines()
    assert [(e["tool"], e["decision"]) for e in lines] == [
        ("notes.search", "allow"),
        ("notes.write", "deny"),
    ]
    assert lines[1]["reason"] == "insufficient_scope: needs notes:write"
    assert set(lines[1]) == {"timestamp", "component", "spiffe_id", "tool", "decision", "reason"}


async def test_expired_access_token_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": RESEARCH,
            "aud": SERVER_A,
            "scope": "notes:read",
            "iat": now - 600,
            "exp": now - 300,
        }
        stale = jwt.encode(
            claims, world.authz.signing_key, algorithm="ES256", headers={"kid": world.authz.kid}
        )
        outcome = await call_tool(SERVER_A, stale, "notes.search", {"query": "x"}, http=world.http)
    assert outcome.startswith("HTTP 401")
    assert "ExpiredSignatureError" in world.audit_lines()[0]["reason"]


async def test_token_from_other_issuer_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        now = int(time.time())
        claims = {
            "iss": "http://evil.test",
            "sub": RESEARCH,
            "aud": SERVER_A,
            "scope": "notes:read",
            "exp": now + 60,
        }
        forged = jwt.encode(
            claims, world.authz.signing_key, algorithm="ES256", headers={"kid": world.authz.kid}
        )
        outcome = await call_tool(SERVER_A, forged, "notes.search", {"query": "x"}, http=world.http)
    assert outcome.startswith("HTTP 401")
    assert "InvalidIssuerError" in world.audit_lines()[0]["reason"]


async def test_protected_resource_metadata(world_factory: Any) -> None:
    async with world_factory() as world, world.http() as client:
        response = await client.get("http://notes-a.test/.well-known/oauth-protected-resource/mcp")
    assert response.json() == {
        "resource": SERVER_A,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["notes:read", "notes:write"],
        "bearer_methods_supported": ["header"],
    }


async def test_missing_token_gets_challenge(world_factory: Any) -> None:
    async with world_factory() as world, world.http() as client:
        response = await client.post(SERVER_A, json={"jsonrpc": "2.0", "id": 1, "method": "x"})
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]
