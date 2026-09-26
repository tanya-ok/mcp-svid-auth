"""Resource server checks: token shape, deny-by-default guard, body limits."""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_svid_auth.agent_client import call_tool
from mcp_svid_auth.mcp_server import MAX_BODY_BYTES, NotesStore, build_mcp
from tests.conftest import ISSUER, RESEARCH, SERVER_A

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _mint(world: Any, headers: dict[str, Any] | None = None, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": RESEARCH,
        "aud": SERVER_A,
        "scope": "notes:read notes:write",
        "iat": now,
        "exp": now + 60,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    hdrs: dict[str, Any] = {"kid": world.authz.kid, "typ": "at+jwt"}
    hdrs.update(headers or {})
    return jwt.encode(claims, world.authz.signing_key, algorithm="ES256", headers=hdrs)


async def _denied_reason(world: Any, token: str) -> str:
    outcome = await call_tool(SERVER_A, token, "notes.search", {"query": "x"}, http=world.http)
    assert outcome.startswith("HTTP 401")
    reason: str = world.audit_lines()[0]["reason"]
    return reason


async def _raw_post(world: Any, content: bytes, token: str) -> Any:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }
    async with world.http() as client:
        return await client.post(SERVER_A, content=content, headers=headers)


async def test_minted_token_is_accepted(world_factory: Any) -> None:
    async with world_factory() as world:
        outcome = await call_tool(
            SERVER_A, _mint(world), "notes.search", {"query": "welcome"}, http=world.http
        )
    assert "welcome" in outcome


async def test_expired_access_token_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        now = int(time.time())
        reason = await _denied_reason(world, _mint(world, iat=now - 600, exp=now - 300))
    assert "ExpiredSignatureError" in reason


async def test_token_from_other_issuer_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        reason = await _denied_reason(world, _mint(world, iss="http://evil.test"))
    assert "InvalidIssuerError" in reason


async def test_access_token_without_at_jwt_typ_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        reason = await _denied_reason(world, _mint(world, headers={"typ": "JWT"}))
    assert "typ must be at+jwt" in reason


async def test_access_token_without_iat_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        reason = await _denied_reason(world, _mint(world, iat=None))
    assert "iat" in reason


async def test_access_token_algorithm_pinned_to_es256(world_factory: Any) -> None:
    async with world_factory() as world:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": RESEARCH,
            "aud": SERVER_A,
            "scope": "notes:read",
            "iat": now,
            "exp": now + 60,
        }
        token = jwt.encode(
            claims, rsa_key, algorithm="RS256", headers={"kid": world.authz.kid, "typ": "at+jwt"}
        )
        reason = await _denied_reason(world, token)
    assert "InvalidAlgorithmError" in reason


async def test_unknown_tool_denied(world_factory: Any) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "notes.delete", "arguments": {}},
    }
    async with world_factory() as world:
        response = await _raw_post(world, json.dumps(body).encode(), _mint(world))
    assert response.status_code == 400
    assert response.json()["error_description"] == "unknown tool"
    line = world.audit_lines()[0]
    assert (line["tool"], line["decision"], line["reason"]) == (
        "notes.delete",
        "deny",
        "unknown tool",
    )


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[1, 2]", b'{"method": "tools/call", "params": {"name": 7}}'],
)
async def test_unparseable_body_rejected(world_factory: Any, content: bytes) -> None:
    async with world_factory() as world:
        response = await _raw_post(world, content, _mint(world))
    assert response.status_code == 400
    assert world.audit_lines()[0]["reason"] == "unparseable request body"


async def test_oversized_body_rejected(world_factory: Any) -> None:
    async with world_factory() as world:
        response = await _raw_post(world, b" " * (MAX_BODY_BYTES + 1), _mint(world))
    assert response.status_code == 413
    assert world.audit_lines()[0]["reason"] == "request body too large"


def test_every_registered_tool_declares_a_scope() -> None:
    mcp, scopes = build_mcp("t", NotesStore())
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert names == set(scopes) == {"notes.search", "notes.write"}
