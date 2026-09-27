"""Tool calls are bounded by the caller's token expiry."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError
from starlette.types import Message, Receive, Scope, Send

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.mcp_server import (
    NotesStore,
    TokenExpiredError,
    ToolScopeGuard,
    build_mcp,
    require_live_token,
)
from tests.conftest import RESEARCH

pytestmark = pytest.mark.anyio

CALL = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "notes.write", "arguments": {"text": "x"}},
    }
).encode()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _user(expires_at: int) -> AuthenticatedUser:
    return AuthenticatedUser(
        AccessToken(
            token="t",
            client_id=RESEARCH,
            scopes=["notes:read", "notes:write"],
            expires_at=expires_at,
            subject=RESEARCH,
        )
    )


def _inner(delay: float, *, start_first: bool = False) -> Any:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        if start_first:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        await anyio.sleep(delay)
        if not start_first:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})

    return app


async def _run(
    tmp_path: Path, inner: Any, seconds_left: float
) -> tuple[list[Message], list[dict[str, Any]], float]:
    expires_at = 1_000_000
    audit_path = tmp_path / "audit.jsonl"
    guard = ToolScopeGuard(
        inner,
        {"notes.write": "notes:write"},
        "http://notes-a.test/.well-known/oauth-protected-resource/mcp",
        AuditLog(path=audit_path),
        clock=lambda: expires_at - seconds_left,
    )
    scope: Scope = {"type": "http", "method": "POST", "user": _user(expires_at), "headers": []}
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": CALL, "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    started = time.monotonic()
    await guard(scope, receive, send)
    elapsed = time.monotonic() - started
    lines = [json.loads(x) for x in audit_path.read_text(encoding="utf-8").splitlines()]
    return sent, lines, elapsed


async def test_call_finishing_before_expiry_passes(tmp_path: Path) -> None:
    sent, lines, _ = await _run(tmp_path, _inner(0), seconds_left=5)
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"done"
    assert [e["decision"] for e in lines] == ["allow"]


async def test_call_outliving_token_gets_401(tmp_path: Path) -> None:
    sent, lines, elapsed = await _run(tmp_path, _inner(5), seconds_left=0.1)
    assert elapsed < 2
    assert sent[0]["status"] == 401
    assert json.loads(sent[1]["body"]) == {
        "error": "invalid_token",
        "error_description": "access token expired during the call",
    }
    assert lines[-1]["decision"] == "deny"
    assert lines[-1]["reason"] == "token_expired_during_call"
    assert lines[-1]["tool"] == "notes.write"
    assert lines[-1]["spiffe_id"] == RESEARCH


async def test_token_already_expired_at_dispatch(tmp_path: Path) -> None:
    sent, lines, _ = await _run(tmp_path, _inner(5), seconds_left=-3)
    assert sent[0]["status"] == 401
    assert lines[-1]["reason"] == "token_expired_during_call"


async def test_started_response_is_cut_without_second_start(tmp_path: Path) -> None:
    sent, lines, _ = await _run(tmp_path, _inner(5, start_first=True), seconds_left=0.1)
    assert [m["type"] for m in sent] == ["http.response.start"]
    assert lines[-1]["reason"] == "token_expired_during_call"


def test_require_live_token() -> None:
    with pytest.raises(TokenExpiredError):
        require_live_token()
    for expires_at, ok in ((int(time.time()) + 60, True), (int(time.time()) - 1, False)):
        reset = auth_context_var.set(_user(expires_at))
        try:
            if ok:
                require_live_token()
            else:
                with pytest.raises(TokenExpiredError):
                    require_live_token()
        finally:
            auth_context_var.reset(reset)


async def test_write_refuses_after_expiry_without_side_effect() -> None:
    store = NotesStore()
    mcp, _ = build_mcp("t", store)
    reset = auth_context_var.set(_user(int(time.time()) - 1))
    try:
        with pytest.raises(ToolError, match="access token expired"):
            await mcp.call_tool("notes.write", {"text": "late"})
    finally:
        auth_context_var.reset(reset)
    assert store.notes == ["welcome to the notes server"]


async def test_write_with_live_token_stores() -> None:
    store = NotesStore()
    mcp, _ = build_mcp("t", store)
    reset = auth_context_var.set(_user(int(time.time()) + 60))
    try:
        await mcp.call_tool("notes.write", {"text": "on time"})
    finally:
        auth_context_var.reset(reset)
    assert store.notes[-1] == "on time"
