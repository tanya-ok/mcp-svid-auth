"""A cached upstream token that the upstream rejects is replaced once, never in a loop."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_svid_auth import mcp_server
from mcp_svid_auth.mcp_server import Upstream

pytestmark = pytest.mark.anyio

REJECTED = 'HTTP 401: Bearer error="invalid_token", resource_metadata="https://b/x"'
FORBIDDEN = 'HTTP 403: Bearer error="insufficient_scope"'


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Recorder:
    def __init__(self, outcomes: dict[str, str]) -> None:
        self.outcomes = outcomes
        self.fetches = 0
        self.calls: list[str] = []

    async def fetch(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.fetches += 1
        return {"access_token": f"token-{self.fetches}", "expires_in": 300}

    async def call(self, resource: str, token: str, *args: Any, **kwargs: Any) -> str:
        self.calls.append(token)
        return self.outcomes.get(token, "welcome")


def upstream(monkeypatch: pytest.MonkeyPatch, recorder: Recorder) -> Upstream:
    monkeypatch.setattr(mcp_server, "fetch_access_token", recorder.fetch)
    monkeypatch.setattr(mcp_server, "call_tool", recorder.call)
    return Upstream(
        resource="https://b/mcp",
        scope="notes:read",
        trusted_issuers=["https://a"],
        svid_source=None,  # type: ignore[arg-type]
    )


async def test_cached_token_rejected_by_the_upstream_is_replaced_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = Recorder({"token-1": REJECTED})
    server = upstream(monkeypatch, recorder)
    assert await server.token() == "token-1"
    assert await server.search("welcome") == "welcome"
    assert recorder.calls == ["token-1", "token-2"]
    assert recorder.fetches == 2
    assert await server.search("welcome") == "welcome"
    assert recorder.fetches == 2


async def test_a_rejected_replacement_is_not_retried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = Recorder({"token-1": REJECTED, "token-2": REJECTED, "token-3": REJECTED})
    server = upstream(monkeypatch, recorder)
    assert await server.search("welcome") == REJECTED
    assert recorder.fetches == 2
    assert len(recorder.calls) == 2


async def test_insufficient_scope_is_returned_without_a_new_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = Recorder({"token-1": FORBIDDEN})
    server = upstream(monkeypatch, recorder)
    assert await server.search("welcome") == FORBIDDEN
    assert recorder.fetches == 1
    assert recorder.calls == ["token-1"]
