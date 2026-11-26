"""The agent can fetch one token per call for servers that allow one call per token."""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

from mcp_svid_auth import agent_client
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.revocation import TokenUseCounter
from tests.conftest import ISSUER, RESEARCH, SERVER_A, HostRouter

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize(("per_call", "second"), [(False, "HTTP 401"), (True, "stored note")])
async def test_single_call_tokens(
    world_factory: Any, capsys: pytest.CaptureFixture[str], per_call: bool, second: str
) -> None:
    async with world_factory() as world:
        app = create_app(
            name="single",
            resource=SERVER_A,
            issuer=ISSUER,
            jwks=world.authz.jwks,
            audit=AuditLog(path=world.audit_path.with_name("single.jsonl")),
            token_uses=TokenUseCounter(1),
        )
        router = HostRouter({"authz.test": world.authz.app(), "notes-a.test": app})

        def http(**kwargs: Any) -> httpx2.AsyncClient:
            return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=router), **kwargs)

        flags = ["--resource", SERVER_A, "--scope", "notes:read notes:write"]
        flags += ["--trusted-issuer", ISSUER, "--allow-http", "--allow-private-network"]
        if per_call:
            flags.append("--token-per-call")
        args = agent_client.build_parser().parse_args(flags)
        async with app.router.lifespan_context(app):
            code = await agent_client.run(args, world.spire.source_for(RESEARCH), http)
    assert code == 0
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    calls = [e["result"] for e in events if e["event"] == "call"]
    assert "welcome" in calls[0]
    assert calls[1].startswith(second)
    assert len([e for e in events if e["event"] == "token"]) == (2 if per_call else 1)
