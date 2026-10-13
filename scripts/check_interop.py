"""Exercise an independent TypeScript MCP SDK against real local HTTP endpoints."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import uvicorn
from starlette.types import Receive, Scope, Send

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer

ROOT = Path(__file__).resolve().parent.parent
IDENTITY = "spiffe://example.org/agent/research"


async def check() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        issuer = f"http://127.0.0.1:{listener.getsockname()[1]}"
        resource = issuer + "/mcp"
        source = LocalSvidIssuer()
        authz = AuthzServer(
            issuer=issuer,
            resolver=source.resolver(),
            policy=Policy.from_dict(
                {
                    "trust_domain": "example.org",
                    "clients": [
                        {
                            "spiffe_id": IDENTITY,
                            "resources": {resource: ["notes:read", "notes:write"]},
                        }
                    ],
                }
            ),
        )
        audit = AuditLog()
        notes = create_app(
            name="interop", resource=resource, issuer=issuer, jwks=authz.jwks, audit=audit
        )
        authorization = authz.app()

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            target = (
                authorization
                if scope.get("path")
                in ("/token", "/jwks.json", "/.well-known/oauth-authorization-server")
                else notes
            )
            await target(scope, receive, send)

        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        running = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            for _ in range(100):
                if server.started:
                    break
                await asyncio.sleep(0.05)
            if not server.started:
                raise RuntimeError("local server did not start")
            process = await asyncio.create_subprocess_exec(
                "node",
                str(ROOT / "examples/typescript-client/client.mjs"),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            fixture: dict[str, Any] = {
                "resource": resource,
                "issuer": issuer,
                "assertion": source.mint(IDENTITY, issuer),
                "scope": "notes:read",
                "allowLocalDemo": True,
            }
            try:
                output, _ = await asyncio.wait_for(
                    process.communicate(json.dumps(fixture).encode()), 30
                )
            except TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError("independent client timed out") from None
            try:
                result = json.loads(output)
            except ValueError:
                raise RuntimeError("independent client produced no safe result") from None
            if process.returncode != 0 or result != {
                "event": "interop",
                "passed": True,
                "tools": ["notes.search"],
                "read": True,
                "writeDenied": True,
            }:
                raise RuntimeError("independent client failed")
            print(
                "PASS: TypeScript SDK 1.32.1 discovery, JWT-SVID adapter, "
                "MCP initialize, listTools, allowed read, denied write"
            )
        finally:
            server.should_exit = True
            await running


if __name__ == "__main__":
    asyncio.run(check())
