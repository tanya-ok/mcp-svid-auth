"""Notes MCP server over Streamable HTTP, protected by audience-bound access tokens.

The server:
- serves Protected Resource Metadata (RFC 9728),
- validates bearer tokens locally (signature via authz JWKS, iss, exp, aud == own URI),
- enforces a scope per tool and answers 403 insufficient_scope otherwise,
- writes one JSON audit line per decision,
- never forwards the incoming token.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx2
import jwt
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.mcpserver import MCPServer
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_svid_auth.audit import AuditLog

TOOL_SCOPES: dict[str, str] = {
    "notes.search": "notes:read",
    "notes.write": "notes:write",
}
_JWKS_CACHE_SECONDS = 60
_ACCESS_TOKEN_ALGS = ["ES256", "RS256"]


@dataclass
class JwksFetcher:
    """Fetches and caches the authorization server JWKS."""

    jwks_uri: str
    _cached: dict[str, Any] | None = None
    _at: float = 0.0

    def __call__(self) -> dict[str, Any]:
        if self._cached is None or time.monotonic() - self._at > _JWKS_CACHE_SECONDS:
            response = httpx2.get(self.jwks_uri, timeout=5)
            response.raise_for_status()
            self._cached = response.json()
            self._at = time.monotonic()
        return self._cached


@dataclass
class AudienceBoundVerifier:
    """TokenVerifier that accepts only tokens minted by `issuer` for `resource`."""

    issuer: str
    resource: str
    jwks: Callable[[], dict[str, Any]]
    audit: AuditLog

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            keys = jwt.PyJWKSet.from_dict(self.jwks()).keys
            key = next((k.key for k in keys if k.key_id == kid), None)
            if key is None:
                raise jwt.InvalidTokenError("unknown signing key")
            claims = jwt.decode(
                token,
                key,
                algorithms=_ACCESS_TOKEN_ALGS,
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["iss", "sub", "aud", "exp", "scope"]},
            )
        except jwt.PyJWTError as exc:
            self.audit.write(
                spiffe_id=_unverified_sub(token),
                tool=None,
                decision="deny",
                reason=f"invalid_token: {type(exc).__name__}: {exc}",
            )
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", claims["sub"])),
            scopes=str(claims["scope"]).split(),
            expires_at=int(claims["exp"]),
            resource=self.resource,
            subject=str(claims["sub"]),
            claims={"iss": claims["iss"]},
        )


def _unverified_sub(token: str) -> str | None:
    try:
        sub = jwt.decode(token, options={"verify_signature": False}).get("sub")
    except jwt.PyJWTError:
        return None
    return f"unverified:{sub}" if sub else None


class ToolScopeGuard:
    """Checks the scope for a tools/call before the MCP layer sees it."""

    def __init__(self, app: ASGIApp, resource_metadata_url: str, audit: AuditLog) -> None:
        self.app = app
        self.resource_metadata_url = resource_metadata_url
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        body = await _read_body(receive)
        user = scope.get("user")
        spiffe_id = user.access_token.subject if isinstance(user, AuthenticatedUser) else None
        granted = set(user.scopes) if isinstance(user, AuthenticatedUser) else set()
        for call in _tool_calls(body):
            required = TOOL_SCOPES.get(call)
            if required is None:
                continue  # unknown tool: let MCP answer with its own error
            if required not in granted:
                self.audit.write(
                    spiffe_id=spiffe_id,
                    tool=call,
                    decision="deny",
                    reason=f"insufficient_scope: needs {required}",
                )
                await _forbidden(send, required, self.resource_metadata_url)
                return
            self.audit.write(
                spiffe_id=spiffe_id, tool=call, decision="allow", reason=f"scope {required}"
            )
        await self.app(scope, _replay(body, receive), send)


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    sent = False

    async def inner() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return inner


def _tool_calls(body: bytes) -> list[str]:
    try:
        payload = json.loads(body)
    except ValueError:
        return []
    messages = payload if isinstance(payload, list) else [payload]
    names: list[str] = []
    for msg in messages:
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            params = msg.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            names.append(str(name))
    return names


async def _forbidden(send: Send, required: str, resource_metadata_url: str) -> None:
    body = json.dumps(
        {"error": "insufficient_scope", "error_description": f"Required scope: {required}"}
    ).encode()
    challenge = (
        f'Bearer error="insufficient_scope", scope="{required}", '
        f'resource_metadata="{resource_metadata_url}"'
    )
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", challenge.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


@dataclass
class NotesStore:
    notes: list[str] = field(default_factory=lambda: ["welcome to the notes server"])

    def search(self, query: str) -> list[str]:
        return [n for n in self.notes if query.lower() in n.lower()]

    def write(self, text: str) -> int:
        self.notes.append(text)
        return len(self.notes)


def build_mcp(name: str, store: NotesStore) -> MCPServer:
    mcp: MCPServer = MCPServer(name=name)

    @mcp.tool(name="notes.search", description="Search notes. Read only.")
    def search(query: str) -> list[str]:
        return store.search(query)

    @mcp.tool(name="notes.write", description="Append a note.")
    def write(text: str) -> str:
        return f"stored note #{store.write(text)}"

    return mcp


def create_app(  # noqa: PLR0913
    *,
    name: str,
    resource: str,
    issuer: str,
    jwks: Callable[[], dict[str, Any]],
    audit: AuditLog,
    store: NotesStore | None = None,
    allowed_hosts: list[str] | None = None,
) -> Starlette:
    resource = resource.rstrip("/")
    mcp = build_mcp(name, store or NotesStore())
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=allowed_hosts is not None,
        allowed_hosts=allowed_hosts or [],
    )
    manager = StreamableHTTPSessionManager(
        app=mcp._lowlevel_server,
        json_response=True,
        stateless=True,
        security_settings=security,
    )
    resource_url = AnyHttpUrl(resource)
    metadata_url = str(build_resource_metadata_url(resource_url))
    verifier = AudienceBoundVerifier(issuer=issuer, resource=resource, jwks=jwks, audit=audit)
    guarded = ToolScopeGuard(StreamableHTTPASGIApp(manager), metadata_url, audit)
    endpoint = RequireAuthMiddleware(guarded, [], AnyHttpUrl(metadata_url))
    path = urlsplit(resource).path or "/"

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    prm = {
        # Exact strings: issuer comparison is simple string comparison (RFC 8414, RFC 9207).
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": sorted(set(TOOL_SCOPES.values())),
        "bearer_methods_supported": ["header"],
    }

    async def protected_resource_metadata(_: Request) -> Response:
        return JSONResponse(prm)

    prm_path = urlsplit(metadata_url).path
    routes: list[Any] = [
        Route(path, endpoint=endpoint),
        Route(prm_path, endpoint=protected_resource_metadata, methods=["GET"]),
    ]
    return Starlette(
        routes=routes,
        middleware=[
            Middleware(
                AuthenticationMiddleware,
                backend=BearerAuthBackend(verifier, resource_server_url=resource_url),
            ),
            Middleware(AuthContextMiddleware),
        ],
        lifespan=lifespan,
    )


def main(argv: list[str] | None = None) -> None:
    import uvicorn  # noqa: PLC0415

    parser = argparse.ArgumentParser(description="Notes MCP server (POC)")
    parser.add_argument("--name", default="notes")
    parser.add_argument(
        "--resource", required=True, help="canonical URI, e.g. http://host:8101/mcp"
    )
    parser.add_argument("--issuer", required=True, help="authorization server issuer URL")
    parser.add_argument("--jwks-uri", help="default: <issuer>/jwks.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8101)
    parser.add_argument("--audit-log", type=Path)
    args = parser.parse_args(argv)
    issuer = args.issuer.rstrip("/")
    app = create_app(
        name=args.name,
        resource=args.resource,
        issuer=issuer,
        jwks=JwksFetcher(args.jwks_uri or f"{issuer}/jwks.json"),
        audit=AuditLog(path=args.audit_log, component=f"mcp_server:{args.name}"),
    )
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
