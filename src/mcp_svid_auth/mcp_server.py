"""Notes MCP server over Streamable HTTP, protected by audience-bound access tokens.

The server:
- serves Protected Resource Metadata (RFC 9728),
- validates bearer tokens locally (signature via authz JWKS, iss, exp, aud == own URI),
- enforces a scope per tool and answers 403 insufficient_scope otherwise,
- lists in tools/list only the tools the token's scopes allow,
- denies tools/call for any tool without a declared scope, and unparseable bodies,
- writes one JSON audit line per decision,
- stops waiting for a tool call once the caller's token expires, and re-checks expiry
  before a tool changes state,
- never forwards the incoming token.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import anyio
import httpx2
import jwt
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import build_resource_metadata_url
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ListToolsResult, PaginatedRequestParams
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_svid_auth.audit import AuditLog

JWKS_CACHE_SECONDS = 60
JWKS_MIN_REFETCH_SECONDS = 10
_ACCESS_TOKEN_ALGS = ["ES256"]
_ACCESS_TOKEN_TYP = "at+jwt"  # noqa: S105 - media type, not a secret
MAX_BODY_BYTES = 1024 * 1024


class JwksUnavailableError(Exception):
    """The authorization server JWKS could not be fetched."""


class JwksSource(Protocol):
    """Async key set. `refresh=True` asks for a fresh copy (unknown `kid`); it may be refused."""

    async def get(self, *, refresh: bool = False) -> dict[str, Any]: ...


@dataclass
class StaticJwks:
    """Wraps a local key set callable, for tests and in-process use."""

    source: Callable[[], dict[str, Any]]

    async def get(self, *, refresh: bool = False) -> dict[str, Any]:
        return self.source()


@dataclass
class JwksFetcher:
    """Fetches and caches the authorization server JWKS without blocking the event loop.

    The URI is fixed at startup and never taken from a token. The cache expires after
    `JWKS_CACHE_SECONDS`. A refresh on unknown `kid` happens at most once per
    `JWKS_MIN_REFETCH_SECONDS`, so tokens with random `kid` values cannot cause a fetch storm.
    """

    jwks_uri: str
    transport: httpx2.AsyncBaseTransport | None = None
    clock: Callable[[], float] = time.monotonic
    _cached: dict[str, Any] | None = None
    _fetched_at: float = 0.0
    _attempted_at: float | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def get(self, *, refresh: bool = False) -> dict[str, Any]:
        async with self._lock:
            if self._cached is None or self.clock() - self._fetched_at > JWKS_CACHE_SECONDS:
                return await self._fetch()
            if refresh and self._may_refetch():
                return await self._fetch()
            return self._cached

    def _may_refetch(self) -> bool:
        return (
            self._attempted_at is None
            or self.clock() - self._attempted_at >= JWKS_MIN_REFETCH_SECONDS
        )

    async def _fetch(self) -> dict[str, Any]:
        self._attempted_at = self.clock()
        try:
            async with httpx2.AsyncClient(
                transport=self.transport, timeout=5, follow_redirects=False
            ) as client:
                response = await client.get(self.jwks_uri)
                response.raise_for_status()
                jwks = response.json()
        except (httpx2.HTTPError, ValueError) as exc:
            raise JwksUnavailableError(type(exc).__name__) from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise JwksUnavailableError("not a JWKS")
        self._cached = jwks
        self._fetched_at = self._attempted_at
        return jwks


@dataclass
class AudienceBoundVerifier:
    """TokenVerifier that accepts only tokens minted by `issuer` for `resource`."""

    issuer: str
    resource: str
    jwks: JwksSource
    audit: AuditLog

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("typ") != _ACCESS_TOKEN_TYP:
                raise jwt.InvalidTokenError(f"typ must be {_ACCESS_TOKEN_TYP}")
            kid = header.get("kid")
            key = _find_key(await self.jwks.get(), kid)
            if key is None:
                key = _find_key(await self.jwks.get(refresh=True), kid)
            if key is None:
                raise jwt.InvalidTokenError("unknown signing key")
            claims = jwt.decode(
                token,
                key,
                algorithms=_ACCESS_TOKEN_ALGS,
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "scope"]},
            )
        except jwt.PyJWTError as exc:
            self.audit.write(
                spiffe_id=_unverified_sub(token),
                tool=None,
                decision="deny",
                reason=f"invalid_token: {type(exc).__name__}: {exc}",
            )
            return None
        except JwksUnavailableError as exc:
            self.audit.write(
                spiffe_id=_unverified_sub(token),
                tool=None,
                decision="deny",
                reason=f"jwks_unavailable: {exc}",
            )
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", claims["sub"])),
            scopes=str(claims["scope"]).split(" "),
            expires_at=int(claims["exp"]),
            resource=self.resource,
            subject=str(claims["sub"]),
            claims={"iss": claims["iss"]},
        )


def _find_key(jwks: dict[str, Any], kid: object) -> Any:
    keys = jwt.PyJWKSet.from_dict(jwks).keys
    return next((k.key for k in keys if k.key_id == kid), None)


def _unverified_sub(token: str) -> str | None:
    try:
        sub = jwt.decode(token, options={"verify_signature": False}).get("sub")
    except jwt.PyJWTError:
        return None
    return f"unverified:{sub}" if sub else None


class ToolScopeGuard:
    """Checks the scope for a tools/call before the MCP layer sees it. Deny by default."""

    def __init__(
        self,
        app: ASGIApp,
        tool_scopes: dict[str, str],
        resource_metadata_url: str,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.app = app
        self.tool_scopes = tool_scopes
        self.resource_metadata_url = resource_metadata_url
        self.audit = audit
        self.clock = clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        user = scope.get("user")
        spiffe_id = user.access_token.subject if isinstance(user, AuthenticatedUser) else None
        granted = set(user.scopes) if isinstance(user, AuthenticatedUser) else set()
        body = await _read_body(receive, MAX_BODY_BYTES)
        if body is None:
            self.audit.write(
                spiffe_id=spiffe_id, tool=None, decision="deny", reason="request body too large"
            )
            await _error(send, 413, "invalid_request", "request body too large")
            return
        calls = _tool_calls(body)
        if calls is None:
            self.audit.write(
                spiffe_id=spiffe_id, tool=None, decision="deny", reason="unparseable request body"
            )
            await _error(send, 400, "invalid_request", "request body is not valid JSON-RPC")
            return
        for call in calls:
            required = self.tool_scopes.get(call)
            if required is None:
                self.audit.write(
                    spiffe_id=spiffe_id, tool=call, decision="deny", reason="unknown tool"
                )
                await _error(send, 400, "invalid_request", "unknown tool")
                return
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
        expires_at = user.access_token.expires_at if isinstance(user, AuthenticatedUser) else None
        if not calls or expires_at is None:
            await self.app(scope, _replay(body, receive), send)
            return
        await self._until_expiry(
            scope,
            _replay(body, receive),
            send,
            expires_at=expires_at,
            spiffe_id=spiffe_id,
            calls=calls,
        )

    async def _until_expiry(  # noqa: PLR0913
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        expires_at: int,
        spiffe_id: str | None,
        calls: list[str],
    ) -> None:
        """Run a tools/call request, but stop waiting for it once the token expires.

        The response is abandoned, not the work: a sync tool keeps running on its worker
        thread, so tools that change state re-check expiry themselves (`require_live_token`).
        """
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            with anyio.fail_after(max(0.0, expires_at - self.clock())):
                await self.app(scope, receive, tracking_send)
        except TimeoutError:
            self.audit.write(
                spiffe_id=spiffe_id,
                tool=",".join(calls),
                decision="deny",
                reason="token_expired_during_call",
            )
            if not started:
                await _error(send, 401, "invalid_token", "access token expired during the call")


class AuditedRequireAuth:
    """RequireAuthMiddleware plus an audit line for requests that carry no bearer token.

    Invalid tokens are audited by the verifier, so only the missing-token case is logged here.
    """

    def __init__(self, app: ASGIApp, resource_metadata_url: str, audit: AuditLog) -> None:
        self.inner = RequireAuthMiddleware(app, [], AnyHttpUrl(resource_metadata_url))
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not isinstance(scope.get("user"), AuthenticatedUser):
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"")
            if not auth.lower().startswith(b"bearer "):
                self.audit.write(spiffe_id=None, tool=None, decision="deny", reason="missing_token")
        await self.inner(scope, receive, send)


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    """Read the full request body, or return None once it exceeds `limit` bytes."""
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
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


def _tool_calls(body: bytes) -> list[str] | None:
    """Tool names in a JSON-RPC message or batch. None when the body cannot be trusted."""
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    messages = payload if isinstance(payload, list) else [payload]
    names: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            return None
        if msg.get("method") == "tools/call":
            params = msg.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            if not isinstance(name, str):
                return None
            names.append(name)
    return names


async def _error(send: Send, status: int, error: str, description: str) -> None:
    body = json.dumps({"error": error, "error_description": description}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


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


class TokenExpiredError(ToolError):
    """The caller's access token expired before the tool reached its side effect."""


def require_live_token(clock: Callable[[], float] = time.time) -> None:
    """Raise unless the current request carries an access token that has not expired."""
    token = get_access_token()
    if token is None or token.expires_at is None or token.expires_at <= clock():
        raise TokenExpiredError("access token expired")


@dataclass
class NotesStore:
    notes: list[str] = field(default_factory=lambda: ["welcome to the notes server"])

    def search(self, query: str) -> list[str]:
        return [n for n in self.notes if query.lower() in n.lower()]

    def write(self, text: str) -> int:
        self.notes.append(text)
        return len(self.notes)


class ScopedToolsServer(MCPServer):
    """MCPServer whose tools/list shows only the tools the caller's token may call.

    Deny by default: no token, or a tool without a declared scope, lists nothing.
    """

    def __init__(self, name: str) -> None:
        super().__init__(name=name)
        self.tool_scopes: dict[str, str] = {}

    async def _handle_list_tools(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        access_token = get_access_token()
        granted = set(access_token.scopes) if access_token else set()
        tools = [t for t in await self.list_tools() if self.tool_scopes.get(t.name) in granted]
        return ListToolsResult(tools=tools)


def build_mcp(name: str, store: NotesStore) -> tuple[MCPServer, dict[str, str]]:
    """Register tools together with the scope each one needs."""
    mcp = ScopedToolsServer(name=name)
    scopes = mcp.tool_scopes

    def tool(tool_name: str, scope: str, description: str) -> Callable[[Any], Any]:
        scopes[tool_name] = scope
        return mcp.tool(name=tool_name, description=description)

    @tool("notes.search", "notes:read", "Search notes. Read only.")
    def search(query: str) -> list[str]:
        return store.search(query)

    @tool("notes.write", "notes:write", "Append a note.")
    def write(text: str) -> str:
        require_live_token()
        return f"stored note #{store.write(text)}"

    registered = {t.name for t in mcp._tool_manager.list_tools()}
    if registered != set(scopes):
        raise RuntimeError(f"tools without a declared scope: {registered - set(scopes)}")
    return mcp, scopes


def create_app(  # noqa: PLR0913
    *,
    name: str,
    resource: str,
    issuer: str,
    jwks: JwksSource | Callable[[], dict[str, Any]],
    audit: AuditLog,
    store: NotesStore | None = None,
    allowed_hosts: list[str] | None = None,
) -> Starlette:
    resource = resource.rstrip("/")
    mcp, tool_scopes = build_mcp(name, store or NotesStore())
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
    source = StaticJwks(jwks) if callable(jwks) else jwks
    verifier = AudienceBoundVerifier(issuer=issuer, resource=resource, jwks=source, audit=audit)
    guarded = ToolScopeGuard(StreamableHTTPASGIApp(manager), tool_scopes, metadata_url, audit)
    endpoint = AuditedRequireAuth(guarded, metadata_url, audit)
    path = urlsplit(resource).path or "/"

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    prm = {
        # Exact strings: issuer comparison is simple string comparison (RFC 8414, RFC 9207).
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": sorted(set(tool_scopes.values())),
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-svid-notes", description="Notes MCP server (POC)")
    parser.add_argument(
        "--name",
        default="notes",
        help="server name, also used in the audit component (mcp_server:<name>)",
    )
    parser.add_argument(
        "--resource",
        required=True,
        help="canonical URI, e.g. http://host:8101/mcp; must equal the token aud",
    )
    parser.add_argument("--issuer", required=True, help="authorization server issuer URL")
    parser.add_argument("--jwks-uri", help="JWKS location, default <issuer>/jwks.json")
    parser.add_argument("--host", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=8101, help="listen port")
    parser.add_argument(
        "--audit-log", type=Path, help="audit log file (JSON lines, appended), default stderr"
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    import uvicorn  # noqa: PLC0415

    args = build_parser().parse_args(argv)
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
