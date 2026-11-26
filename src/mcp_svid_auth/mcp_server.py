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
- never forwards the incoming token. With --upstream-resource it calls one upstream MCP server
  with its own SVID-based token (tool notes.search_upstream).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import ssl
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
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_svid_auth.agent_client import (
    STRICT_URLS,
    HttpFactory,
    TokenRequestError,
    UrlPolicy,
    add_url_flags,
    call_tool,
    default_http,
    fetch_access_token,
    issuer_arg,
    url_policy_from_args,
)
from mcp_svid_auth.audit import AuditLog, default_replica_id
from mcp_svid_auth.budgets import WindowBudget
from mcp_svid_auth.dpop import DPOP_ALG, DPoPError, ProofReplayStore, verify_proof
from mcp_svid_auth.metrics import CONTENT_TYPE as METRICS_CONTENT_TYPE
from mcp_svid_auth.metrics import Metrics, succeeds
from mcp_svid_auth.revocation import (
    DEFAULT_REVOCATION_POLL_SECONDS,
    DEFAULT_TOKEN_USE_CACHE_SIZE,
    RevocationList,
    TokenUseCounter,
    TokenUseError,
    load_revocation_key,
    poll_seconds_arg,
)
from mcp_svid_auth.spiffe_keys import SvidSource, WorkloadApiSvidSource
from mcp_svid_auth.state import (
    SharedState,
    StateUnavailableError,
    add_state_flags,
    state_from_args,
)
from mcp_svid_auth.tls import add_tls_server_flags, client_context, tls_server_kwargs

JWKS_CACHE_SECONDS = 60
JWKS_MIN_REFETCH_SECONDS = 10
# Access token lifetime plus clock skew: the longest a token signed under a cached key lives.
JWKS_STALE_SECONDS = 330
_ACCESS_TOKEN_ALGS = ["ES256"]
_ACCESS_TOKEN_TYP = "at+jwt"  # noqa: S105 - media type, not a secret
MAX_BODY_BYTES = 1024 * 1024
MAX_ACCESS_TOKEN_BYTES = 8192
MAX_JWKS_BYTES = 65_536
MAX_JWKS_KEYS = 16
DEFAULT_TOKEN_VERIFICATIONS_PER_SECOND = 256
HEALTH_PATHS = ("/healthz", "/readyz", "/metrics")


class JwksUnavailableError(Exception):
    """The authorization server JWKS could not be fetched."""


class JwksInvalidError(Exception):
    """The authorization server JWKS has no usable keys or a malformed key."""


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
    verify: ssl.SSLContext | bool = True
    _cached: dict[str, Any] | None = None
    _fetched_at: float = 0.0
    _attempted_at: float | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    degraded: bool = False

    async def get(self, *, refresh: bool = False) -> dict[str, Any]:
        async with self._lock:
            if self._cached is None or self.clock() - self._fetched_at > JWKS_CACHE_SECONDS:
                if not self._may_refetch():
                    return self._stale(JwksUnavailableError("JWKS retry budget exceeded"))
                try:
                    return await self._fetch()
                except JwksUnavailableError as exc:
                    return self._stale(exc)
            if refresh and self._may_refetch():
                with contextlib.suppress(JwksUnavailableError):
                    return await self._fetch()
            return self._cached

    def _stale(self, error: JwksUnavailableError) -> dict[str, Any]:
        """Serve the last good set while tokens signed under it can still be valid."""
        if self._cached is None or self.clock() - self._fetched_at > (
            JWKS_CACHE_SECONDS + JWKS_STALE_SECONDS
        ):
            self.degraded = False
            raise error
        self.degraded = True
        return self._cached

    def _may_refetch(self) -> bool:
        return (
            self._attempted_at is None
            or self.clock() - self._attempted_at >= JWKS_MIN_REFETCH_SECONDS
        )

    async def _fetch(self) -> dict[str, Any]:
        self._attempted_at = self.clock()
        try:
            async with (
                httpx2.AsyncClient(
                    transport=self.transport,
                    timeout=5,
                    follow_redirects=False,
                    trust_env=False,
                    verify=self.verify,
                ) as client,
                client.stream("GET", self.jwks_uri) as response,
            ):
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > MAX_JWKS_BYTES:
                        raise JwksUnavailableError("JWKS response too large")
                    content.extend(chunk)
                jwks = json.loads(content)
        except (httpx2.HTTPError, ValueError) as exc:
            raise JwksUnavailableError(type(exc).__name__) from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise JwksUnavailableError("not a JWKS")
        if len(jwks["keys"]) > MAX_JWKS_KEYS:
            raise JwksUnavailableError("too many JWKS keys")
        self._cached = jwks
        self._fetched_at = self._attempted_at
        self.degraded = False
        return jwks


@dataclass
class AudienceBoundVerifier:
    """TokenVerifier that accepts only tokens minted by `issuer` for `resource`."""

    issuer: str
    resource: str
    jwks: JwksSource
    audit: AuditLog

    budget: WindowBudget = field(
        default_factory=lambda: WindowBudget(DEFAULT_TOKEN_VERIFICATIONS_PER_SECOND, max_keys=1)
    )
    revocation: RevocationList | None = None
    require_jti: bool = False

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self._verify(token, bound=False)

    async def verify_bound_token(self, token: str) -> AccessToken | None:
        return await self._verify(token, bound=True)

    async def _verify(self, token: str, *, bound: bool) -> AccessToken | None:
        if not self.budget.take():
            self.audit.write(
                spiffe_id=None, tool=None, decision="deny", reason="verification_budget_exceeded"
            )
            return None
        if len(token) > MAX_ACCESS_TOKEN_BYTES or not token.isascii():
            self.audit.write(
                spiffe_id=None, tool=None, decision="deny", reason="invalid_token_size_or_encoding"
            )
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in _ACCESS_TOKEN_ALGS:
                raise jwt.InvalidAlgorithmError("unsupported access token algorithm")
            if header.get("typ") != _ACCESS_TOKEN_TYP:
                raise jwt.InvalidTokenError(f"typ must be {_ACCESS_TOKEN_TYP}")
            kid = header.get("kid")
            if not isinstance(kid, str) or not 0 < len(kid) <= 128:
                raise jwt.InvalidTokenError("invalid key identifier")
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
            if claims["aud"] not in (self.resource, [self.resource]):
                raise jwt.InvalidAudienceError("audience must name this resource only")
            jkt = _check_binding(claims, bound=bound)
            self._check_jti(claims)
        except jwt.PyJWTError as exc:
            self.audit.write(
                spiffe_id=_unverified_sub(token),
                tool=None,
                decision="deny",
                reason=f"invalid_token: {type(exc).__name__}",
            )
            return None
        except (JwksUnavailableError, JwksInvalidError, _RevokedError) as exc:
            reason = (
                str(exc)
                if isinstance(exc, _RevokedError)
                else "jwks_unavailable"
                if isinstance(exc, JwksUnavailableError)
                else "jwks_invalid"
            )
            self.audit.write(
                spiffe_id=_unverified_sub(token), tool=None, decision="deny", reason=reason
            )
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", claims["sub"])),
            scopes=str(claims["scope"]).split(" "),
            expires_at=int(claims["exp"]),
            resource=self.resource,
            subject=str(claims["sub"]),
            claims={
                "iss": claims["iss"],
                **({"jti": claims["jti"]} if isinstance(claims.get("jti"), str) else {}),
                **({"cnf_jkt": jkt} if bound else {}),
            },
        )

    def _check_jti(self, claims: dict[str, Any]) -> None:
        """Require a usable jti when tracking needs it, then apply the revocation list."""
        jti = claims.get("jti")
        if not (self.require_jti or self.revocation is not None):
            return
        if not (isinstance(jti, str) and 0 < len(jti) <= 256):
            raise jwt.MissingRequiredClaimError("jti")
        if self.revocation is None:
            return
        act = claims.get("act")
        denied = self.revocation.check(
            jti=jti,
            subjects=[
                _str_or_none(claims.get("sub")),
                _str_or_none(claims.get("client_id")),
                _str_or_none(act.get("sub")) if isinstance(act, dict) else None,
            ],
        )
        if denied is not None:
            raise _RevokedError(denied)


class _RevokedError(Exception):
    """Carries a fixed revocation audit reason."""


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


class DPoPAuthBackend(AuthenticationBackend):
    """RFC 9449 resource-side check: a bound token plus a fresh proof from its key.

    The proof target comes from the configured resource, never from request or forwarding
    headers, so a client cannot choose which URI its proof is compared with.
    """

    def __init__(
        self,
        verifier: AudienceBoundVerifier,
        resource: str,
        audit: AuditLog,
        replay: ProofReplayStore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.verifier = verifier
        self.resource = resource
        self.audit = audit
        self.replay = replay or ProofReplayStore()
        self.clock = clock

    def _deny(self, reason: str) -> None:
        self.audit.write(spiffe_id=None, tool=None, decision="deny", reason=reason)

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, AuthenticatedUser] | None:
        authorization = conn.headers.getlist("authorization")
        if not authorization:
            return None
        scheme, _, token = authorization[0].partition(" ")
        if len(authorization) != 1 or scheme.lower() != "dpop" or not token:
            self._deny("dpop_scheme_required")
            return None
        proofs = conn.headers.getlist("dpop")
        if len(proofs) != 1:
            self._deny("invalid_dpop_proof: exactly one proof required")
            return None
        access = await self.verifier.verify_bound_token(token)
        if access is None:
            return None
        now = self.clock()
        try:
            proof = verify_proof(
                proofs[0],
                htm=conn.scope.get("method", ""),
                htu=self.resource,
                now=now,
                access_token=token,
            )
            if proof.jkt != (access.claims or {}).get("cnf_jkt"):
                raise DPoPError("jkt_mismatch")
            self.replay.add(proof, now)
        except DPoPError as exc:
            self._deny(f"invalid_dpop_proof: {exc}")
            return None
        return AuthCredentials(access.scopes), AuthenticatedUser(access)


def _check_binding(claims: dict[str, Any], *, bound: bool) -> str | None:
    """Return the bound key thumbprint; refuse a token used outside its binding."""
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if bound and not isinstance(jkt, str):
        raise jwt.InvalidTokenError("token is not sender-constrained")
    if not bound and cnf is not None:
        raise jwt.InvalidTokenError("sender-constrained token sent as Bearer")
    return jkt


def _find_key(jwks: dict[str, Any], kid: object) -> Any:
    try:
        keys = jwt.PyJWKSet.from_dict(jwks).keys
    except (jwt.PyJWKSetError, ValueError, TypeError) as exc:
        raise JwksInvalidError(type(exc).__name__) from exc
    return next((k.key for k in keys if k.key_id == kid), None)


def _unverified_sub(token: str) -> str | None:
    try:
        sub = jwt.decode(token, options={"verify_signature": False}).get("sub")
    except jwt.PyJWTError:
        return None
    return (
        "unverified:sha256:"
        + hashlib.sha256(sub.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
        if isinstance(sub, str)
        else None
    )


class ToolScopeGuard:
    """Checks the scope for a tools/call before the MCP layer sees it. Deny by default."""

    def __init__(  # noqa: PLR0913
        self,
        app: ASGIApp,
        tool_scopes: dict[str, str],
        resource_metadata_url: str,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        *,
        scheme: str = "Bearer",
        token_uses: TokenUseCounter | None = None,
    ) -> None:
        self.app = app
        self.scheme = scheme
        self.token_uses = token_uses
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
        if not await self._check_scopes(send, spiffe_id, granted, calls):
            return
        if calls and not await self._consume(send, user, spiffe_id, calls):
            return
        for call in calls:
            self.audit.write(
                spiffe_id=spiffe_id,
                tool=call,
                decision="allow",
                reason=f"scope {self.tool_scopes[call]}",
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

    async def _check_scopes(
        self, send: Send, spiffe_id: str | None, granted: set[str], calls: list[str]
    ) -> bool:
        """Every call needs a declared scope the token grants; False after sending the refusal."""
        for call in calls:
            required = self.tool_scopes.get(call)
            if required is None:
                self.audit.write(
                    spiffe_id=spiffe_id, tool=None, decision="deny", reason="unknown tool"
                )
                await _error(send, 400, "invalid_request", "unknown tool")
                return False
            if required not in granted:
                self.audit.write(
                    spiffe_id=spiffe_id,
                    tool=call,
                    decision="deny",
                    reason=f"insufficient_scope: needs {required}",
                )
                await _forbidden(send, required, self.resource_metadata_url, self.scheme)
                return False
        return True

    async def _consume(
        self, send: Send, user: object, spiffe_id: str | None, calls: list[str]
    ) -> bool:
        """Count the calls against the token's limit; False after sending the refusal."""
        if self.token_uses is None or not isinstance(user, AuthenticatedUser):
            return True
        token = user.access_token
        jti = (token.claims or {}).get("jti")
        try:
            if not isinstance(jti, str) or token.expires_at is None:
                raise TokenUseError("token_call_limit_reached")
            self.token_uses.consume(
                jti, token.expires_at, len(calls), self.clock(), subject=token.subject or ""
            )
        except TokenUseError as exc:
            reason = str(exc)
            self.audit.write(
                spiffe_id=spiffe_id, tool=",".join(calls), decision="deny", reason=reason
            )
            if reason in ("token_use_store_full", "token_use_store_unavailable"):
                await _error(send, 503, "temporarily_unavailable", "token use store unavailable")
            elif reason == "token_use_subject_limit_reached":
                await _error(send, 429, "temporarily_unavailable", "token use quota reached")
            else:
                await _error(send, 401, "invalid_token", "access token call limit reached")
            return False
        return True

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

    def __init__(
        self, app: ASGIApp, resource_metadata_url: str, audit: AuditLog, *, dpop: bool = False
    ) -> None:
        self.inner = RequireAuthMiddleware(app, [], AnyHttpUrl(resource_metadata_url))
        self.audit = audit
        self.dpop = dpop
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not isinstance(scope.get("user"), AuthenticatedUser):
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"")
            if self.dpop:
                if not auth:
                    self.audit.write(
                        spiffe_id=None, tool=None, decision="deny", reason="missing_token"
                    )
                await _dpop_challenge(send, self.resource_metadata_url)
                return
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


async def _dpop_challenge(send: Send, resource_metadata_url: str) -> None:
    body = json.dumps(
        {"error": "invalid_token", "error_description": "valid DPoP token and proof required"}
    ).encode()
    challenge = (
        f'DPoP error="invalid_token", algs="{DPOP_ALG}", '
        f'resource_metadata="{resource_metadata_url}"'
    )
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", challenge.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _forbidden(
    send: Send, required: str, resource_metadata_url: str, scheme: str = "Bearer"
) -> None:
    body = json.dumps(
        {"error": "insufficient_scope", "error_description": f"Required scope: {required}"}
    ).encode()
    challenge = (
        f'{scheme} error="insufficient_scope", scope="{required}", '
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


@dataclass
class Upstream:
    """This server's own credential for one upstream MCP server.

    Invariant 3: the token sent upstream is always obtained here, with this server's JWT-SVID,
    for the upstream `resource`. The caller's token is never read, stored or forwarded.
    """

    resource: str
    scope: str
    trusted_issuers: list[str]
    svid_source: SvidSource
    url_policy: UrlPolicy = STRICT_URLS
    http: HttpFactory = default_http
    refresh_margin: int = 30
    _token: str | None = None
    _expires_at: float = 0.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def token(self, *, discard: str | None = None) -> str:
        async with self._lock:
            if discard is not None and self._token == discard:
                self._token = None
            if self._token is None or time.time() >= self._expires_at - self.refresh_margin:
                body = await fetch_access_token(
                    self.resource,
                    self.svid_source,
                    scope=self.scope,
                    trusted_issuers=self.trusted_issuers,
                    http=self.http,
                    url_policy=self.url_policy,
                )
                self._token = str(body["access_token"])
                self._expires_at = time.time() + int(body["expires_in"])
            return self._token

    async def _call(self, token: str, query: str) -> str:
        return await call_tool(
            self.resource,
            token,
            "notes.search",
            {"query": query},
            http=self.http,
            url_policy=self.url_policy,
        )

    async def search(self, query: str) -> str:
        try:
            token = await self.token()
            result = await self._call(token, query)
            if result.startswith("HTTP 401:"):
                # A cached token can outlive its signing key, for example after an issuer
                # restart with an ephemeral key. Obtain one new token with this server's own
                # SVID and try once more; a 403 or a second 401 is returned unchanged.
                result = await self._call(await self.token(discard=token), query)
            return result
        except TokenRequestError:
            raise ToolError("upstream credential unavailable") from None


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


def build_mcp(
    name: str, store: NotesStore, upstream: Upstream | None = None
) -> tuple[MCPServer, dict[str, str]]:
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

    if upstream is not None:

        @tool(
            "notes.search_upstream",
            "notes:read",
            "Search notes on the upstream server, called with this server's own credential.",
        )
        async def search_upstream(query: str) -> str:
            return await upstream.search(query)

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
    upstream: Upstream | None = None,
    dpop_required: bool = False,
    revocation: RevocationList | None = None,
    token_uses: TokenUseCounter | None = None,
    state: SharedState | None = None,
    metrics: Metrics | None = None,
) -> Starlette:
    resource = resource.rstrip("/")
    mcp, tool_scopes = build_mcp(name, store or NotesStore(), upstream)
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
    verifier = AudienceBoundVerifier(
        issuer=issuer,
        resource=resource,
        jwks=source,
        audit=audit,
        revocation=revocation,
        require_jti=token_uses is not None,
    )
    guarded = ToolScopeGuard(
        StreamableHTTPASGIApp(manager),
        tool_scopes,
        metadata_url,
        audit,
        scheme="DPoP" if dpop_required else "Bearer",
        token_uses=token_uses,
    )
    endpoint = AuditedRequireAuth(guarded, metadata_url, audit, dpop=dpop_required)
    backend: AuthenticationBackend = (
        DPoPAuthBackend(verifier, resource, audit, ProofReplayStore(shared=state))
        if dpop_required
        else BearerAuthBackend(verifier, resource_server_url=resource_url)
    )
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
        **(
            {
                "dpop_signing_alg_values_supported": [DPOP_ALG],
                "dpop_bound_access_tokens_required": True,
            }
            if dpop_required
            else {}
        ),
    }

    async def protected_resource_metadata(_: Request) -> Response:
        return JSONResponse(prm)

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        try:
            _find_key(await source.get(), None)
        except (JwksUnavailableError, JwksInvalidError):
            return JSONResponse({"status": "unavailable"}, status_code=503)
        if revocation is not None and not revocation.available:
            return JSONResponse({"status": "revocation_unavailable"}, status_code=503)
        if state is not None:
            try:
                state.ping()
            except StateUnavailableError:
                return JSONResponse({"status": "state_store_unavailable"}, status_code=503)
        if getattr(source, "degraded", False):
            return JSONResponse({"status": "degraded", "jwks": "stale"})
        return JSONResponse({"status": "ok"})

    async def metrics_endpoint(_: Request) -> Response:
        if metrics is None:
            return Response(status_code=404)
        try:
            await source.get()
            jwks_up = 0.0 if getattr(source, "degraded", False) else 1.0
        except (JwksUnavailableError, JwksInvalidError):
            jwks_up = 0.0
        text = await anyio.to_thread.run_sync(metrics.render, [("jwks", jwks_up)])
        return Response(text, media_type=METRICS_CONTENT_TYPE)

    if metrics is not None:
        audit.metrics = metrics
        if state is not None:
            metrics.gauge("state_store", succeeds(state.ping))
        if revocation is not None:
            metrics.gauge("revocation", lambda: float(revocation.available))

    prm_path = urlsplit(metadata_url).path
    if path in HEALTH_PATHS:
        raise ValueError("resource path collides with a health endpoint")
    routes: list[Any] = [
        Route(path, endpoint=endpoint),
        Route(prm_path, endpoint=protected_resource_metadata, methods=["GET"]),
        Route("/healthz", endpoint=healthz, methods=["GET"]),
        Route("/readyz", endpoint=readyz, methods=["GET"]),
        *([Route("/metrics", endpoint=metrics_endpoint, methods=["GET"])] if metrics else []),
    ]
    return Starlette(
        routes=routes,
        middleware=[
            Middleware(AuthenticationMiddleware, backend=backend),
            Middleware(AuthContextMiddleware),
        ],
        lifespan=lifespan,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-notes", description="Notes MCP server (reference resource server)"
    )
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
    parser.add_argument(
        "--audit-replica-id",
        help="replica name written into every audit record; default HOSTNAME. "
        "Each replica needs its own --audit-log file",
    )
    parser.add_argument(
        "--dpop-required",
        action="store_true",
        help="accept only RFC 9449 sender-constrained tokens with a fresh proof on every request",
    )
    parser.add_argument(
        "--upstream-resource",
        metavar="URI",
        help="upstream MCP server for notes.search_upstream, called with this server's own token",
    )
    parser.add_argument(
        "--upstream-scope", default="notes:read", help="scope requested for the upstream token"
    )
    parser.add_argument(
        "--trusted-issuer",
        action="append",
        type=issuer_arg,
        metavar="URL",
        help="authorization server allowed for the upstream token; required with an upstream",
    )
    parser.add_argument(
        "--socket", help="Workload API socket for the upstream SVID, default SPIFFE_ENDPOINT_SOCKET"
    )
    parser.add_argument(
        "--revocation-file",
        type=Path,
        help="YAML or JSON list of revoked token jti values and blocked SPIFFE IDs; fail closed",
    )
    parser.add_argument(
        "--revocation-public-key",
        type=Path,
        help="Ed25519 PEM public key; the revocation file then needs a valid <file>.sig",
    )
    parser.add_argument(
        "--revocation-poll-seconds",
        type=poll_seconds_arg,
        default=DEFAULT_REVOCATION_POLL_SECONDS,
        help="maximum delay before a changed revocation file applies",
    )
    parser.add_argument(
        "--max-calls-per-token",
        type=_positive,
        help="tool calls one access token jti may authorize on this server; default unlimited",
    )
    parser.add_argument(
        "--token-use-cache-size",
        type=_positive,
        default=DEFAULT_TOKEN_USE_CACHE_SIZE,
        help="live token jti entries kept for --max-calls-per-token; refuses new tokens when full",
    )
    add_url_flags(parser)
    add_tls_server_flags(parser)
    add_state_flags(parser)
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="serve Prometheus text metrics on /metrics (bounded labels, no identifiers)",
    )
    return parser


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv: list[str] | None = None) -> None:
    import uvicorn  # noqa: PLC0415

    parser = build_parser()
    args = parser.parse_args(argv)
    issuer = args.issuer.rstrip("/")
    upstream = None
    if args.upstream_resource:
        if not args.trusted_issuer:
            parser.error("--upstream-resource needs at least one --trusted-issuer")
        upstream = Upstream(
            resource=args.upstream_resource,
            scope=args.upstream_scope,
            trusted_issuers=args.trusted_issuer,
            svid_source=WorkloadApiSvidSource(socket_path=args.socket),
            url_policy=url_policy_from_args(args),
        )
    state = state_from_args(args, parser)
    app = create_app(
        name=args.name,
        resource=args.resource,
        issuer=issuer,
        jwks=JwksFetcher(
            args.jwks_uri or f"{issuer}/jwks.json", verify=client_context(args.ca_file)
        ),
        audit=AuditLog(
            path=args.audit_log,
            component=f"mcp_server:{args.name}",
            replica_id=args.audit_replica_id or default_replica_id(),
        ),
        upstream=upstream,
        dpop_required=args.dpop_required,
        state=state,
        metrics=Metrics() if args.metrics else None,
        revocation=(
            RevocationList.load(
                args.revocation_file,
                args.revocation_poll_seconds,
                load_revocation_key(args.revocation_public_key),
            )
            if args.revocation_file
            else None
        ),
        token_uses=(
            TokenUseCounter(args.max_calls_per_token, args.token_use_cache_size, shared=state)
            if args.max_calls_per_token
            else None
        ),
    )
    tls = tls_server_kwargs(args, parser, public_url=args.resource)
    uvicorn.run(app, host=args.host, port=args.port, **tls)


if __name__ == "__main__":
    main()
