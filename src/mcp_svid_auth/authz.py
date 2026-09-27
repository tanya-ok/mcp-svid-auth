"""Minimal OAuth token endpoint: JWT-SVID client assertion in, audience-bound access token out.

Client authentication follows draft-ietf-oauth-spiffe-client-auth. Resource binding follows
RFC 8707. Access tokens follow the RFC 9068 JWT profile.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import re
import signal
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.errors import AuthError
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import (
    JWT_SVID_ALGORITHMS,
    KeyResolver,
    StaticJwksResolver,
    WorkloadApiResolver,
    spiffe_trust_domain,
)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
ACCESS_TOKEN_ALG = "ES256"  # noqa: S105 - algorithm name, not a secret
DEFAULT_TOKEN_TTL = 300
DEFAULT_MAX_SVID_LIFETIME = 300
_CLOCK_SKEW = 30
DEFAULT_REPLAY_CACHE_SIZE = 10_000
# reject: jti required, each (sub, jti) accepted once. allow-reuse-within-lifetime: jti optional and
# not tracked, for SVID sources that cache and re-serve one SVID (SPIRE 1.15.3 agent, see docs).
SVID_REPLAY_MODES = ("reject", "allow-reuse-within-lifetime")
DEFAULT_SVID_REPLAY = "reject"
_MAX_JTI_LENGTH = 256
# RFC 6749 section 3.3 scope-token characters.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
DEFAULT_POLICY_POLL_SECONDS = 5.0


@dataclass
class ReplayCache:
    """Seen (sub, jti) pairs, each kept until its assertion expires plus clock skew.

    In-memory and per process: replicas or a restart do not share it. When full after evicting
    expired entries, new assertions are refused (fail closed) instead of forgetting live ones.
    """

    max_entries: int = DEFAULT_REPLAY_CACHE_SIZE
    _expiry: dict[tuple[str, str], float] = field(default_factory=dict)
    _heap: list[tuple[float, tuple[str, str]]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __len__(self) -> int:
        return len(self._expiry)

    def evict_expired(self, now: float) -> None:
        with self._lock:
            self._evict(now)

    def _evict(self, now: float) -> None:
        while self._heap and self._heap[0][0] <= now:
            _, key = heapq.heappop(self._heap)
            self._expiry.pop(key, None)

    def add(self, sub: str, jti: str, expires_at: float, now: float) -> None:
        """Record a first use. Raises AuthError on replay or when the cache is full."""
        key = (sub, jti)
        with self._lock:
            self._evict(now)
            if key in self._expiry:
                raise AuthError("invalid_client", "client assertion replayed", 401, f"jti={jti}")
            if len(self._expiry) >= self.max_entries:
                raise AuthError(
                    "temporarily_unavailable",
                    "replay cache full",
                    503,
                    f"{len(self._expiry)} live entries",
                )
            self._expiry[key] = expires_at
            heapq.heappush(self._heap, (expires_at, key))


@dataclass
class AuthzServer:
    issuer: str
    policy: Policy
    resolver: KeyResolver
    token_ttl: int = DEFAULT_TOKEN_TTL
    max_svid_lifetime: int = DEFAULT_MAX_SVID_LIFETIME
    audit: AuditLog = field(default_factory=lambda: AuditLog(component="authz"))
    signing_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    kid: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    replay_cache: ReplayCache = field(default_factory=ReplayCache)
    svid_replay: str = DEFAULT_SVID_REPLAY
    policy_path: Path | None = None
    _policy_digest: str | None = None
    _reload_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.svid_replay not in SVID_REPLAY_MODES:
            raise ValueError(f"svid_replay must be one of {SVID_REPLAY_MODES}")
        if self.policy_path is not None:
            self._policy_digest = _digest(self.policy_path)

    def reload_policy(self, *, force: bool = False) -> bool:
        """Reload `policy_path` if its content changed (or always with `force`).

        Applies to token requests from then on; tokens already issued stay valid until `exp`.
        An unreadable or invalid file fails closed: every token request is denied until a
        valid file is loaded. Returns True when a reload was attempted.
        """
        if self.policy_path is None:
            return False
        with self._reload_lock:
            try:
                digest = _digest(self.policy_path)
            except OSError as exc:
                digest = f"unreadable:{type(exc).__name__}"
            if not force and digest == self._policy_digest:
                return False
            self._policy_digest = digest
            try:
                policy = Policy.load(self.policy_path)
            except Exception as exc:
                self.policy = Policy(trust_domain=self.policy.trust_domain, grants={})
                self.audit.write(
                    spiffe_id=None,
                    tool=None,
                    decision="policy_reload",
                    reason=f"failed: {type(exc).__name__}; denying all token requests",
                )
                return True
            self.policy = policy
            self.audit.write(
                spiffe_id=None,
                tool=None,
                decision="policy_reload",
                reason=f"loaded sha256={digest[:16]} clients={len(policy.grants)}",
            )
            return True

    def watch_policy(self, interval: float, stop: threading.Event) -> None:
        """Poll `policy_path` every `interval` seconds until `stop` is set."""
        while not stop.wait(interval):
            self.reload_policy()

    def jwks(self) -> dict[str, Any]:
        jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(self.signing_key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": ACCESS_TOKEN_ALG})
        return {"keys": [jwk]}

    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["spiffe_jwt"],
        }

    def verify_svid(self, assertion: str, policy: Policy | None = None) -> str:
        """Validate a JWT-SVID client assertion and return its SPIFFE ID."""
        policy = policy or self.policy
        try:
            header = jwt.get_unverified_header(assertion)
            unverified = jwt.decode(assertion, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_client", "malformed client assertion", 401) from exc
        alg = header.get("alg")
        if alg not in JWT_SVID_ALGORITHMS:
            raise AuthError("invalid_client", "unsupported assertion algorithm", 401)
        sub = unverified.get("sub")
        if not isinstance(sub, str):
            raise AuthError("invalid_client", "assertion has no sub", 401)
        try:
            trust_domain = spiffe_trust_domain(sub)
            if trust_domain != policy.trust_domain:
                raise AuthError("invalid_client", "foreign trust domain")
            key = self.resolver.resolve(trust_domain, header.get("kid"))
        except AuthError as exc:
            raise AuthError(exc.code, exc.description, 401, exc.detail) from exc
        except Exception as exc:
            raise AuthError(
                "temporarily_unavailable", "trust bundle unavailable", 503, repr(exc)
            ) from exc
        required = ["sub", "aud", "exp", "iat"]
        if self.svid_replay == "reject":
            required.append("jti")
        try:
            claims = jwt.decode(
                assertion,
                key,
                algorithms=[alg],
                audience=self.issuer,
                options={"require": required},
                leeway=_CLOCK_SKEW,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("invalid_client", "client assertion expired", 401) from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("invalid_client", "client assertion audience mismatch", 401) from exc
        except jwt.PyJWTError as exc:
            raise AuthError(
                "invalid_client", "client assertion invalid", 401, f"{type(exc).__name__}: {exc}"
            ) from exc
        aud = claims["aud"]
        if aud not in (self.issuer, [self.issuer]):
            # The draft requires the issuer as the sole audience value.
            raise AuthError("invalid_client", "client assertion audience must be issuer only", 401)
        lifetime = int(claims["exp"]) - int(claims["iat"])
        if lifetime > self.max_svid_lifetime:
            raise AuthError(
                "invalid_client",
                "client assertion lifetime too long",
                401,
                f"exp - iat = {lifetime}s, max {self.max_svid_lifetime}s",
            )
        self._check_jti(sub, claims)
        return sub

    def _check_jti(self, sub: str, claims: dict[str, Any]) -> None:
        """Validate jti when present. In reject mode (jti required) record it and refuse reuse."""
        if "jti" not in claims:
            return
        jti = claims["jti"]
        if not isinstance(jti, str) or not 0 < len(jti) <= _MAX_JTI_LENGTH:
            raise AuthError("invalid_client", "client assertion jti invalid", 401)
        if self.svid_replay == "reject":
            # RFC 7523 section 3: remember each jti for as long as the assertion would be accepted.
            self.replay_cache.add(sub, jti, int(claims["exp"]) + _CLOCK_SKEW, time.time())

    def issue(self, form: dict[str, str]) -> dict[str, Any]:
        if form.get("grant_type") != "client_credentials":
            raise AuthError("unsupported_grant_type", "only client_credentials is supported")
        if form.get("client_assertion_type") != CLIENT_ASSERTION_TYPE:
            raise AuthError("invalid_client", "unsupported client_assertion_type", 401)
        assertion = form.get("client_assertion")
        if not assertion:
            raise AuthError("invalid_client", "missing client_assertion", 401)
        resource = form.get("resource")
        if not resource:
            raise AuthError("invalid_target", "resource parameter is required")
        policy = self.policy  # one snapshot per request, even if a reload swaps it
        spiffe_id = self.verify_svid(assertion, policy)
        client_id = form.get("client_id")
        if client_id is not None and client_id != spiffe_id:
            raise AuthError("invalid_client", "client_id does not match SVID", 401)
        scopes = policy.grant(spiffe_id, resource, parse_scope(form.get("scope")))
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": spiffe_id,
            "client_id": spiffe_id,
            "aud": resource.rstrip("/"),
            "scope": " ".join(sorted(scopes)),
            "iat": now,
            "exp": now + self.token_ttl,
            "jti": uuid.uuid4().hex,
        }
        token = jwt.encode(
            claims,
            self.signing_key,
            algorithm=ACCESS_TOKEN_ALG,
            headers={"kid": self.kid, "typ": "at+jwt"},
        )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.token_ttl,
            "scope": claims["scope"],
        }

    async def token_endpoint(self, request: Request) -> Response:
        items = (await request.form()).multi_items()
        form = {k: str(v) for k, v in items}
        try:
            if len(form) != len(items):
                # RFC 6749 section 3.2: request parameters MUST NOT be included more than once.
                raise AuthError("invalid_request", "repeated request parameter")
            body = self.issue(form)
        except AuthError as exc:
            detail = f" ({exc.detail})" if exc.detail else ""
            self._audit(form, "deny", f"{exc.code}: {exc.description}{detail}")
            return JSONResponse(
                {"error": exc.code, "error_description": exc.description},
                status_code=exc.status,
                headers=_NO_STORE,
            )
        self._audit(form, "allow", f"issued for {form.get('resource')} scope={body['scope']}")
        return JSONResponse(body, headers=_NO_STORE)

    def _audit(self, form: dict[str, str], decision: str, reason: str) -> None:
        spiffe_id: str | None = None
        try:
            sub = jwt.decode(form.get("client_assertion", ""), options={"verify_signature": False})
            spiffe_id = (
                str(sub.get("sub")) if decision == "allow" else f"unverified:{sub.get('sub')}"
            )
            if decision == "allow":
                # Lets reuse of one SVID be spotted in the audit trail when reuse is allowed.
                reason = f"{reason} svid_jti={sub.get('jti', 'none')}"
        except jwt.PyJWTError:
            pass
        self.audit.write(spiffe_id=spiffe_id, tool=None, decision=decision, reason=reason)

    def app(self) -> Starlette:
        async def jwks(_: Request) -> Response:
            return JSONResponse(self.jwks())

        async def metadata(_: Request) -> Response:
            return JSONResponse(self.metadata())

        return Starlette(
            routes=[
                Route("/token", self.token_endpoint, methods=["POST"]),
                Route("/jwks.json", jwks, methods=["GET"]),
                Route("/.well-known/oauth-authorization-server", metadata, methods=["GET"]),
            ]
        )


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_policy_reload(server: AuthzServer, poll_seconds: float) -> threading.Event:
    """Reload on SIGHUP and, if `poll_seconds` > 0, when the file content changes."""
    signal.signal(signal.SIGHUP, lambda _s, _f: server.reload_policy(force=True))
    stop = threading.Event()
    if poll_seconds > 0:
        threading.Thread(target=server.watch_policy, args=(poll_seconds, stop), daemon=True).start()
    return stop


def parse_scope(raw: str | None) -> set[str]:
    """Parse a scope parameter. Explicit scope is required; tokens separated by single spaces."""
    if not raw:
        raise AuthError("invalid_scope", "scope parameter is required")
    tokens = raw.split(" ")
    if not all(_SCOPE_TOKEN.fullmatch(t) for t in tokens):
        raise AuthError("invalid_scope", "malformed scope parameter")
    return set(tokens)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-authz", description="JWT-SVID to access token bridge (POC)"
    )
    parser.add_argument(
        "--issuer",
        required=True,
        help="public base URL, used as iss and as the required SVID aud; trailing slash removed",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        required=True,
        help="path to the policy YAML file; reloaded on SIGHUP and when its content changes",
    )
    parser.add_argument(
        "--policy-poll-seconds",
        type=float,
        default=DEFAULT_POLICY_POLL_SECONDS,
        help="how often to check the policy file for changes; 0 disables polling (SIGHUP only)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="listen address")
    parser.add_argument("--port", type=int, default=8100, help="listen port")
    parser.add_argument(
        "--static-jwks",
        type=Path,
        help="test mode: JWT-SVID bundle as a JWKS file instead of the Workload API",
    )
    parser.add_argument(
        "--socket", help="Workload API socket for JWT bundles, default SPIFFE_ENDPOINT_SOCKET"
    )
    parser.add_argument(
        "--audit-log", type=Path, help="audit log file (JSON lines, appended), default stderr"
    )
    parser.add_argument(
        "--max-svid-lifetime",
        type=int,
        default=DEFAULT_MAX_SVID_LIFETIME,
        help="reject JWT-SVIDs whose exp - iat exceeds this many seconds",
    )
    parser.add_argument(
        "--svid-replay",
        choices=SVID_REPLAY_MODES,
        default=DEFAULT_SVID_REPLAY,
        help=(
            "reject: require a JWT-SVID jti and accept each (sub, jti) once; "
            "allow-reuse-within-lifetime: jti optional, a reused SVID is accepted until it expires"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    import uvicorn  # noqa: PLC0415

    args = build_parser().parse_args(argv)

    policy = Policy.load(args.policy)
    resolver: KeyResolver
    if args.static_jwks:
        resolver = StaticJwksResolver.from_file(policy.trust_domain, args.static_jwks)
    else:
        resolver = WorkloadApiResolver(socket_path=args.socket)
    server = AuthzServer(
        issuer=args.issuer.rstrip("/"),
        policy=policy,
        resolver=resolver,
        audit=AuditLog(path=args.audit_log, component="authz"),
        max_svid_lifetime=args.max_svid_lifetime,
        svid_replay=args.svid_replay,
        policy_path=args.policy,
    )
    install_policy_reload(server, args.policy_poll_seconds)
    uvicorn.run(server.app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
