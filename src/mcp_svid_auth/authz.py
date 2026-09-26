"""Minimal OAuth token endpoint: JWT-SVID client assertion in, audience-bound access token out.

Client authentication follows draft-ietf-oauth-spiffe-client-auth. Resource binding follows
RFC 8707. Access tokens follow the RFC 9068 JWT profile.
"""

from __future__ import annotations

import argparse
import json
import re
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
# RFC 6749 section 3.3 scope-token characters.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


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

    def verify_svid(self, assertion: str) -> str:
        """Validate a JWT-SVID client assertion and return its SPIFFE ID."""
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
            if trust_domain != self.policy.trust_domain:
                raise AuthError("invalid_client", "foreign trust domain")
            key = self.resolver.resolve(trust_domain, header.get("kid"))
        except AuthError as exc:
            raise AuthError(exc.code, exc.description, 401, exc.detail) from exc
        except Exception as exc:
            raise AuthError(
                "temporarily_unavailable", "trust bundle unavailable", 503, repr(exc)
            ) from exc
        try:
            claims = jwt.decode(
                assertion,
                key,
                algorithms=[alg],
                audience=self.issuer,
                options={"require": ["sub", "aud", "exp", "iat"]},
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
        return sub

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
        spiffe_id = self.verify_svid(assertion)
        client_id = form.get("client_id")
        if client_id is not None and client_id != spiffe_id:
            raise AuthError("invalid_client", "client_id does not match SVID", 401)
        scopes = self.policy.grant(spiffe_id, resource, parse_scope(form.get("scope")))
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


def parse_scope(raw: str | None) -> set[str]:
    """Parse a scope parameter. Explicit scope is required; tokens separated by single spaces."""
    if not raw:
        raise AuthError("invalid_scope", "scope parameter is required")
    tokens = raw.split(" ")
    if not all(_SCOPE_TOKEN.fullmatch(t) for t in tokens):
        raise AuthError("invalid_scope", "malformed scope parameter")
    return set(tokens)


def main(argv: list[str] | None = None) -> None:
    import uvicorn  # noqa: PLC0415

    parser = argparse.ArgumentParser(description="JWT-SVID to access token bridge (POC)")
    parser.add_argument("--issuer", required=True, help="public base URL, used as iss and SVID aud")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--static-jwks", type=Path, help="test mode: JWT-SVID bundle as JWKS file")
    parser.add_argument("--socket", help="Workload API socket, default SPIFFE_ENDPOINT_SOCKET")
    parser.add_argument("--audit-log", type=Path)
    parser.add_argument(
        "--max-svid-lifetime",
        type=int,
        default=DEFAULT_MAX_SVID_LIFETIME,
        help="reject JWT-SVIDs whose exp - iat exceeds this many seconds",
    )
    args = parser.parse_args(argv)

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
    )
    uvicorn.run(server.app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
