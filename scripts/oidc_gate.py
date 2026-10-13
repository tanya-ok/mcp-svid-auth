"""Optional local OIDC sign-in; browser sessions never contain bearer credentials."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx2
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from scripts.local_identity_profile import IDENTITY_PORT, VIEWER_PORT
from scripts.passwordless_policy import PasswordlessApproval

ISSUER = f"http://localhost:{IDENTITY_PORT}"
PANEL_ORIGIN = f"http://localhost:{VIEWER_PORT}"
CALLBACK = PANEL_ORIGIN + "/_auth/callback"
FLOW_COOKIE = "lab_oidc_flow"
SESSION_COOKIE = "lab_human_session"
ROLE_CLAIM = "urn:zitadel:iam:org:project:roles"


@dataclass(frozen=True)
class Settings:
    client_id: str
    project_id: str
    org_id: str
    approved_subjects: frozenset[str]

    @classmethod
    def parse(cls, data: dict[str, Any]) -> Settings:
        values = [data.get(name) for name in ("client_id", "project_id", "org_id")]
        if not all(
            isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9@_-]{1,128}", value)
            for value in values
        ):
            raise ValueError("Invalid local OIDC configuration")
        subjects = data.get("approved_subjects")
        if not isinstance(subjects, list) or not all(isinstance(value, str) for value in subjects):
            raise ValueError("Invalid local OIDC configuration")
        approval = PasswordlessApproval(frozenset(subjects))
        return cls(str(values[0]), str(values[1]), str(values[2]), approval.approved_subjects)


@dataclass(frozen=True)
class Flow:
    verifier: str
    nonce: str
    expires: float


class OidcGate:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.approval = PasswordlessApproval(settings.approved_subjects)
        self.transport = transport
        self.clock = clock
        self.flows: dict[str, Flow] = {}
        self.sessions: dict[str, float] = {}

    def purge(self) -> None:
        now = self.clock()
        self.flows = {key: value for key, value in self.flows.items() if value.expires > now}
        self.sessions = {key: expiry for key, expiry in self.sessions.items() if expiry > now}

    async def fetch(self, path: str, *, form: dict[str, str] | None = None) -> dict[str, Any]:
        async with httpx2.AsyncClient(
            transport=self.transport, trust_env=False, follow_redirects=False, timeout=5
        ) as client:
            response = (
                await client.get(ISSUER + path)
                if form is None
                else await client.post(ISSUER + path, data=form)
            )
        response.raise_for_status()
        if len(response.content) > 65536:
            raise ValueError("Invalid OIDC response")
        value: Any = response.json()
        if not isinstance(value, dict):
            raise ValueError("Invalid OIDC response")
        return value

    async def metadata(self) -> None:
        value = await self.fetch("/.well-known/openid-configuration")
        expected = {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/oauth/v2/authorize",
            "token_endpoint": ISSUER + "/oauth/v2/token",
            "jwks_uri": ISSUER + "/oauth/v2/keys",
        }
        if any(value.get(name) != required for name, required in expected.items()):
            raise ValueError("Unexpected OIDC issuer or endpoint")

    def authenticated(self, request: Request) -> bool:
        self.purge()
        return self.sessions.get(request.cookies.get(SESSION_COOKIE, ""), 0) > self.clock()

    @staticmethod
    def landing(*, denied: bool = False) -> Response:
        heading = "Access unavailable" if denied else "Sign in to the lab"
        description = (
            "This account cannot open the lab. Sign in with an account that has the viewer role."
            if denied
            else "Your viewer role opens a read-only view of services, permissions "
            "and demo results."
        )
        return HTMLResponse(
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>Security lab - {heading}</title><style>"
            "body{margin:0;background:#f4f6fa;color:#263445;font:16px system-ui}"
            "main{max-width:440px;margin:12vh auto;padding:32px;border:1px solid #dde3ec;"
            "border-radius:18px;background:white}h1{font-size:30px}p{line-height:1.6;color:#617084}"
            "a{display:inline-block;padding:13px 20px;background:#355b87;color:white;"
            "border-radius:8px;text-decoration:none}@media(max-width:520px){main{margin:8vh 16px}}"
            f"</style><main><p>LOCAL SECURITY WORKSPACE</p><h1>{heading}</h1>"
            f"<p>{description}</p>"
            "<a href='/_auth/login'>Continue with ZITADEL</a>"
            "<p>Synthetic local demo. Workload identity remains protected by SPIRE.</p>"
            "</main></html>",
            status_code=403 if denied else 200,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    async def login(self) -> Response:
        self.purge()
        if len(self.flows) >= 256 or len(self.sessions) >= 256:
            return JSONResponse({"error": "login_unavailable"}, status_code=503)
        try:
            await self.metadata()
        except (httpx2.HTTPError, ValueError):
            return JSONResponse({"error": "login_unavailable"}, status_code=503)
        state = secrets.token_urlsafe(32)
        flow = Flow(secrets.token_urlsafe(48), secrets.token_urlsafe(32), self.clock() + 120)
        self.flows[state] = flow
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(flow.verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        query = urlencode(
            {
                "client_id": self.settings.client_id,
                "response_type": "code",
                "redirect_uri": CALLBACK,
                "scope": "openid profile "
                + ROLE_CLAIM
                + " urn:zitadel:iam:org:id:"
                + self.settings.org_id,
                "state": state,
                "nonce": flow.nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "max_age": "0",
            }
        )
        response = RedirectResponse(ISSUER + "/oauth/v2/authorize?" + query, status_code=303)
        response.set_cookie(FLOW_COOKIE, state, max_age=120, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def validate(self, encoded: str, nonce: str) -> dict[str, Any]:
        if len(encoded) > 16384:
            raise ValueError("Invalid identity token")
        header = jwt.get_unverified_header(encoded)
        if (
            header.get("alg") != "RS256"
            or header.get("typ") not in (None, "JWT")
            or header.get("crit")
        ):
            raise ValueError("Invalid identity token")
        keys = (await self.fetch("/oauth/v2/keys")).get("keys")
        if not isinstance(keys, list) or len(keys) > 16:
            raise ValueError("Invalid identity keys")
        candidates = [
            key for key in keys if isinstance(key, dict) and key.get("kid") == header.get("kid")
        ]
        if len(candidates) != 1 or not isinstance(header.get("kid"), str):
            raise ValueError("Invalid identity keys")
        key = jwt.PyJWK.from_dict(candidates[0], algorithm="RS256")
        claims: dict[str, Any] = jwt.decode(
            encoded,
            key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=self.settings.client_id,
            options={"require": ["iss", "aud", "sub", "iat", "exp"]},
        )
        audience = claims["aud"]
        single = audience in (self.settings.client_id, [self.settings.client_id])
        project = (
            isinstance(audience, list)
            and len(audience) == 2
            and set(audience) == {self.settings.client_id, self.settings.project_id}
            and claims.get("azp") == self.settings.client_id
        )
        if (
            not (single or project)
            or claims.get("azp", self.settings.client_id) != self.settings.client_id
        ):
            raise ValueError("Invalid identity audience")
        if not isinstance(claims["sub"], str) or not 1 <= len(claims["sub"]) <= 128:
            raise ValueError("Invalid identity subject")
        if (
            type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 900
        ):
            raise ValueError("Invalid identity lifetime")
        received = claims.get("nonce")
        if not isinstance(received, str) or not secrets.compare_digest(
            received.encode(), nonce.encode()
        ):
            raise ValueError("Invalid identity nonce")
        roles = claims.get(ROLE_CLAIM)
        role = roles.get("viewer") if isinstance(roles, dict) else None
        if not isinstance(role, dict) or self.settings.org_id not in role:
            raise ValueError("Viewer role required")
        self.approval.require_verified_claims(claims, now=self.clock())
        return claims

    async def callback(self, request: Request) -> Response:
        self.purge()
        state = request.query_params.getlist("state")
        code = request.query_params.getlist("code")
        cookie = request.cookies.get(FLOW_COOKIE, "")
        if (
            len(state) != 1
            or len(code) != 1
            or not cookie
            or not secrets.compare_digest(cookie.encode(), state[0].encode())
        ):
            return JSONResponse({"error": "login_denied"}, status_code=403)
        flow = self.flows.pop(cookie, None)
        if flow is None or not 1 <= len(code[0]) <= 8192:
            return JSONResponse({"error": "login_denied"}, status_code=403)
        try:
            await self.metadata()
            value = await self.fetch(
                "/oauth/v2/token",
                form={
                    "grant_type": "authorization_code",
                    "client_id": self.settings.client_id,
                    "redirect_uri": CALLBACK,
                    "code": code[0],
                    "code_verifier": flow.verifier,
                },
            )
            encoded = value.get("id_token")
            if not isinstance(encoded, str):
                raise ValueError("Missing identity token")
            claims = await self.validate(encoded, flow.nonce)
        except (httpx2.HTTPError, ValueError, jwt.PyJWTError, TypeError, KeyError):
            response: Response = (
                self.landing(denied=True)
                if request.headers.get("sec-fetch-dest") == "document"
                else JSONResponse({"error": "login_denied"}, status_code=403)
            )
        else:
            session = secrets.token_urlsafe(32)
            self.sessions[session] = min(self.clock() + 300, float(claims["exp"]))
            response = RedirectResponse("/c/main/security-lab", status_code=303)
            response.set_cookie(SESSION_COOKIE, session, max_age=300, httponly=True, samesite="lax")
        response.delete_cookie(FLOW_COOKIE, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def logout(self, request: Request) -> Response:
        self.sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        return response

    async def route(self, request: Request) -> Response | None:  # noqa: PLR0911 - explicit auth denials
        path = request.url.path
        if path == "/_auth/login" and request.method == "GET":
            return await self.login()
        if path == "/_auth/callback" and request.method == "GET":
            return await self.callback(request)
        if path == "/_auth/logout" and request.method == "POST":
            return self.logout(request)
        if path.startswith("/_auth/"):
            return JSONResponse({"error": "login_denied"}, status_code=403)
        if not self.authenticated(request):
            if request.method == "GET" and (path == "/" or path.startswith("/c/")):
                return self.landing()
            return JSONResponse({"error": "sign_in_required"}, status_code=401)
        return None
