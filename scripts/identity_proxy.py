"""Loopback entry point for the demo's public OIDC and Login V2 endpoints."""

from __future__ import annotations

from urllib.parse import unquote

import httpx2
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from scripts.local_identity_profile import IDENTITY_PORT
from scripts.oidc_gate import FLOW_COOKIE, ISSUER, PANEL_ORIGIN, SESSION_COOKIE
from scripts.zitadel_demo import API_BACKEND, LOGIN_BACKEND

PUBLIC_API = {
    "/.well-known/openid-configuration",
    "/oauth/v2/authorize",
    "/oauth/v2/token",
    "/oauth/v2/keys",
    "/oidc/v1/end_session",
    "/idps/callback",
}


def create_proxy(*, transport: httpx2.AsyncBaseTransport | None = None) -> Starlette:
    async def dispatch(request: Request) -> Response:  # noqa: PLR0911 - explicit protocol denials
        provider_callback = request.method == "GET" and request.url.path == "/idps/callback"
        if request.headers.get("host") != f"localhost:{IDENTITY_PORT}" or (
            request.headers.get("sec-fetch-site") == "cross-site" and not provider_callback
        ):
            return JSONResponse({"error": "local_access_only"}, status_code=403)
        if request.headers.get("origin") not in {None, ISSUER, PANEL_ORIGIN}:
            return JSONResponse({"error": "local_access_only"}, status_code=403)
        path = unquote(request.url.path)
        login = path == "/ui/v2/login" or path.startswith("/ui/v2/login/")
        if (
            (not login and path not in PUBLIC_API)
            or "\\" in path
            or any(piece in {".", ".."} for piece in path.split("/"))
        ):
            return JSONResponse({"error": "endpoint_unavailable"}, status_code=403)
        if request.method not in {"GET", "HEAD", "POST"}:
            return JSONResponse({"error": "endpoint_unavailable"}, status_code=405)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 131072:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        allowed = {
            "accept",
            "accept-encoding",
            "content-type",
            "user-agent",
            "origin",
            "rsc",
            "next-action",
            "next-router-state-tree",
            "next-router-prefetch",
            "next-url",
        }
        headers = {key: value for key, value in request.headers.items() if key.lower() in allowed}
        cookies = [
            piece.strip()
            for piece in request.headers.get("cookie", "").split(";")
            if piece.split("=", 1)[0].strip() not in {SESSION_COOKIE, FLOW_COOKIE}
        ]
        if any(cookies):
            headers["Cookie"] = "; ".join(cookies)
        headers.update({"Host": f"localhost:{IDENTITY_PORT}", "X-Forwarded-Proto": "http"})
        client = httpx2.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx2.Timeout(30, connect=5),
        )
        try:
            target = (LOGIN_BACKEND if login else API_BACKEND) + request.url.path
            if request.url.query:
                target += "?" + request.url.query
            upstream = await client.send(
                client.build_request(request.method, target, headers=headers, content=bytes(body)),
                stream=True,
            )
        except httpx2.HTTPError:
            await client.aclose()
            return JSONResponse({"error": "identity_unavailable"}, status_code=503)

        async def close() -> None:
            await upstream.aclose()
            await client.aclose()

        response = StreamingResponse(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers={
                key: value
                for key, value in upstream.headers.items()
                if key.lower()
                in {
                    "content-type",
                    "content-encoding",
                    "location",
                    "x-action-redirect",
                    "x-action-revalidated",
                }
            },
            background=BackgroundTask(close),
        )
        for cookie in upstream.headers.get_list("set-cookie"):
            if cookie.split("=", 1)[0].strip() not in {SESSION_COOKIE, FLOW_COOKIE}:
                response.raw_headers.append((b"set-cookie", cookie.encode("latin1")))
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        return response

    return Starlette(
        routes=[
            Route(
                "/{path:path}",
                dispatch,
                methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            )
        ]
    )
