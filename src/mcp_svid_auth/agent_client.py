"""Agent: JWT-SVID in, access token out, MCP tool calls with that token.

Flow per MCP server:
1. Read Protected Resource Metadata to find the authorization server.
2. Read authorization server metadata to find the issuer and token endpoint.
3. Fetch a JWT-SVID with audience = issuer.
4. client_credentials grant with the SVID as client assertion and resource = server URI.
5. Call tools with the access token.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE
from mcp_svid_auth.spiffe_keys import SvidSource, WorkloadApiSvidSource

HttpFactory = Callable[..., httpx2.AsyncClient]


class TokenRequestError(Exception):
    pass


def default_http(**kwargs: Any) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(timeout=httpx2.Timeout(30, read=300), **kwargs)


def resource_metadata_url(resource: str) -> str:
    parts = urlsplit(resource)
    path = "/.well-known/oauth-protected-resource" + (parts.path if parts.path != "/" else "")
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


@dataclass
class Discovery:
    issuer: str
    token_endpoint: str


async def discover(resource: str, http: HttpFactory = default_http) -> Discovery:
    async with http() as client:
        prm = (await client.get(resource_metadata_url(resource))).raise_for_status().json()
        if prm.get("resource") != resource:
            raise TokenRequestError("protected resource metadata names a different resource")
        issuer = prm["authorization_servers"][0]
        meta_url = issuer.rstrip("/") + "/.well-known/oauth-authorization-server"
        meta = (await client.get(meta_url)).raise_for_status().json()
    if meta.get("issuer") != issuer:
        raise TokenRequestError("authorization server metadata issuer mismatch")
    return Discovery(issuer=issuer, token_endpoint=meta["token_endpoint"])


async def fetch_access_token(
    resource: str,
    svid_source: SvidSource,
    *,
    scope: str,
    spiffe_id: str | None = None,
    http: HttpFactory = default_http,
) -> dict[str, Any]:
    found = await discover(resource, http)
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": svid_source.fetch(found.issuer),
        "resource": resource,
        "scope": scope,
    }
    if spiffe_id:
        form["client_id"] = spiffe_id
    async with http() as client:
        response = await client.post(found.token_endpoint, data=form)
    body: dict[str, Any] = response.json()
    if response.status_code != 200:
        raise TokenRequestError(
            f"{response.status_code} {body.get('error')}: {body.get('error_description')}"
        )
    return body


async def call_tool(
    resource: str,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    http: HttpFactory = default_http,
) -> str:
    """Call one tool. Returns the text result, or 'HTTP <status>: <challenge>' on auth failure."""
    auth_failures: list[str] = []

    async def record(response: httpx2.Response) -> None:
        if response.status_code in (401, 403):
            challenge = response.headers.get("www-authenticate")
            auth_failures.append(f"HTTP {response.status_code}: {challenge}")

    headers = {"Authorization": f"Bearer {token}"}
    async with http(headers=headers, event_hooks={"response": [record]}) as client:
        try:
            async with Client(streamable_http_client(resource, http_client=client)) as mcp:
                result = await mcp.call_tool(tool, arguments)
        except Exception:
            if auth_failures:
                return auth_failures[-1]
            raise
    texts = [getattr(block, "text", "") for block in result.content]
    prefix = "tool error: " if result.is_error else ""
    return prefix + " ".join(t for t in texts if t)


async def run(args: argparse.Namespace) -> int:
    source: SvidSource = WorkloadApiSvidSource(socket_path=args.socket)
    token = await fetch_access_token(
        args.resource, source, spiffe_id=args.spiffe_id, scope=args.scope
    )
    print(
        json.dumps(
            {
                "event": "token",
                "resource": args.resource,
                "scope": token["scope"],
                "expires_in": token["expires_in"],
            }
        )
    )
    target = args.steal_token or args.resource
    if args.steal_token:
        print(json.dumps({"event": "replay", "issued_for": args.resource, "sent_to": target}))
    for tool, arguments in (
        ("notes.search", {"query": "welcome"}),
        ("notes.write", {"text": "hello from the agent"}),
    ):
        outcome = await call_tool(target, token["access_token"], tool, arguments)
        print(json.dumps({"event": "call", "server": target, "tool": tool, "result": outcome}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-agent", description="Agent that authenticates with its JWT-SVID"
    )
    parser.add_argument("--resource", required=True, help="MCP server canonical URI")
    parser.add_argument(
        "--scope", required=True, help="space separated scopes, e.g. 'notes:read notes:write'"
    )
    parser.add_argument("--spiffe-id", help="sent as client_id")
    parser.add_argument("--socket", help="Workload API socket, default SPIFFE_ENDPOINT_SOCKET")
    parser.add_argument(
        "--steal-token",
        metavar="OTHER_RESOURCE",
        help="demo: send the token issued for --resource to OTHER_RESOURCE instead",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    try:
        sys.exit(asyncio.run(run(parser.parse_args(argv))))
    except TokenRequestError as exc:
        print(json.dumps({"event": "token_denied", "error": str(exc)}))
        sys.exit(2)


if __name__ == "__main__":
    main()
