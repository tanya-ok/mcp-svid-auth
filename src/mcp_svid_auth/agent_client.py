"""Agent: JWT-SVID in, access token out, MCP tool calls with that token.

Flow per MCP server:
1. Read Protected Resource Metadata to find the authorization server.
   Refuse it unless it is on the operator's trusted issuer allowlist.
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
from collections.abc import Callable, Collection
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


class UntrustedIssuerError(TokenRequestError):
    """The resource named no authorization server on the trusted issuer allowlist."""

    def __init__(self, resource: str, issuers: list[str]) -> None:
        super().__init__("no trusted authorization server for this resource")
        self.resource = resource
        self.issuers = issuers


_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_issuer(url: str) -> str:
    """Canonical form for exact issuer comparison (RFC 8414 section 2, RFC 3986 section 6.2).

    Lowercases scheme and host, drops the default port and maps an empty path to "/". The path
    is otherwise kept byte for byte, so "/a" and "/a/" differ. Raises ValueError for anything
    that is not a valid issuer identifier: non-http(s) scheme, no host, userinfo, query or
    fragment.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("issuer must be an http or https URL")
    if not parts.hostname or "@" in parts.netloc:
        raise ValueError("issuer must have a host and no userinfo")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise ValueError("issuer must not have a query or fragment")
    port = parts.port
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", "", ""))


def is_trusted_issuer(issuer: str, trusted: Collection[str]) -> bool:
    try:
        candidate = normalize_issuer(issuer)
    except ValueError:
        return False
    return candidate in {normalize_issuer(t) for t in trusted}


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


async def discover(
    resource: str, trusted_issuers: Collection[str], http: HttpFactory = default_http
) -> Discovery:
    """Find the token endpoint for `resource`, using only an allowlisted authorization server.

    The allowlist check runs before any request to the authorization server and before any
    SVID is fetched, so a resource cannot steer the agent to an issuer of its choosing.
    """
    if not trusted_issuers:
        raise ValueError("at least one trusted issuer is required")
    async with http() as client:
        prm = (await client.get(resource_metadata_url(resource))).raise_for_status().json()
        if prm.get("resource") != resource:
            raise TokenRequestError("protected resource metadata names a different resource")
        named = [a for a in prm.get("authorization_servers", []) if isinstance(a, str)]
        trusted = [a for a in named if is_trusted_issuer(a, trusted_issuers)]
        if not trusted:
            raise UntrustedIssuerError(resource, named)
        issuer = trusted[0]
        meta_url = issuer.rstrip("/") + "/.well-known/oauth-authorization-server"
        meta = (await client.get(meta_url)).raise_for_status().json()
    if meta.get("issuer") != issuer:
        raise TokenRequestError("authorization server metadata issuer mismatch")
    return Discovery(issuer=issuer, token_endpoint=meta["token_endpoint"])


async def fetch_access_token(  # noqa: PLR0913
    resource: str,
    svid_source: SvidSource,
    *,
    scope: str,
    trusted_issuers: Collection[str],
    spiffe_id: str | None = None,
    http: HttpFactory = default_http,
) -> dict[str, Any]:
    found = await discover(resource, trusted_issuers, http)
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
        args.resource,
        source,
        spiffe_id=args.spiffe_id,
        scope=args.scope,
        trusted_issuers=args.trusted_issuer,
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


def issuer_arg(value: str) -> str:
    try:
        normalize_issuer(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None
    return value


def refusal_event(exc: UntrustedIssuerError) -> dict[str, Any]:
    return {"event": "issuer_refused", "resource": exc.resource, "issuers": exc.issuers}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-agent", description="Agent that authenticates with its JWT-SVID"
    )
    parser.add_argument("--resource", required=True, help="MCP server canonical URI")
    parser.add_argument(
        "--scope", required=True, help="space separated scopes, e.g. 'notes:read notes:write'"
    )
    parser.add_argument(
        "--trusted-issuer",
        action="append",
        required=True,
        type=issuer_arg,
        metavar="URL",
        help="authorization server issuer the agent may mint SVIDs for; repeatable, exact match",
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
    except UntrustedIssuerError as exc:
        print(json.dumps(refusal_event(exc)))
        sys.exit(2)
    except TokenRequestError as exc:
        print(json.dumps({"event": "token_denied", "error": str(exc)}))
        sys.exit(2)


if __name__ == "__main__":
    main()
