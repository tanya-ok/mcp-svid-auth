"""Discovery URL checks: https only and public addresses only, unless relaxed for dev."""

from __future__ import annotations

from typing import Any

import httpx2
import pytest

from mcp_svid_auth import agent_client, stdio_wrapper
from mcp_svid_auth.agent_client import (
    UnsafeUrlError,
    UrlPolicy,
    call_tool,
    fetch_access_token,
    is_public_address,
)

pytestmark = pytest.mark.anyio

RESOURCE = "https://mcp.example.org/mcp"
ISSUER = "https://as.example.org"
PUBLIC_V4 = "9.9.9.9"
PUBLIC_V6 = "2620:fe::fe"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def resolver(table: dict[str, list[str]]) -> Any:
    async def resolve(host: str) -> list[str]:
        if host not in table:
            raise OSError("no such host")
        return table[host]

    return resolve


PUBLIC_DNS = resolver({"mcp.example.org": [PUBLIC_V4], "as.example.org": [PUBLIC_V6]})


class CountingSource:
    def __init__(self) -> None:
        self.audiences: list[str] = []

    def fetch(self, audience: str) -> str:
        self.audiences.append(audience)
        return "svid"


class Upstream:
    """PRM and AS metadata with a configurable token endpoint. Records every request."""

    def __init__(self, token_endpoint: str = f"{ISSUER}/token") -> None:
        self.token_endpoint = token_endpoint
        self.requests: list[str] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(str(request.url))
        if request.url.path.startswith("/.well-known/oauth-protected-resource"):
            return httpx2.Response(
                200, json={"resource": RESOURCE, "authorization_servers": [ISSUER]}
            )
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx2.Response(
                200, json={"issuer": ISSUER, "token_endpoint": self.token_endpoint}
            )
        return httpx2.Response(200, json={"access_token": "t", "expires_in": 300, "scope": "s"})

    def http(self, **kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self.handler), **kwargs)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104 - address under test, not a bind
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ],
)
def test_non_public_addresses(address: str) -> None:
    assert not is_public_address(address)


@pytest.mark.parametrize("address", [PUBLIC_V4, PUBLIC_V6, "::ffff:9.9.9.9"])
def test_public_addresses(address: str) -> None:
    assert is_public_address(address)


async def test_https_public_host_passes() -> None:
    await UrlPolicy(resolve=PUBLIC_DNS).check(RESOURCE)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://mcp.example.org/mcp", "scheme not allowed"),
        ("file:///etc/passwd", "scheme not allowed"),
        ("https://user@mcp.example.org/mcp", "no host or userinfo present"),
        ("https:///mcp", "no host or userinfo present"),
        ("https://127.0.0.1/mcp", "host resolves to a non-public address"),
        ("https://[::1]/mcp", "host resolves to a non-public address"),
        ("https://169.254.169.254/latest", "host resolves to a non-public address"),
        ("https://unknown.example.org/mcp", "host does not resolve"),
    ],
)
async def test_strict_policy_refuses(url: str, reason: str) -> None:
    with pytest.raises(UnsafeUrlError) as refused:
        await UrlPolicy(resolve=PUBLIC_DNS).check(url)
    assert refused.value.reason == reason
    assert refused.value.url == url


async def test_name_resolving_to_any_private_address_is_refused() -> None:
    mixed = resolver({"mcp.example.org": [PUBLIC_V4, "10.0.0.5"]})
    with pytest.raises(UnsafeUrlError, match="non-public"):
        await UrlPolicy(resolve=mixed).check(RESOURCE)


async def test_empty_resolution_is_refused() -> None:
    with pytest.raises(UnsafeUrlError, match="does not resolve"):
        await UrlPolicy(resolve=resolver({"mcp.example.org": []})).check(RESOURCE)


async def test_dev_flags_relax_each_check_separately() -> None:
    private = resolver({"mcp.example.org": ["10.0.0.5"]})
    await UrlPolicy(allow_http=True, resolve=PUBLIC_DNS).check("http://mcp.example.org/mcp")
    with pytest.raises(UnsafeUrlError, match="non-public"):
        await UrlPolicy(allow_http=True, resolve=private).check("http://mcp.example.org/mcp")
    with pytest.raises(UnsafeUrlError, match="scheme"):
        await UrlPolicy(allow_private=True).check("http://mcp.example.org/mcp")
    await UrlPolicy(allow_http=True, allow_private=True).check("http://10.0.0.5/mcp")
    with pytest.raises(UnsafeUrlError, match="scheme"):
        await UrlPolicy(allow_http=True, allow_private=True).check("ftp://mcp.example.org/")


async def test_private_resource_refused_before_any_request() -> None:
    upstream = Upstream()
    source = CountingSource()
    urls = UrlPolicy(resolve=resolver({"mcp.example.org": ["192.168.0.10"]}))
    with pytest.raises(UnsafeUrlError):
        await fetch_access_token(
            RESOURCE,
            source,
            scope="s",
            trusted_issuers=[ISSUER],
            http=upstream.http,
            url_policy=urls,
        )
    assert upstream.requests == []
    assert source.audiences == []


async def test_http_issuer_refused_even_when_allowlisted() -> None:
    upstream = Upstream()
    source = CountingSource()
    http_issuer = "http://as.example.org"

    def handler(request: httpx2.Request) -> httpx2.Response:
        upstream.requests.append(str(request.url))
        return httpx2.Response(
            200, json={"resource": RESOURCE, "authorization_servers": [http_issuer]}
        )

    def http(**kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(handler), **kwargs)

    with pytest.raises(UnsafeUrlError, match="scheme"):
        await fetch_access_token(
            RESOURCE,
            source,
            scope="s",
            trusted_issuers=[http_issuer],
            http=http,
            url_policy=UrlPolicy(resolve=PUBLIC_DNS),
        )
    assert upstream.requests == ["https://mcp.example.org/.well-known/oauth-protected-resource/mcp"]
    assert source.audiences == []


@pytest.mark.parametrize(
    "endpoint",
    ["https://169.254.169.254/token", "http://as.example.org/token", "https://10.0.0.1/token"],
)
async def test_unsafe_token_endpoint_refused_before_svid(endpoint: str) -> None:
    upstream = Upstream(token_endpoint=endpoint)
    source = CountingSource()
    with pytest.raises(UnsafeUrlError):
        await fetch_access_token(
            RESOURCE,
            source,
            scope="s",
            trusted_issuers=[ISSUER],
            http=upstream.http,
            url_policy=UrlPolicy(resolve=PUBLIC_DNS),
        )
    assert source.audiences == []
    assert all("/token" not in r for r in upstream.requests)


async def test_safe_flow_reaches_token_endpoint() -> None:
    upstream = Upstream()
    source = CountingSource()
    body = await fetch_access_token(
        RESOURCE,
        source,
        scope="s",
        trusted_issuers=[ISSUER],
        http=upstream.http,
        url_policy=UrlPolicy(resolve=PUBLIC_DNS),
    )
    assert body["access_token"] == "t"
    assert source.audiences == [ISSUER]
    assert upstream.requests[-1] == f"{ISSUER}/token"


async def test_call_tool_refuses_unsafe_url_before_sending_token() -> None:
    upstream = Upstream()
    with pytest.raises(UnsafeUrlError):
        await call_tool(
            "http://mcp.example.org/mcp",
            "secret-token",
            "notes.search",
            {},
            http=upstream.http,
            url_policy=UrlPolicy(resolve=PUBLIC_DNS),
        )
    assert upstream.requests == []


@pytest.mark.parametrize("module", [agent_client, stdio_wrapper])
def test_cli_dev_flags_default_off(module: Any) -> None:
    base = ["--resource", RESOURCE, "--scope", "s", "--trusted-issuer", ISSUER]
    tail = ["--", "child"] if module is stdio_wrapper else []
    strict = agent_client.url_policy_from_args(module.build_parser().parse_args(base + tail))
    assert (strict.allow_http, strict.allow_private) == (False, False)
    dev_args = [*base, "--allow-http", "--allow-private-network", *tail]
    dev = agent_client.url_policy_from_args(module.build_parser().parse_args(dev_args))
    assert (dev.allow_http, dev.allow_private) == (True, True)


def test_agent_logs_url_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = CountingSource()
    monkeypatch.setattr(agent_client, "WorkloadApiSvidSource", lambda **_kw: source)
    with pytest.raises(SystemExit) as exited:
        agent_client.main(
            ["--resource", "http://127.0.0.1:8101/mcp", "--scope", "s", "--trusted-issuer", ISSUER]
        )
    assert exited.value.code == 2
    assert capsys.readouterr().out.strip() == (
        '{"event": "url_refused", "url": "http://127.0.0.1:8101/mcp",'
        ' "reason": "scheme not allowed"}'
    )
    assert source.audiences == []
