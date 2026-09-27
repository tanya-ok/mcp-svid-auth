"""Client-side trusted issuer allowlist: a resource cannot pick the SVID audience."""

from __future__ import annotations

import functools
import json
from typing import Any

import httpx2
import pytest

from mcp_svid_auth import agent_client, stdio_wrapper
from mcp_svid_auth.agent_client import (
    UntrustedIssuerError,
    fetch_access_token,
    is_trusted_issuer,
    normalize_issuer,
)
from tests.conftest import DEV_URLS, ISSUER, RESEARCH, SERVER_A

pytestmark = pytest.mark.anyio

ROGUE = "http://rogue.test/mcp"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class CountingSource:
    def __init__(self) -> None:
        self.audiences: list[str] = []

    def fetch(self, audience: str) -> str:
        self.audiences.append(audience)
        return "svid"


class RogueResource:
    """Serves Protected Resource Metadata naming `issuers`. Records every request."""

    def __init__(self, issuers: list[str]) -> None:
        self.issuers = issuers
        self.requests: list[str] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(str(request.url))
        if request.url.host == "rogue.test":
            body = {"resource": ROGUE, "authorization_servers": self.issuers}
            return httpx2.Response(200, json=body)
        return httpx2.Response(500)

    def http(self, **kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self.handler), **kwargs)


async def test_allowed_issuer_gets_token(world_factory: Any) -> None:
    async with world_factory() as world:
        token = await fetch_access_token(
            SERVER_A,
            world.spire.source_for(RESEARCH),
            scope="notes:read",
            trusted_issuers=["HTTP://Authz.Test:80"],
            http=world.http,
            url_policy=DEV_URLS,
        )
    assert token["scope"] == "notes:read"


@pytest.mark.parametrize(
    "named",
    [
        "http://attacker.test",
        "http://authz.test.attacker.test",
        "http://authz.testx",
        "http://authz.test:8443",
        "https://authz.test",
        "http://authz.test/other",
        "http://authz.test@attacker.test",
        "http://authz.test?x=1",
        "http://authz.test#frag",
        "file:///authz.test",
    ],
)
async def test_untrusted_issuer_refused_before_svid(named: str) -> None:
    rogue = RogueResource([named])
    source = CountingSource()
    with pytest.raises(UntrustedIssuerError) as refused:
        await fetch_access_token(
            ROGUE,
            source,
            scope="notes:read",
            trusted_issuers=[ISSUER],
            http=rogue.http,
            url_policy=DEV_URLS,
        )
    assert refused.value.issuers == [named]
    assert source.audiences == []
    assert rogue.requests == ["http://rogue.test/.well-known/oauth-protected-resource/mcp"]


async def test_path_issuer_trailing_slash_refused() -> None:
    rogue = RogueResource(["https://as.test/tenant/"])
    source = CountingSource()
    with pytest.raises(UntrustedIssuerError):
        await fetch_access_token(
            ROGUE,
            source,
            scope="notes:read",
            trusted_issuers=["https://as.test/tenant"],
            http=rogue.http,
            url_policy=DEV_URLS,
        )
    assert source.audiences == []


async def test_first_trusted_issuer_is_used(world_factory: Any) -> None:
    async with world_factory() as world:
        found = await agent_client.discover(
            SERVER_A, [ISSUER], http=world.http, url_policy=DEV_URLS
        )
    assert found.issuer == ISSUER


async def test_empty_allowlist_is_an_error() -> None:
    with pytest.raises(ValueError, match="trusted issuer"):
        await agent_client.discover(ROGUE, [], http=RogueResource([ISSUER]).http)


@pytest.mark.parametrize(
    ("issuer", "trusted", "ok"),
    [
        ("http://authz.test", "http://authz.test/", True),
        ("https://as.test:443/t", "https://as.test/t", True),
        ("https://as.test/t", "https://as.test/t/", False),
        ("https://as.test/t", "https://as.test/T", False),
        ("https://as.test/t", "https://as.test/t2", False),
        ("https://as.test/t/../t", "https://as.test/t", False),
        ("not a url", "https://as.test", False),
    ],
)
def test_issuer_comparison(issuer: str, trusted: str, ok: bool) -> None:
    assert is_trusted_issuer(issuer, [trusted]) is ok


@pytest.mark.parametrize(
    "bad", ["ftp://as.test", "https://", "https://u@as.test", "https://as.test?q", "as.test"]
)
def test_normalize_rejects_non_issuers(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_issuer(bad)


def test_agent_cli_requires_trusted_issuer() -> None:
    with pytest.raises(SystemExit):
        agent_client.build_parser().parse_args(["--resource", SERVER_A, "--scope", "notes:read"])
    args = agent_client.build_parser().parse_args(
        [
            "--resource",
            SERVER_A,
            "--scope",
            "notes:read",
            "--trusted-issuer",
            ISSUER,
            "--trusted-issuer",
            "https://as.test",
        ]
    )
    assert args.trusted_issuer == [ISSUER, "https://as.test"]


def test_agent_cli_rejects_malformed_trusted_issuer() -> None:
    argv = ["--resource", SERVER_A, "--scope", "x", "--trusted-issuer", "https://u@as.test"]
    with pytest.raises(SystemExit):
        agent_client.build_parser().parse_args(argv)


def test_stdio_cli_requires_trusted_issuer() -> None:
    with pytest.raises(SystemExit):
        stdio_wrapper.build_parser().parse_args(["--resource", SERVER_A, "--scope", "x", "--", "y"])


def test_agent_logs_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rogue = RogueResource(["http://attacker.test"])
    source = CountingSource()
    monkeypatch.setattr(agent_client, "WorkloadApiSvidSource", lambda **_kw: source)
    patched = functools.partial(fetch_access_token, http=rogue.http, url_policy=DEV_URLS)
    monkeypatch.setattr(agent_client, "fetch_access_token", patched)
    with pytest.raises(SystemExit) as exited:
        agent_client.main(
            [
                "--resource",
                ROGUE,
                "--scope",
                "notes:read",
                "--trusted-issuer",
                ISSUER,
                "--allow-http",
                "--allow-private-network",
            ]
        )
    assert exited.value.code == 2
    event = json.loads(capsys.readouterr().out.strip())
    assert event == {
        "event": "issuer_refused",
        "resource": ROGUE,
        "issuers": ["http://attacker.test"],
    }
    assert source.audiences == []


def test_agent_call_flag() -> None:
    base = ["--resource", SERVER_A, "--scope", "s", "--trusted-issuer", ISSUER]
    args = agent_client.build_parser().parse_args(
        [*base, "--call", 'notes.search_upstream={"query": "x"}', "--call", "notes.search"]
    )
    assert args.call == [("notes.search_upstream", {"query": "x"}), ("notes.search", {})]
    assert agent_client.build_parser().parse_args(base).call is None
    for bad in ["=1", "t=[1]", "t={bad"]:
        with pytest.raises(SystemExit):
            agent_client.build_parser().parse_args([*base, "--call", bad])
