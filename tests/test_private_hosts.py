"""Exact private host allowlist: in-cluster names without the blanket dev flag."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_svid_auth import agent_client, mcp_server, stdio_wrapper
from mcp_svid_auth.agent_client import UnsafeUrlError, UrlPolicy
from tests.test_url_policy import ISSUER, RESOURCE, resolver

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_named_private_host_is_allowed_and_nothing_else() -> None:
    dns = resolver(
        {"notes.cluster.example.org": ["10.0.0.7"], "other.cluster.example.org": ["10.0.0.8"]}
    )
    policy = UrlPolicy(resolve=dns, private_hosts=frozenset({"notes.cluster.example.org"}))
    assert await policy.addresses("https://NOTES.cluster.example.org/mcp") == ["10.0.0.7"]
    with pytest.raises(UnsafeUrlError, match="non-public"):
        await policy.check("https://other.cluster.example.org/mcp")
    with pytest.raises(UnsafeUrlError, match="scheme"):
        await policy.check("http://notes.cluster.example.org/mcp")


@pytest.mark.parametrize("module", [agent_client, stdio_wrapper])
def test_private_host_flag_is_exact_and_not_a_dev_relaxation(
    module: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    base = ["--resource", RESOURCE, "--scope", "s", "--trusted-issuer", ISSUER]
    tail = ["--", "child"] if module is stdio_wrapper else []
    argv = [*base, "--allow-private-host", "Notes.Cluster.Example.Org", *tail]
    policy = agent_client.url_policy_from_args(module.build_parser().parse_args(argv))
    assert policy.private_hosts == frozenset({"notes.cluster.example.org"})
    assert (policy.allow_http, policy.allow_private) == (False, False)
    assert capsys.readouterr().err == ""


def test_mcp_server_accepts_the_flag_for_its_upstream() -> None:
    args = mcp_server.build_parser().parse_args(
        ["--resource", RESOURCE, "--issuer", ISSUER, "--allow-private-host", "notes-b.example.org"]
    )
    assert agent_client.url_policy_from_args(args).private_hosts == frozenset(
        {"notes-b.example.org"}
    )
