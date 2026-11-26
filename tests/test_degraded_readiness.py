"""Stale JWKS while the issuer is briefly unreachable; trust bundle readiness."""

from __future__ import annotations

from typing import Any

import httpx2
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.mcp_server import (
    JWKS_CACHE_SECONDS,
    JWKS_STALE_SECONDS,
    JwksFetcher,
    JwksUnavailableError,
    create_app,
)
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer, WorkloadApiResolver
from tests.conftest import ISSUER, POLICY, SERVER_A

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


class Issuer:
    def __init__(self, jwks: dict[str, Any]) -> None:
        self.jwks = jwks
        self.up = True

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        if not self.up:
            raise httpx2.ConnectError("down", request=request)
        return httpx2.Response(200, json=self.jwks)


async def test_last_good_jwks_is_served_until_tokens_signed_under_it_expire() -> None:
    issuer = Issuer(LocalSvidIssuer().jwks())
    clock = Clock()
    fetcher = JwksFetcher(
        f"{ISSUER}/jwks.json", transport=httpx2.MockTransport(issuer.handler), clock=clock
    )
    assert await fetcher.get() == issuer.jwks
    issuer.up = False
    clock.now += JWKS_CACHE_SECONDS + 1
    assert await fetcher.get() == issuer.jwks
    assert fetcher.degraded
    clock.now += JWKS_STALE_SECONDS
    with pytest.raises(JwksUnavailableError):
        await fetcher.get()
    issuer.up = True
    clock.now += 10
    assert await fetcher.get() == issuer.jwks
    assert not fetcher.degraded


async def test_mcp_readiness_reports_degraded_then_unavailable() -> None:
    issuer = Issuer(LocalSvidIssuer().jwks())
    clock = Clock()
    fetcher = JwksFetcher(
        f"{ISSUER}/jwks.json", transport=httpx2.MockTransport(issuer.handler), clock=clock
    )
    app = create_app(name="a", resource=SERVER_A, issuer=ISSUER, jwks=fetcher, audit=AuditLog())
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://notes-a.test"
    ) as client:
        assert (await client.get("/readyz")).json() == {"status": "ok"}
        issuer.up = False
        clock.now += JWKS_CACHE_SECONDS + 1
        degraded = await client.get("/readyz")
        clock.now += JWKS_STALE_SECONDS
        gone = await client.get("/readyz")
    assert (degraded.status_code, degraded.json()["status"]) == (200, "degraded")
    assert gone.status_code == 503


class FakeBundles:
    def __init__(self, domains: set[str]) -> None:
        self.domains = domains

    def get_bundle_for_trust_domain(self, domain: Any) -> object | None:
        return object() if str(domain) in self.domains else None


class FakeClient:
    def __init__(self, result: FakeBundles | Exception) -> None:
        self.result = result

    def fetch_jwt_bundles(self) -> FakeBundles:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    ("result", "status"),
    [
        (FakeBundles({"example.org"}), 200),
        (FakeBundles({"other.example.org"}), 503),
        (OSError("socket gone"), 503),
    ],
)
def test_authz_readiness_requires_a_current_trust_bundle(
    result: FakeBundles | Exception, status: int
) -> None:
    resolver = WorkloadApiResolver(client_factory=lambda _socket: FakeClient(result))
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=resolver,
        audit=AuditLog(),
    )
    with TestClient(server.app()) as client:
        response = client.get("/readyz")
    assert response.status_code == status
    if status == 503:
        assert response.json() == {"status": "trust_bundle_unavailable"}
