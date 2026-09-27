"""Async JWKS fetch: cache, refetch on unknown kid, rate limit, fixed URI, no loop blocking."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.mcp_server import (
    JWKS_CACHE_SECONDS,
    JWKS_MIN_REFETCH_SECONDS,
    AudienceBoundVerifier,
    JwksFetcher,
)

pytestmark = pytest.mark.anyio

ISSUER = "http://authz.test"
RESOURCE = "http://notes-a.test/mcp"
JWKS_URI = f"{ISSUER}/jwks.json"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class SigningKey:
    def __init__(self) -> None:
        self.kid = uuid.uuid4().hex[:16]
        self.key = ec.generate_private_key(ec.SECP256R1())

    def jwks(self) -> dict[str, Any]:
        jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "ES256"})
        return {"keys": [jwk]}

    def mint(self, kid: str | None = None, **headers: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "spiffe://example.org/agent/research",
            "aud": RESOURCE,
            "scope": "notes:read",
            "iat": now,
            "exp": now + 60,
        }
        hdrs = {"kid": kid or self.kid, "typ": "at+jwt", **headers}
        return jwt.encode(claims, self.key, algorithm="ES256", headers=hdrs)


class FakeAuthz:
    """Serves the current JWKS and records every request."""

    def __init__(self, jwks: dict[str, Any], delay: float = 0.0) -> None:
        self.jwks = jwks
        self.delay = delay
        self.status = 200
        self.urls: list[str] = []

    async def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.urls.append(str(request.url))
        if self.delay:
            await asyncio.sleep(self.delay)
        return httpx2.Response(self.status, json=self.jwks)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _verifier(
    server: FakeAuthz, tmp_path: Path, clock: Clock | None = None
) -> tuple[AudienceBoundVerifier, JwksFetcher]:
    fetcher = JwksFetcher(
        JWKS_URI, transport=httpx2.MockTransport(server.handle), clock=clock or time.monotonic
    )
    audit = AuditLog(path=tmp_path / "mcp.jsonl")
    return AudienceBoundVerifier(ISSUER, RESOURCE, fetcher, audit), fetcher


def _reasons(tmp_path: Path) -> list[str]:
    path = tmp_path / "mcp.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["reason"] for line in path.read_text().splitlines()]


async def test_unknown_kid_refetches_once_and_accepts_rotated_key(tmp_path: Path) -> None:
    old, new = SigningKey(), SigningKey()
    server = FakeAuthz(old.jwks())
    clock = Clock()
    verifier, _ = _verifier(server, tmp_path, clock)
    assert await verifier.verify_token(old.mint()) is not None
    server.jwks = new.jwks()
    clock.now += JWKS_MIN_REFETCH_SECONDS
    token = await verifier.verify_token(new.mint())
    assert token is not None
    assert len(server.urls) == 2
    assert await verifier.verify_token(new.mint()) is not None
    assert len(server.urls) == 2


async def test_refetch_is_rate_limited(tmp_path: Path) -> None:
    key = SigningKey()
    server = FakeAuthz(key.jwks())
    clock = Clock()
    verifier, _ = _verifier(server, tmp_path, clock)
    assert await verifier.verify_token(key.mint()) is not None
    clock.now += JWKS_MIN_REFETCH_SECONDS
    bogus = [key.mint(kid=uuid.uuid4().hex) for _ in range(50)]
    results = await asyncio.gather(*(verifier.verify_token(t) for t in bogus))
    assert results == [None] * 50
    assert len(server.urls) == 2
    for token in bogus:
        assert await verifier.verify_token(token) is None
    assert len(server.urls) == 2
    clock.now += JWKS_MIN_REFETCH_SECONDS
    assert await verifier.verify_token(bogus[0]) is None
    assert len(server.urls) == 3
    assert all("unknown signing key" in r for r in _reasons(tmp_path))


async def test_cache_expires_after_ttl(tmp_path: Path) -> None:
    key = SigningKey()
    server = FakeAuthz(key.jwks())
    clock = Clock()
    verifier, _ = _verifier(server, tmp_path, clock)
    await verifier.verify_token(key.mint())
    clock.now += JWKS_CACHE_SECONDS - 1
    await verifier.verify_token(key.mint())
    assert len(server.urls) == 1
    clock.now += 2
    await verifier.verify_token(key.mint())
    assert len(server.urls) == 2


async def test_jwks_uri_never_comes_from_the_token(tmp_path: Path) -> None:
    key = SigningKey()
    server = FakeAuthz(key.jwks())
    verifier, _ = _verifier(server, tmp_path)
    token = key.mint(
        kid=uuid.uuid4().hex, jku="http://evil.test/jwks.json", x5u="http://evil.test/c"
    )
    assert await verifier.verify_token(token) is None
    assert server.urls
    assert set(server.urls) == {JWKS_URI}


async def test_fetch_failure_denies_without_raising(tmp_path: Path) -> None:
    key = SigningKey()
    server = FakeAuthz(key.jwks())
    server.status = 503
    verifier, _ = _verifier(server, tmp_path)
    assert await verifier.verify_token(key.mint()) is None
    assert _reasons(tmp_path) == ["jwks_unavailable: HTTPStatusError"]


async def test_fetch_does_not_block_the_event_loop(tmp_path: Path) -> None:
    key = SigningKey()
    server = FakeAuthz(key.jwks(), delay=0.2)
    verifier, _ = _verifier(server, tmp_path)
    ticks = 0
    done = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not done.is_set():
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    try:
        assert await verifier.verify_token(key.mint()) is not None
    finally:
        done.set()
        await task
    assert ticks >= 5
