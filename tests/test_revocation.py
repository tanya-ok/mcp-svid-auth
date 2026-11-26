"""Revocation by access token jti and SPIFFE ID, and per-token tool call limits."""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.agent_client import call_tool
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import (
    ACCESS_TOKEN_TYPE,
    CLIENT_ASSERTION_TYPE,
    TOKEN_EXCHANGE_GRANT,
    AuthzServer,
)
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.revocation import (
    BLOCKED_SPIFFE_ID,
    MAX_REVOCATION_ENTRIES,
    REVOKED_TOKEN,
    UNAVAILABLE,
    RevocationList,
    TokenUseCounter,
    TokenUseError,
)
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import DEV_URLS, ISSUER, POLICY, READER, RESEARCH, SERVER_A, HostRouter

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _write(path: Path, **lists: list[str]) -> None:
    content = {"revoked_jti": [], "blocked_spiffe_ids": [], **lists}
    path.write_text(json.dumps(content), encoding="utf-8")


def _revocations(path: Path, clock: Clock, **lists: list[str]) -> RevocationList:
    _write(path, **lists)
    revocations = RevocationList.load(path, poll_seconds=5)
    revocations.clock = clock
    revocations._checked_at = clock()
    return revocations


# Unit behaviour of the list.


def test_listed_jti_and_spiffe_id_are_refused(tmp_path: Path) -> None:
    revocations = _revocations(
        tmp_path / "r.json", Clock(), revoked_jti=["j1"], blocked_spiffe_ids=[READER]
    )
    assert revocations.check(jti="j1", subjects=[RESEARCH]) == REVOKED_TOKEN
    assert revocations.check(jti="j2", subjects=[None, READER]) == BLOCKED_SPIFFE_ID
    assert revocations.check(jti="j2", subjects=[RESEARCH]) is None


def test_change_applies_within_the_poll_bound_and_not_before(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "r.json"
    revocations = _revocations(path, clock)
    _write(path, revoked_jti=["j1"])
    clock.now += 4.9
    assert revocations.check(jti="j1", subjects=[]) is None
    clock.now += 0.1
    assert revocations.check(jti="j1", subjects=[]) == REVOKED_TOKEN


@pytest.mark.parametrize(
    "content",
    ["{not yaml", '{"unknown": []}', '{"revoked_jti": "j1"}', '{"revoked_jti": [""]}', "[1]"],
)
def test_broken_file_fails_closed_until_repaired(tmp_path: Path, content: str) -> None:
    clock = Clock()
    path = tmp_path / "r.json"
    revocations = _revocations(path, clock)
    path.write_text(content, encoding="utf-8")
    clock.now += 5
    assert revocations.check(jti="other", subjects=[RESEARCH]) == UNAVAILABLE
    assert not revocations.available
    _write(path, revoked_jti=[])
    clock.now += 5
    assert revocations.check(jti="other", subjects=[RESEARCH]) is None


def test_deleted_file_fails_closed(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "r.json"
    revocations = _revocations(path, clock)
    path.unlink()
    clock.now += 5
    assert revocations.check(jti=None, subjects=[RESEARCH]) == UNAVAILABLE


def test_startup_refuses_a_missing_invalid_or_oversized_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be opened"):
        RevocationList.load(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text('{"revoked": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="known keys"):
        RevocationList.load(bad)
    _write(bad, revoked_jti=[f"j{i}" for i in range(MAX_REVOCATION_ENTRIES + 1)])
    with pytest.raises(ValueError, match=r"too large|too many"):
        RevocationList.load(bad)


@pytest.mark.parametrize("content", ["", "  \n", "{}", '{"revoked_jti": []}'])
def test_empty_or_partial_file_is_refused_not_read_as_revoke_nothing(
    tmp_path: Path, content: str
) -> None:
    path = tmp_path / "r.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="known keys"):
        RevocationList.load(path)
    clock = Clock()
    revocations = _revocations(tmp_path / "ok.json", clock)
    revocations.path.write_text(content, encoding="utf-8")
    clock.now += 5
    assert revocations.check(jti="j", subjects=[RESEARCH]) == UNAVAILABLE


def test_explicit_empty_lists_revoke_nothing(tmp_path: Path) -> None:
    path = tmp_path / "r.yaml"
    path.write_text("revoked_jti: []\nblocked_spiffe_ids:\n", encoding="utf-8")
    assert RevocationList.load(path).check(jti="j", subjects=[RESEARCH]) is None


def test_call_counter_limits_counts_and_forgets_expired_tokens() -> None:
    counter = TokenUseCounter(max_calls=2, max_entries=2)
    counter.consume("a", expires_at=100, calls=1, now=0)
    counter.consume("a", expires_at=100, calls=1, now=1)
    with pytest.raises(TokenUseError, match="call_limit"):
        counter.consume("a", expires_at=100, calls=1, now=2)
    with pytest.raises(TokenUseError, match="call_limit"):
        counter.consume("b", expires_at=100, calls=3, now=2)
    counter.consume("b", expires_at=50, calls=2, now=2)
    with pytest.raises(TokenUseError, match="store_full"):
        counter.consume("c", expires_at=100, calls=1, now=3)
    counter.consume("c", expires_at=100, calls=1, now=50)
    assert len(counter) == 2
    with pytest.raises(ValueError, match="positive"):
        TokenUseCounter(max_calls=0)


# Resource server integration.


@contextlib.asynccontextmanager
async def _world(tmp_path: Path, **options: Any) -> AsyncIterator[tuple[Any, AuthzServer, Path]]:
    spire = LocalSvidIssuer()
    authz = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        token_exchange=True,
    )
    audit_path = tmp_path / "mcp.jsonl"
    app = create_app(
        name="a",
        resource=SERVER_A,
        issuer=ISSUER,
        jwks=authz.jwks,
        audit=AuditLog(path=audit_path),
        **options,
    )
    router = HostRouter({"authz.test": authz.app(), "notes-a.test": app})

    def http(**kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=router), **kwargs)

    async with app.router.lifespan_context(app):
        yield http, authz, audit_path


def _token(authz: AuthzServer, who: str = RESEARCH, **extra: Any) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": who,
        "client_id": who,
        "aud": SERVER_A,
        "scope": "notes:read notes:write",
        "iat": now,
        "exp": now + 60,
        "jti": "token-1",
        **extra,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(
        claims, authz.signing_key, algorithm="ES256", headers={"kid": authz.kid, "typ": "at+jwt"}
    )


async def _search(http: Any, token: str) -> str:
    return await call_tool(
        SERVER_A, token, "notes.search", {"query": "welcome"}, http=http, url_policy=DEV_URLS
    )


def _reasons(path: Path) -> list[str]:
    return [json.loads(line)["reason"] for line in path.read_text(encoding="utf-8").splitlines()]


async def test_revoked_jti_is_refused_on_the_next_call(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "revoked.json"
    revocations = _revocations(path, clock)
    async with _world(tmp_path, revocation=revocations) as (http, authz, audit):
        token = _token(authz)
        assert "welcome" in await _search(http, token)
        _write(path, revoked_jti=["token-1"])
        clock.now += 5
        assert (await _search(http, token)).startswith("HTTP 401")
        assert "welcome" in await _search(http, _token(authz, jti="token-2"))
    assert REVOKED_TOKEN in _reasons(audit)


async def test_blocked_spiffe_id_is_refused_as_subject_client_or_actor(tmp_path: Path) -> None:
    revocations = _revocations(tmp_path / "r.json", Clock(), blocked_spiffe_ids=[READER])
    async with _world(tmp_path, revocation=revocations) as (http, authz, audit):
        assert (await _search(http, _token(authz, who=READER))).startswith("HTTP 401")
        as_client = _token(authz, client_id=READER)
        assert (await _search(http, as_client)).startswith("HTTP 401")
        as_actor = _token(authz, act={"sub": READER})
        assert (await _search(http, as_actor)).startswith("HTTP 401")
        assert "welcome" in await _search(http, _token(authz))
    reasons = _reasons(audit)
    assert reasons.count(BLOCKED_SPIFFE_ID) >= 3
    assert reasons.count("scope notes:read") == 1


async def test_unreadable_revocation_state_denies_every_token(tmp_path: Path) -> None:
    clock = Clock()
    path = tmp_path / "r.json"
    revocations = _revocations(path, clock)
    async with _world(tmp_path, revocation=revocations) as (http, authz, audit):
        path.write_text("{broken", encoding="utf-8")
        clock.now += 5
        assert (await _search(http, _token(authz))).startswith("HTTP 401")
        async with http() as client:
            ready = await client.get("http://notes-a.test/readyz")
    assert ready.status_code == 503
    assert UNAVAILABLE in _reasons(audit)


async def test_tracking_requires_a_jti(tmp_path: Path) -> None:
    revocations = _revocations(tmp_path / "r.json", Clock())
    async with _world(tmp_path, revocation=revocations) as (http, authz, audit):
        assert (await _search(http, _token(authz, jti=None))).startswith("HTTP 401")
    async with _world(tmp_path, token_uses=TokenUseCounter(5)) as (http, authz, _):
        assert (await _search(http, _token(authz, jti=None))).startswith("HTTP 401")
    assert "invalid_token: MissingRequiredClaimError" in _reasons(audit)


async def test_without_tracking_a_token_without_jti_still_works(tmp_path: Path) -> None:
    async with _world(tmp_path) as (http, authz, _):
        assert "welcome" in await _search(http, _token(authz, jti=None))


async def test_single_call_token_cannot_be_replayed(tmp_path: Path) -> None:
    async with _world(tmp_path, token_uses=TokenUseCounter(1)) as (http, authz, audit):
        token = _token(authz)
        assert "welcome" in await _search(http, token)
        assert (await _search(http, token)).startswith("HTTP 401")
        assert "welcome" in await _search(http, _token(authz, jti="token-2"))
    reasons = _reasons(audit)
    assert reasons.count("token_call_limit_reached") == 1
    assert reasons.count("scope notes:read") == 2


async def test_batch_counts_every_call_and_is_refused_as_a_whole(tmp_path: Path) -> None:
    async with _world(tmp_path, token_uses=TokenUseCounter(1)) as (http, authz, audit):
        batch = [
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "notes.search", "arguments": {"query": "x"}},
            }
            for i in (1, 2)
        ]
        async with http() as client:
            response = await client.post(
                SERVER_A,
                json=batch,
                headers={
                    "Authorization": f"Bearer {_token(authz)}",
                    "Accept": "application/json, text/event-stream",
                },
            )
    assert response.status_code == 401
    assert "scope notes:read" not in _reasons(audit)


async def test_full_use_store_refuses_new_tokens(tmp_path: Path) -> None:
    counter = TokenUseCounter(5, max_entries=1)
    async with _world(tmp_path, token_uses=counter) as (http, authz, audit):
        assert "welcome" in await _search(http, _token(authz))
        async with http() as client:
            response = await client.post(
                SERVER_A,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "notes.search", "arguments": {"query": "x"}},
                },
                headers={
                    "Authorization": f"Bearer {_token(authz, jti='token-2')}",
                    "Accept": "application/json, text/event-stream",
                },
            )
    assert response.status_code == 503
    assert "token_use_store_full" in _reasons(audit)


# Token endpoint integration.


def _post(authz: AuthzServer, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
    with TestClient(authz.app()) as client:
        response = client.post("/token", data=form)
    return response.status_code, response.json()


def _grant(spire: LocalSvidIssuer, who: str) -> dict[str, str]:
    return {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": spire.mint(who, ISSUER),
        "resource": SERVER_A,
        "scope": "notes:read",
    }


def _authz(spire: LocalSvidIssuer, tmp_path: Path, revocations: RevocationList) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        token_exchange=True,
        revocation=revocations,
    )


def test_blocked_spiffe_id_gets_no_new_token(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    clock = Clock()
    path = tmp_path / "r.json"
    authz = _authz(spire, tmp_path, _revocations(path, clock))
    assert _post(authz, _grant(spire, READER))[0] == 200
    _write(path, blocked_spiffe_ids=[READER])
    clock.now += 5
    status, body = _post(authz, _grant(spire, READER))
    assert (status, body["error"]) == (401, "invalid_client")
    assert _post(authz, _grant(spire, RESEARCH))[0] == 200


def test_exchange_refuses_a_revoked_or_blocked_subject_token(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    clock = Clock()
    path = tmp_path / "r.json"
    authz = _authz(spire, tmp_path, _revocations(path, clock))
    status, body = _post(authz, _grant(spire, READER))
    assert status == 200
    subject = body["access_token"]
    jti = jwt.decode(subject, options={"verify_signature": False})["jti"]

    def exchange() -> tuple[int, dict[str, Any]]:
        return _post(
            authz,
            {
                **_grant(spire, RESEARCH),
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "subject_token": subject,
                "subject_token_type": ACCESS_TOKEN_TYPE,
            },
        )

    assert exchange()[0] == 200
    for lists in ({"revoked_jti": [jti]}, {"blocked_spiffe_ids": [READER]}):
        _write(path, **lists)
        clock.now += 5
        status, body = exchange()
        assert (status, body["error"]) == (400, "invalid_grant")


def test_unavailable_revocation_state_stops_issuance(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    clock = Clock()
    path = tmp_path / "r.json"
    authz = _authz(spire, tmp_path, _revocations(path, clock))
    path.write_text("{broken", encoding="utf-8")
    clock.now += 5
    status, body = _post(authz, _grant(spire, RESEARCH))
    assert (status, body["error"]) == (503, "temporarily_unavailable")
    with TestClient(authz.app()) as client:
        assert client.get("/readyz").status_code == 503
