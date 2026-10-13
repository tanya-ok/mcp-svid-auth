"""Cost bounds and planned rotation use runtime keys and synthetic signed assertions."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx2
import jwt
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import (
    _CLOCK_SKEW,
    MAX_TOKEN_REQUEST_BYTES,
    AuthzServer,
    ReplayCache,
    build_parser,
)
from mcp_svid_auth.budgets import WindowBudget
from mcp_svid_auth.mcp_server import AudienceBoundVerifier, JwksFetcher
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import INTRUDER, ISSUER, POLICY, READER, RESEARCH, SERVER_A
from tests.test_authz import _form, _post


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_window_budget_is_atomic_bounded_and_resets() -> None:
    clock = Clock()
    budget = WindowBudget(3, max_keys=2, clock=clock)
    with ThreadPoolExecutor(max_workers=8) as workers:
        assert sum(workers.map(lambda _: budget.take("a"), range(40))) == 3
    assert budget.take("b")
    assert not budget.take("c")
    assert len(budget._counts) == 2
    clock.now += 1
    assert budget.take("c")
    assert budget._counts == {"c": 1}


def test_token_global_budget_runs_before_parsing_or_signature(authz: AuthzServer) -> None:
    authz.request_budget = WindowBudget(1)
    with TestClient(authz.app()) as client:
        first = client.post("/token", content="private malformed body")
        second = client.post("/token", content="private malformed body")
    assert first.status_code == 400
    assert second.status_code == 429
    assert second.headers["retry-after"] == "1"
    assert "private" not in second.text
    assert len(authz.replay_cache) == 0


def test_token_form_has_a_streaming_byte_and_field_limit(authz: AuthzServer) -> None:
    with TestClient(authz.app()) as client:
        response = client.post(
            "/token",
            content=b"a=" + b"x" * MAX_TOKEN_REQUEST_BYTES,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        fields = client.post(
            "/token",
            content="&".join(f"k{i}=x" for i in range(17)),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 413
    assert response.json()["error_description"] == "token request too large"
    assert fields.status_code == 400


def test_authorization_precedes_replay_allocation(
    authz: AuthzServer, spire: LocalSvidIssuer
) -> None:
    assert _post(authz, _form(spire.mint(INTRUDER, ISSUER)))[0] == 400
    assert len(authz.replay_cache) == 0
    assert _post(authz, _form(spire.mint(RESEARCH, ISSUER), scope="unknown"))[0] == 400
    assert len(authz.replay_cache) == 0


def test_one_subject_cannot_consume_every_global_cache_slot(
    authz: AuthzServer, spire: LocalSvidIssuer
) -> None:
    authz.replay_cache = ReplayCache(max_entries=4, per_subject_limit=2)
    for _ in range(2):
        assert _post(authz, _form(spire.mint(RESEARCH, ISSUER)))[0] == 200
    code, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER)))
    assert code == 503 and body["error_description"] == "subject replay cache full"
    assert _post(authz, _form(spire.mint(READER, ISSUER), scope="notes:read"))[0] == 200
    assert len(authz.replay_cache) == 3
    authz.replay_cache.evict_expired(float("inf"))
    assert authz.replay_cache._subjects == {}


def test_subject_exchange_budget_applies_to_reuse_mode(
    authz: AuthzServer, spire: LocalSvidIssuer
) -> None:
    authz.svid_replay = "allow-reuse-within-lifetime"
    clock = Clock()
    authz.subject_budget = WindowBudget(1, clock=clock)
    assertion = spire.mint(RESEARCH, ISSUER)
    assert _post(authz, _form(assertion))[0] == 200
    assert _post(authz, _form(assertion))[0] == 429
    assert _post(authz, _form(spire.mint(READER, ISSUER), scope="notes:read"))[0] == 200
    clock.now += 1
    assert _post(authz, _form(assertion))[0] == 200
    assert len(authz.replay_cache) == 0


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--replay-cache-size", "0"),
        ("--replay-subject-limit", "-1"),
        ("--token-requests-per-second", "0"),
        ("--subject-requests-per-second", "0"),
        ("--signing-rotation-seconds", "59"),
        ("--signing-rotation-seconds", "-1"),
    ],
)
def test_invalid_cost_and_rotation_flags_refused(flag: str, value: str) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--issuer", ISSUER, "--policy", "p.yaml", flag, value])


def test_old_and_new_tokens_work_during_planned_overlap(
    spire: LocalSvidIssuer, tmp_path: Path
) -> None:
    clock = Clock()
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        signing_rotation_seconds=60,
        clock=clock,
        audit=AuditLog(path=tmp_path / "issuer.jsonl"),
    )
    old = _post(server, _form(spire.mint(RESEARCH, ISSUER)))[1]["access_token"]
    old_kid = jwt.get_unverified_header(old)["kid"]

    async def scenario() -> None:
        fetcher = JwksFetcher(
            ISSUER + "/jwks.json", clock=clock, transport=httpx2.ASGITransport(app=server.app())
        )
        verifier = AudienceBoundVerifier(
            ISSUER, SERVER_A, fetcher, AuditLog(path=tmp_path / "resource.jsonl")
        )
        assert await verifier.verify_token(old) is not None
        clock.now += 60
        public = server.jwks()
        assert len(public["keys"]) == 2
        assert all("d" not in key and key["alg"] == "ES256" for key in public["keys"])
        assert server.kid == old_kid
        # Fill the resource cache during prepublication, including unknown-kid refresh pressure.
        await fetcher.get()
        clock.now += 59
        assert server.kid == old_kid
        clock.now += 1
        new = _post(server, _form(spire.mint(RESEARCH, ISSUER)))[1]["access_token"]
        assert jwt.get_unverified_header(new)["kid"] != old_kid
        assert await verifier.verify_token(new) is not None
        assert await verifier.verify_token(old) is not None
        # Retired public material is bounded by the last-issue lifetime plus skew.
        clock.now += server.token_ttl + _CLOCK_SKEW + 1
        assert old_kid not in {key["kid"] for key in server.jwks()["keys"]}

    asyncio.run(scenario())


def test_retired_key_expiry_follows_the_injected_clock(
    authz: AuthzServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    authz.clock = clock
    authz.signing_rotation_seconds = 60
    authz._next_rotation = clock.now
    old_kid = authz.kid
    authz.jwks()
    clock.now += 60
    authz.jwks()
    assert authz.kid != old_kid
    monkeypatch.setattr("mcp_svid_auth.authz.time.time", lambda: 1e12)
    clock.now += authz.token_ttl + _CLOCK_SKEW - 1
    assert old_kid in {key["kid"] for key in authz.jwks()["keys"]}
    clock.now += 2
    assert old_kid not in {key["kid"] for key in authz.jwks()["keys"]}


def test_disabled_rotation_keeps_one_runtime_key(authz: AuthzServer) -> None:
    authz.signing_rotation_seconds = 0
    authz.clock = lambda: 1e9
    assert len(authz.jwks()["keys"]) == 1


def test_retired_key_memory_is_bounded_when_wall_clock_does_not_advance(
    authz: AuthzServer,
) -> None:
    clock = Clock()
    authz.clock = clock
    authz.signing_rotation_seconds = 60
    authz._next_rotation = clock.now
    last = authz.kid
    for _ in range(30):
        clock.now += 60
        public = authz.jwks()
        assert len(public["keys"]) <= 8
        assert all("d" not in key for key in public["keys"])
        last = authz.kid
    clock.now += 600
    assert len(authz.jwks()["keys"]) <= 8
    assert authz.kid == last
