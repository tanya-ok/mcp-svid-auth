"""Metrics: bounded reason labels, decision counters and dependency gauges."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.agent_client import call_tool
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer
from mcp_svid_auth.budgets import WindowBudget
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.metrics import Metrics, classify
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.revocation import RevocationList
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import DEV_URLS, ISSUER, POLICY, RESEARCH, SERVER_A, HostRouter

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize(
    ("decision", "reason", "label"),
    [
        ("deny", "invalid_client: client assertion replayed (jti_sha256=ab)", "replay"),
        ("deny", "temporarily_unavailable: request budget exceeded", "rate_limited"),
        ("deny", "verification_budget_exceeded", "rate_limited"),
        ("deny", "token_call_limit_reached", "rate_limited"),
        ("deny", "jwks_unavailable", "jwks_unavailable"),
        ("deny", "revoked_token", "revoked"),
        ("deny", "blocked_spiffe_id", "revoked"),
        ("deny", "revocation_unavailable", "revocation_unavailable"),
        (
            "deny",
            "temporarily_unavailable: replay store unavailable",
            "store_unavailable",
        ),
        ("deny", "invalid_dpop_proof: proof_replay_store_unavailable", "store_unavailable"),
        ("deny", "insufficient_scope: needs notes:write", "insufficient_scope"),
        ("allow", "issued for http://x scope=a jti=1", "allowed"),
        ("deny", "unauthorized_client: spiffe://example.org/agent/x", "unauthorized_client"),
        ("deny", "spiffe://example.org/free text", "other"),
    ],
)
def test_reason_labels_come_from_a_fixed_vocabulary(decision: str, reason: str, label: str) -> None:
    assert classify(decision, reason) == label


def _post(server: AuthzServer, assertion: str) -> int:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    with TestClient(server.app()) as client:
        return client.post("/token", data=form).status_code


def test_authz_metrics_count_replays_rate_limits_and_report_dependencies(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    metrics = Metrics()
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz", metrics=metrics),
        metrics=metrics,
        request_budget=WindowBudget(3, max_keys=1, clock=lambda: 1.0),
    )
    assertion = spire.mint(RESEARCH, ISSUER)
    assert [_post(server, assertion) for _ in range(2)] == [200, 401]
    assert _post(server, spire.mint(RESEARCH, ISSUER)) == 200
    assert _post(server, spire.mint(RESEARCH, ISSUER)) == 429
    with TestClient(server.app()) as client:
        response = client.get("/metrics")
    text = response.text
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert 'component="authz",decision="allow",reason="allowed"} 2' in text
    assert 'decision="deny",reason="replay"} 1' in text
    assert 'decision="deny",reason="rate_limited"} 1' in text
    assert 'mcp_svid_dependency_up{dependency="policy"} 1' in text
    assert 'mcp_svid_dependency_up{dependency="trust_bundle"} 1' in text
    assert "spiffe://" not in text


def test_metrics_endpoint_is_off_by_default() -> None:
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=LocalSvidIssuer().resolver(),
        audit=AuditLog(),
    )
    with TestClient(server.app()) as client:
        assert client.get("/metrics").status_code == 404


async def test_mcp_metrics_count_revocations_and_report_jwks(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    authz = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(),
    )
    revoked = tmp_path / "revoked.json"
    revoked.write_text(
        json.dumps({"revoked_jti": ["gone"], "blocked_spiffe_ids": []}), encoding="utf-8"
    )
    metrics = Metrics()
    app = create_app(
        name="a",
        resource=SERVER_A,
        issuer=ISSUER,
        jwks=authz.jwks,
        audit=AuditLog(path=tmp_path / "mcp.jsonl"),
        revocation=RevocationList.load(revoked),
        metrics=metrics,
    )
    router = HostRouter({"authz.test": authz.app(), "notes-a.test": app})

    def http(**kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=router), **kwargs)

    now = int(time.time())
    token = jwt.encode(
        {
            **{"iss": ISSUER, "sub": RESEARCH, "aud": SERVER_A, "scope": "notes:read"},
            **{"iat": now, "exp": now + 60, "jti": "gone"},
        },
        authz.signing_key,
        algorithm="ES256",
        headers={"kid": authz.kid, "typ": "at+jwt"},
    )
    async with app.router.lifespan_context(app):
        outcome = await call_tool(
            SERVER_A, token, "notes.search", {"query": "x"}, http=http, url_policy=DEV_URLS
        )
        async with http() as client:
            text = (await client.get("http://notes-a.test/metrics")).text
    assert outcome.startswith("HTTP 401")
    assert 'component="mcp_server",decision="deny",reason="revoked"}' in text
    assert 'mcp_svid_dependency_up{dependency="jwks"} 1' in text
    assert 'mcp_svid_dependency_up{dependency="revocation"} 1' in text
