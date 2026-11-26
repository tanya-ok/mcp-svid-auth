"""Allow records name the issued token; a replayed DPoP proof does not burn the SVID."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jwt
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer
from mcp_svid_auth.dpop import DPoPKey
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, RESEARCH, SERVER_A

TOKEN_URL = f"{ISSUER}/token"


def _server(tmp_path: Path, *, dpop: bool = False) -> tuple[AuthzServer, LocalSvidIssuer, Path]:
    spire = LocalSvidIssuer()
    path = tmp_path / "authz.jsonl"
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=path, component="authz"),
        dpop_required=dpop,
    )
    return server, spire, path


def _post(server: AuthzServer, assertion: str, proof: str | None = None) -> Any:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    with TestClient(server.app()) as client:
        return client.post("/token", data=form, headers={"DPoP": proof} if proof else None)


def _reasons(path: Path) -> list[str]:
    return [json.loads(line)["reason"] for line in path.read_text(encoding="utf-8").splitlines()]


def test_allow_record_names_jti_audience_expiry_and_binding(tmp_path: Path) -> None:
    server, spire, path = _server(tmp_path, dpop=True)
    response = _post(server, spire.mint(RESEARCH, ISSUER), DPoPKey().proof("POST", TOKEN_URL))
    assert response.status_code == 200
    claims = jwt.decode(response.json()["access_token"], options={"verify_signature": False})
    reason = _reasons(path)[-1]
    assert f"jti={claims['jti']}" in reason
    assert f"exp={claims['exp']}" in reason
    assert f"issued for {SERVER_A}" in reason
    assert "cnf_jkt_sha256=none" not in reason
    assert response.json()["access_token"] not in reason


def test_bearer_allow_record_marks_no_binding(tmp_path: Path) -> None:
    server, spire, path = _server(tmp_path)
    assert _post(server, spire.mint(RESEARCH, ISSUER)).status_code == 200
    assert "cnf_jkt_sha256=none" in _reasons(path)[-1]


def test_replayed_proof_does_not_consume_the_svid(tmp_path: Path) -> None:
    server, spire, _ = _server(tmp_path, dpop=True)
    key = DPoPKey()
    proof = key.proof("POST", TOKEN_URL)
    assert _post(server, spire.mint(RESEARCH, ISSUER), proof).status_code == 200
    second = spire.mint(RESEARCH, ISSUER)
    assert _post(server, second, proof).status_code == 400
    assert _post(server, second, key.proof("POST", TOKEN_URL)).status_code == 200
