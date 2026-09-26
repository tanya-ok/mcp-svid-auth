from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer, StaticJwksResolver
from tests.conftest import INTRUDER, ISSUER, READER, RESEARCH, SERVER_A, SERVER_B


def _form(assertion: str, **extra: str) -> dict[str, str]:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "resource": SERVER_A,
    }
    form.update(extra)
    return {k: v for k, v in form.items() if v != ""}


def _post(authz: AuthzServer, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
    with TestClient(authz.app()) as client:
        response = client.post("/token", data=form)
    return response.status_code, response.json()


def test_valid_flow_issues_audience_bound_token(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), client_id=RESEARCH))
    assert status == 200, body
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 300
    claims = jwt.decode(
        body["access_token"],
        jwt.PyJWKSet.from_dict(authz.jwks()).keys[0].key,
        algorithms=["ES256"],
        audience=SERVER_A,
        issuer=ISSUER,
    )
    assert claims["sub"] == RESEARCH
    assert claims["client_id"] == RESEARCH
    assert claims["aud"] == SERVER_A
    assert set(claims["scope"].split()) == {"notes:read", "notes:write"}
    assert claims["exp"] - claims["iat"] == 300
    assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+jwt"


def test_requested_scope_is_narrowed(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), scope="notes:read"))
    assert status == 200
    assert body["scope"] == "notes:read"


def test_scope_beyond_policy_is_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(
        authz, _form(spire.mint(RESEARCH, ISSUER), resource=SERVER_B, scope="notes:write")
    )
    assert (status, body["error"]) == (400, "invalid_scope")


def test_spiffe_id_not_allowlisted(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(INTRUDER, ISSUER)))
    assert (status, body["error"]) == (400, "unauthorized_client")


def test_resource_not_allowed_for_client(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(READER, ISSUER), resource=SERVER_B))
    assert (status, body["error"]) == (400, "invalid_target")


def test_wrong_svid_audience(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, SERVER_A)))
    assert (status, body["error"]) == (401, "invalid_client")
    assert "audience" in body["error_description"]


def test_svid_with_extra_audience_is_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, [ISSUER, SERVER_A])))
    assert (status, body["error"]) == (401, "invalid_client")


def test_expired_svid(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    now = int(time.time())
    expired = spire.mint(RESEARCH, ISSUER, iat=now - 600, exp=now - 300)
    status, body = _post(authz, _form(expired))
    assert (status, body["error"]) == (401, "invalid_client")
    assert "expired" in body["error_description"]


def test_svid_signed_by_unknown_key(authz: AuthzServer) -> None:
    rogue = LocalSvidIssuer()
    status, body = _post(authz, _form(rogue.mint(RESEARCH, ISSUER)))
    assert (status, body["error"]) == (401, "invalid_client")


def test_svid_signed_by_wrong_key_with_known_kid(
    authz: AuthzServer, spire: LocalSvidIssuer
) -> None:
    rogue = LocalSvidIssuer(kid=spire.kid)
    status, body = _post(authz, _form(rogue.mint(RESEARCH, ISSUER)))
    assert (status, body["error"]) == (401, "invalid_client")


def test_foreign_trust_domain(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint("spiffe://other.test/agent/x", ISSUER)))
    assert (status, body["error"]) == (401, "invalid_client")


def test_missing_resource(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), resource=""))
    assert (status, body["error"]) == (400, "invalid_target")


def test_client_id_must_match_svid(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), client_id=READER))
    assert (status, body["error"]) == (401, "invalid_client")


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("grant_type", "authorization_code", "unsupported_grant_type"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "invalid_client",
        ),
    ],
)
def test_protocol_errors(
    authz: AuthzServer, spire: LocalSvidIssuer, field: str, value: str, error: str
) -> None:
    _, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), **{field: value}))
    assert body["error"] == error


def test_unsigned_assertion_rejected(authz: AuthzServer) -> None:
    unsigned = jwt.encode(
        {"sub": RESEARCH, "aud": ISSUER, "exp": int(time.time()) + 60},
        None,  # type: ignore[arg-type]
        algorithm="none",
    )
    status, body = _post(authz, _form(unsigned))
    assert (status, body["error"]) == (401, "invalid_client")


def test_metadata_and_jwks(authz: AuthzServer) -> None:
    with TestClient(authz.app()) as client:
        meta = client.get("/.well-known/oauth-authorization-server").json()
        jwks = client.get("/jwks.json").json()
    assert meta["issuer"] == ISSUER
    assert meta["token_endpoint"] == f"{ISSUER}/token"
    assert "spiffe_jwt" in meta["token_endpoint_auth_methods_supported"]
    assert jwks["keys"][0]["kid"] == authz.kid
    assert "d" not in jwks["keys"][0]


def test_authz_audit_lines(authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path) -> None:
    _post(authz, _form(spire.mint(RESEARCH, ISSUER)))
    _post(authz, _form(spire.mint(INTRUDER, ISSUER)))
    assert authz.audit.path is not None
    lines = authz.audit.path.read_text(encoding="utf-8").splitlines()
    assert '"decision":"allow"' in lines[0]
    assert f'"spiffe_id":"unverified:{INTRUDER}"' in lines[1]


def test_static_jwks_file_mode(tmp_path: Path, spire: LocalSvidIssuer) -> None:
    import json  # noqa: PLC0415

    path = tmp_path / "bundle.jwks"
    path.write_text(json.dumps(spire.jwks()), encoding="utf-8")
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict({"trust_domain": "example.org", "clients": []}),
        resolver=StaticJwksResolver.from_file("example.org", path),
    )
    assert server.verify_svid(spire.mint(RESEARCH, ISSUER)) == RESEARCH
