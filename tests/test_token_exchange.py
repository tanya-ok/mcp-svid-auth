"""RFC 8693 on-behalf-of exchange: never wider than subject or actor, never outlives the subject."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import (
    ACCESS_TOKEN_TYPE,
    CLIENT_ASSERTION_TYPE,
    TOKEN_EXCHANGE_GRANT,
    AuthzServer,
)
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, READER, RESEARCH, SERVER_A, SERVER_B


@pytest.fixture
def exchanger(spire: LocalSvidIssuer, tmp_path: Path) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        token_exchange=True,
    )


def _post(authz: AuthzServer, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
    with TestClient(authz.app()) as client:
        response = client.post("/token", data=form)
    return response.status_code, response.json()


def _token(authz: AuthzServer, spire: LocalSvidIssuer, who: str, resource: str, scope: str) -> str:
    status, body = _post(
        authz,
        {
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": spire.mint(who, ISSUER),
            "resource": resource,
            "scope": scope,
        },
    )
    assert status == 200, body
    return str(body["access_token"])


def _exchange(
    authz: AuthzServer, spire: LocalSvidIssuer, actor: str, subject_token: str, **extra: str
) -> tuple[int, dict[str, Any]]:
    form = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": spire.mint(actor, ISSUER),
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    form.update(extra)
    return _post(authz, {k: v for k, v in form.items() if v != ""})


def _claims(authz: AuthzServer, token: str) -> dict[str, Any]:
    keys = jwt.PyJWKSet.from_dict(authz.jwks()).keys
    decoded: dict[str, Any] = jwt.decode(
        token, keys[0].key, algorithms=["ES256"], audience=SERVER_A, issuer=ISSUER
    )
    return decoded


def test_exchange_is_off_by_default(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    subject = _token(authz, spire, RESEARCH, SERVER_A, "notes:read")
    status, body = _exchange(authz, spire, READER, subject)
    assert (status, body["error"]) == (400, "unsupported_grant_type")
    assert TOKEN_EXCHANGE_GRANT not in authz.metadata()["grant_types_supported"]


def test_narrowed_on_behalf_of_token(exchanger: AuthzServer, spire: LocalSvidIssuer) -> None:
    subject = _token(exchanger, spire, RESEARCH, SERVER_A, "notes:read notes:write")
    status, body = _exchange(exchanger, spire, READER, subject)
    assert status == 200, body
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
    claims = _claims(exchanger, body["access_token"])
    original = _claims(exchanger, subject)
    assert claims["sub"] == RESEARCH
    assert claims["act"] == {"sub": READER}
    assert claims["client_id"] == READER
    assert claims["aud"] == SERVER_A
    assert claims["scope"] == "notes:read"
    assert claims["exp"] <= original["exp"]
    assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+jwt"
    assert TOKEN_EXCHANGE_GRANT in exchanger.metadata()["grant_types_supported"]


def test_actor_cannot_gain_scope_it_lacks(exchanger: AuthzServer, spire: LocalSvidIssuer) -> None:
    subject = _token(exchanger, spire, RESEARCH, SERVER_A, "notes:read notes:write")
    status, body = _exchange(exchanger, spire, READER, subject, scope="notes:write")
    assert (status, body["error"]) == (400, "invalid_scope")


def test_subject_scope_bounds_the_actor(exchanger: AuthzServer, spire: LocalSvidIssuer) -> None:
    subject = _token(exchanger, spire, READER, SERVER_A, "notes:read")
    status, body = _exchange(exchanger, spire, RESEARCH, subject, scope="notes:write")
    assert (status, body["error"]) == (400, "invalid_scope")


def test_chained_delegation_is_refused(exchanger: AuthzServer, spire: LocalSvidIssuer) -> None:
    subject = _token(exchanger, spire, RESEARCH, SERVER_A, "notes:read")
    _, first = _exchange(exchanger, spire, READER, subject)
    status, body = _exchange(exchanger, spire, RESEARCH, first["access_token"])
    assert (status, body["error"]) == (400, "invalid_request")


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("audience", "invalid_target"),
        ("same_party", "invalid_request"),
        ("token_type", "invalid_request"),
        ("actor_token", "invalid_request"),
        ("empty_scope", "invalid_scope"),
        ("garbage", "invalid_grant"),
        ("foreign_key", "invalid_grant"),
    ],
)
def test_malformed_or_foreign_exchange_is_denied(
    exchanger: AuthzServer, spire: LocalSvidIssuer, case: str, error: str
) -> None:
    subject = _token(exchanger, spire, RESEARCH, SERVER_A, "notes:read")
    actor, extra = READER, {}
    if case == "audience":
        subject = _token(exchanger, spire, RESEARCH, SERVER_B, "notes:read")
    elif case == "same_party":
        actor = RESEARCH
    elif case == "token_type":
        extra = {"subject_token_type": "urn:ietf:params:oauth:token-type:jwt"}
    elif case == "actor_token":
        extra = {"actor_token": "x"}
    elif case == "empty_scope":
        extra = {"scope": ""}
    elif case == "garbage":
        subject = "not-a-token"
    elif case == "foreign_key":
        claims = _claims(exchanger, subject)
        subject = jwt.encode(
            claims,
            ec.generate_private_key(ec.SECP256R1()),
            algorithm="ES256",
            headers={"kid": exchanger.kid, "typ": "at+jwt"},
        )
    status, body = _exchange(exchanger, spire, actor, subject, **extra)
    assert (status, body["error"]) == (400, error)
    assert "access_token" not in body
