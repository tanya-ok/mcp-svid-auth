"""Token endpoint hardening: SVID lifetime, scope parsing, repeated parameters, error text."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient

from mcp_svid_auth.authz import AuthzServer
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, RESEARCH
from tests.test_authz import _form, _post


def _audit_reasons(authz: AuthzServer) -> list[str]:
    assert authz.audit.path is not None
    import json  # noqa: PLC0415

    lines = authz.audit.path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["reason"] for line in lines]


def test_svid_without_iat_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    svid = spire.mint(RESEARCH, ISSUER, iat=None)
    status, body = _post(authz, _form(svid))
    assert (status, body["error"]) == (401, "invalid_client")


def test_svid_lifetime_above_max_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    svid = spire.mint(RESEARCH, ISSUER, ttl=3600)
    status, body = _post(authz, _form(svid))
    assert (status, body["error"]) == (401, "invalid_client")
    assert body["error_description"] == "client assertion lifetime too long"
    assert "exp - iat = 3600s, max 300s" in _audit_reasons(authz)[0]


def test_svid_lifetime_at_max_accepted(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, _ = _post(authz, _form(spire.mint(RESEARCH, ISSUER, ttl=300)))
    assert status == 200


def test_max_svid_lifetime_is_configurable(spire: LocalSvidIssuer) -> None:
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        max_svid_lifetime=60,
    )
    status, _ = _post(server, _form(spire.mint(RESEARCH, ISSUER, ttl=120)))
    assert status == 401


def test_error_description_does_not_echo_exception_text(
    authz: AuthzServer, spire: LocalSvidIssuer
) -> None:
    # Future iat makes PyJWT raise ImmatureSignatureError with its own message.
    now = int(time.time())
    svid = spire.mint(RESEARCH, ISSUER, iat=now + 3600, exp=now + 3700)
    status, body = _post(authz, _form(svid))
    assert status == 401
    assert body["error_description"] == "client assertion invalid"
    assert "ImmatureSignatureError" in _audit_reasons(authz)[0]


def test_bundle_lookup_failure_is_503_without_detail(spire: LocalSvidIssuer) -> None:
    class Broken:
        def resolve(self, trust_domain: str, kid: str | None) -> Any:
            raise OSError("socket /secret/path missing")

    server = AuthzServer(issuer=ISSUER, policy=Policy.from_dict(POLICY), resolver=Broken())
    status, body = _post(server, _form(spire.mint(RESEARCH, ISSUER)))
    assert (status, body["error"]) == (503, "temporarily_unavailable")
    assert "secret" not in body["error_description"]


def test_scope_is_required(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), scope=""))
    assert (status, body["error"]) == (400, "invalid_scope")
    assert body["error_description"] == "scope parameter is required"


@pytest.mark.parametrize(
    "scope",
    ["notes:read  notes:write", " notes:read", "notes:read ", "notes:read\tnotes:write"],
)
def test_scope_split_on_single_space_only(
    authz: AuthzServer, spire: LocalSvidIssuer, scope: str
) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER), scope=scope))
    assert (status, body["error"]) == (400, "invalid_scope")


def test_repeated_parameter_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    form = list(_form(spire.mint(RESEARCH, ISSUER)).items())
    form.append(("resource", "http://notes-b.test/mcp"))
    body = urlencode(form)
    with TestClient(authz.app()) as client:
        response = client.post(
            "/token",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_repeated_parameter_audited(
    authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
) -> None:
    form = [*_form(spire.mint(RESEARCH, ISSUER)).items(), ("scope", "notes:read")]
    body = urlencode(form)
    with TestClient(authz.app()) as client:
        client.post(
            "/token",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert _audit_reasons(authz)[0] == "invalid_request: repeated request parameter"
