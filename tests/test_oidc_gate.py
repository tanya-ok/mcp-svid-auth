from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from scripts.identity_proxy import create_proxy
from scripts.kubernetes_ui import create_app
from scripts.oidc_gate import CALLBACK, ISSUER, ROLE_CLAIM, SESSION_COOKIE, OidcGate, Settings
from scripts.zitadel_demo import (
    api_documents,
    database_documents,
    login_documents,
    network_policy,
    write_private,
)


@pytest.fixture
def identity() -> tuple[OidcGate, dict[str, Any], list[httpx2.Request]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public["kid"] = "test-key"
    changes: dict[str, Any] = {}
    requests: list[httpx2.Request] = []

    def provider(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        assert request.url.host == "localhost"
        if request.url.path == "/.well-known/openid-configuration":
            metadata = {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/oauth/v2/authorize",
                "token_endpoint": ISSUER + "/oauth/v2/token",
                "jwks_uri": ISSUER + "/oauth/v2/keys",
            }
            metadata.update(changes.get("metadata", {}))
            return httpx2.Response(200, json=metadata)
        if request.url.path == "/oauth/v2/keys":
            return httpx2.Response(200, json={"keys": changes.get("keys", [public])})
        assert request.url.path == "/oauth/v2/token"
        flow = changes["flow"]
        form = parse_qs(request.content.decode())
        assert form["code_verifier"] == [flow.verifier]
        assert form["redirect_uri"] == [CALLBACK]
        assert "authorization" not in request.headers
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": "lab-client",
            "sub": "synthetic-user",
            "iat": now,
            "exp": now + 600,
            "nonce": flow.nonce,
            "amr": ["user", "mfa"],
            "auth_time": now,
            ROLE_CLAIM: {"viewer": {"lab-org": "example.org"}},
        }
        claims.update(changes.get("claims", {}))
        for field in changes.get("omit", []):
            claims.pop(field, None)
        algorithm = changes.get("algorithm", "RS256")
        signing = secrets.token_bytes(32) if algorithm == "HS256" else key
        if changes.get("wrong_signature"):
            signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encoded = jwt.encode(
            claims,
            signing,
            algorithm=algorithm,
            headers={"kid": "test-key", **changes.get("header", {})},
        )
        return httpx2.Response(
            200, json={"id_token": encoded, "access_token": "provider-private-token"}
        )

    gate = OidcGate(
        Settings("lab-client", "lab-project", "lab-org", frozenset({"synthetic-user"})),
        transport=httpx2.MockTransport(provider),
    )
    return gate, changes, requests


def client(gate: OidcGate) -> TestClient:
    def backend(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, stream=httpx2.ByteStream(b"read-only backend"))

    return TestClient(
        create_app(
            lambda: "kubernetes-private-token",
            lambda: {"services": []},
            "private-stop-capability",
            transport=httpx2.MockTransport(backend),
            gate=gate,
        ),
        base_url="http://localhost:4466",
        follow_redirects=False,
    )


def begin(gate: OidcGate, changes: dict[str, Any], browser: TestClient) -> str:
    response = browser.get("/_auth/login")
    assert response.status_code == 303
    query = parse_qs(urlsplit(response.headers["location"]).query)
    state = query["state"][0]
    changes["flow"] = gate.flows[state]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(gate.flows[state].verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert query["code_challenge"] == [challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["max_age"] == ["0"]
    assert "httponly" in response.headers["set-cookie"].lower()
    return state


def complete(browser: TestClient, state: str) -> Any:
    return browser.get(
        "/_auth/callback", params={"state": state, "code": "test-authorization-code"}
    )


def test_viewer_gets_only_opaque_bounded_session(identity: Any) -> None:
    gate, changes, requests = identity
    with client(gate) as browser:
        assert browser.get("/_lab/snapshot").status_code == 401
        assert "Continue with ZITADEL" in browser.get("/").text
        state = begin(gate, changes, browser)
        response = complete(browser, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/c/main/security-lab"
        navigation = {
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        }
        assert browser.get("/c/main/security-lab", headers=navigation).status_code == 200
        assert browser.get("/_lab/snapshot", headers=navigation).status_code == 403
        assert (
            browser.get(
                "/c/main/security-lab", headers={**navigation, "Sec-Fetch-Dest": "iframe"}
            ).status_code
            == 403
        )
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie and "max-age=300" in cookie
        session_value = browser.cookies.get(SESSION_COOKIE)
        assert session_value is not None and len(session_value) == 43 and "." not in session_value
        assert "private-token" not in cookie
        snapshot = browser.get("/_lab/snapshot")
        assert snapshot.json()["viewer"] == {"provider": "ZITADEL", "role": "viewer"}
        assert "private-token" not in snapshot.text
        assert (
            browser.get("/clusters/main/api/v1/namespaces/security-lab/secrets").status_code == 403
        )
        assert browser.post("/clusters/main/api/v1/namespaces/security-lab/pods").status_code == 405
        count = len(requests)
        assert complete(browser, state).status_code == 403
        assert len(requests) == count


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://example.org"},
        {"aud": "another-client"},
        {"aud": ["lab-client", "another-client"]},
        {"aud": ["lab-client", "lab-project"]},
        {"aud": ["lab-client", "lab-project"], "azp": "another-client"},
        {"azp": "another-client"},
        {"nonce": "another-nonce"},
        {"exp": 1},
        {"iat": int(time.time()) + 1000},
        {"exp": int(time.time()) + 7200},
        {ROLE_CLAIM: {}},
        {ROLE_CLAIM: {"viewer": {"another-org": "example.org"}}},
        {ROLE_CLAIM: {"viewer": "lab-org"}},
        {"sub": []},
        {"sub": "unapproved-user"},
        {"amr": ["pwd", "mfa"]},
        {"amr": ["pwd", "user", "mfa"]},
        {"amr": ["otp", "mfa"]},
        {"amr": ["user"]},
        {"amr": []},
        {"auth_time": int(time.time()) - 301},
        {"auth_time": True},
    ],
)
def test_invalid_identity_or_role_never_creates_session(
    identity: Any, claims: dict[str, Any]
) -> None:
    gate, changes, _ = identity
    changes["claims"] = claims
    with client(gate) as browser:
        state = begin(gate, changes, browser)
        assert complete(browser, state).json() == {"error": "login_denied"}
        assert not gate.sessions
        assert browser.get("/_lab/snapshot").status_code == 401


def test_provider_project_audience_requires_the_exact_authorized_client(identity: Any) -> None:
    gate, changes, _ = identity
    changes["claims"] = {"aud": ["lab-project", "lab-client"], "azp": "lab-client"}
    with client(gate) as browser:
        state = begin(gate, changes, browser)
        assert complete(browser, state).status_code == 303
        assert browser.get("/_lab/snapshot").status_code == 200


@pytest.mark.parametrize(
    "changes",
    [
        {"omit": ["iat"]},
        {"omit": ["exp"]},
        {"omit": ["nonce"]},
        {"omit": ["iss"]},
        {"omit": ["aud"]},
        {"omit": ["sub"]},
        {"omit": ["amr"]},
        {"omit": ["auth_time"]},
        {"wrong_signature": True},
        {"algorithm": "HS256"},
        {"header": {"crit": ["unknown"]}},
        {"header": {"kid": "unknown"}},
        {"keys": []},
    ],
)
def test_missing_claims_and_untrusted_crypto_fail_closed(
    identity: Any, changes: dict[str, Any]
) -> None:
    gate, settings, _ = identity
    settings.update(changes)
    with client(gate) as browser:
        state = begin(gate, settings, browser)
        response = complete(browser, state)
        assert response.status_code == 403
        assert response.json() == {"error": "login_denied"}
        assert not gate.sessions


def test_discovery_cannot_redirect_credential_exchange(identity: Any) -> None:
    gate, changes, requests = identity
    changes["metadata"] = {"token_endpoint": "https://example.org/collect"}
    with client(gate) as browser:
        assert browser.get("/_auth/login").status_code == 503
    assert len(requests) == 1
    assert not gate.flows


def test_wrong_state_and_expired_flow_do_not_exchange_code(identity: Any) -> None:
    gate, changes, requests = identity
    with client(gate) as browser:
        state = begin(gate, changes, browser)
        count = len(requests)
        assert complete(browser, "wrong-state").status_code == 403
        assert len(requests) == count
        gate.clock = lambda: time.time() + 121
        assert complete(browser, state).status_code == 403
        assert len(requests) == count


def test_expiry_and_logout_remove_panel_access(identity: Any) -> None:
    gate, changes, _ = identity
    with client(gate) as browser:
        state = begin(gate, changes, browser)
        assert complete(browser, state).status_code == 303
        assert browser.get("/_auth/logout").status_code == 403
        assert browser.post("/_auth/logout").status_code == 303
        assert browser.get("/_lab/snapshot").status_code == 401
        state = begin(gate, changes, browser)
        assert complete(browser, state).status_code == 303
        gate.clock = lambda: time.time() + 301
        assert browser.get("/_lab/snapshot").status_code == 401
        assert not gate.sessions


def test_callback_accepts_only_the_fixed_local_navigation(identity: Any) -> None:
    gate, changes, _ = identity
    with client(gate) as browser:
        state = begin(gate, changes, browser)
        assert (
            browser.get(
                "/_auth/callback",
                params={"state": state, "code": "test"},
                headers={"origin": "http://127.0.0.1:4467"},
            ).status_code
            == 403
        )
        assert (
            browser.get(
                "/_auth/callback",
                params={"state": state, "code": "test"},
                headers={"sec-fetch-site": "same-site"},
            ).status_code
            == 303
        )


@pytest.mark.parametrize(
    "path", ["/management/v1/projects", "/v2/users", "/ui/console", "/debug/metrics"]
)
def test_identity_proxy_never_exposes_management(path: str) -> None:
    def forbidden(_: httpx2.Request) -> httpx2.Response:
        pytest.fail("Management must not reach the provider")

    with TestClient(
        create_proxy(transport=httpx2.MockTransport(forbidden)), base_url=ISSUER
    ) as browser:
        assert browser.get(path).status_code == 403


def test_identity_proxy_strips_panel_cookies_and_incoming_credentials() -> None:
    def backend(request: httpx2.Request) -> httpx2.Response:
        assert "authorization" not in request.headers
        assert "x-forwarded-id-token" not in request.headers
        assert request.headers["host"] == "localhost:4467"
        assert request.headers["cookie"] == "provider-session=opaque"
        return httpx2.Response(
            200,
            stream=httpx2.ByteStream(b"ready"),
            headers=[
                ("set-cookie", "provider-session=changed; HttpOnly"),
                ("set-cookie", SESSION_COOKIE + "=injected"),
                ("set-cookie", "sessions=local-signed; HttpOnly; SameSite=Lax; Secure"),
                ("x-action-redirect", "/ui/v2/login/continue;push"),
            ],
        )

    with TestClient(
        create_proxy(transport=httpx2.MockTransport(backend)), base_url=ISSUER
    ) as browser:
        response = browser.get(
            "/ui/v2/login/healthy",
            headers={
                "Cookie": SESSION_COOKIE
                + "=panel-opaque; lab_oidc_flow=flow; provider-session=opaque",
                "Authorization": "Bearer private",
                "X-Forwarded-Id-Token": "private",
            },
        )
        assert response.status_code == 200
        assert SESSION_COOKIE not in response.headers["set-cookie"]
        assert "httponly" in response.headers["set-cookie"].lower()
        assert response.headers["x-action-redirect"] == "/ui/v2/login/continue;push"
        session = next(
            value
            for value in response.headers.get_list("set-cookie")
            if value.startswith("sessions=")
        )
        assert "secure" in session.lower()
        assert "httponly" in session.lower() and "samesite=lax" in session.lower()


def test_identity_manifests_keep_secrets_and_ports_private(tmp_path: Any) -> None:
    documents = database_documents() + api_documents("2030-01-01T00:00:00Z") + login_documents()
    for document in documents:
        if document["kind"] == "Service":
            assert document["spec"].get("type", "ClusterIP") == "ClusterIP"
        if document["kind"] == "Deployment":
            pod = document["spec"]["template"]["spec"]
            assert pod["automountServiceAccountToken"] is False
            assert pod["enableServiceLinks"] is False
            for item in pod["containers"]:
                assert "@sha256:" in item["image"]
                assert item["securityContext"]["readOnlyRootFilesystem"] is True
                assert item["securityContext"]["capabilities"]["drop"] == ["ALL"]
                assert not item.get("ports")
    assert network_policy()["spec"]["policyTypes"] == ["Ingress", "Egress"]
    path = tmp_path / "runtime.json"
    path.write_text("old")
    path.chmod(0o666)
    write_private(path, {"test": "synthetic"})
    assert path.stat().st_mode & 0o077 == 0


def test_login_uses_approved_organization_policy(identity: Any) -> None:
    gate, _, _ = identity
    with client(gate) as browser:
        response = browser.get("/_auth/login")
        scope = parse_qs(urlsplit(response.headers["location"]).query)["scope"][0]
        assert "urn:zitadel:iam:org:id:lab-org" in scope.split()


def test_ip_navigation_redirects_before_creating_login_state(identity: Any) -> None:
    gate, _, requests = identity
    with client(gate) as browser:
        response = browser.get("http://127.0.0.1:4466/_auth/login")
        assert response.status_code == 303
        assert response.headers["location"] == "http://localhost:4466/_auth/login"
        assert "set-cookie" not in response.headers
        assert not gate.flows and not requests
        assert browser.get("http://127.0.0.1:4466/_lab/session").status_code == 403


@pytest.mark.parametrize("subjects", [None, [], "synthetic-user", [True], ["bad subject"]])
def test_configuration_requires_explicit_valid_approval(subjects: Any) -> None:
    with pytest.raises(ValueError):
        Settings.parse(
            {
                "client_id": "lab-client",
                "project_id": "lab-project",
                "org_id": "lab-org",
                "approved_subjects": subjects,
            }
        )


def test_cross_site_google_return_only_exposes_provider_callback() -> None:
    captured: list[httpx2.Request] = []

    def backend(request: httpx2.Request) -> httpx2.Response:
        captured.append(request)
        return httpx2.Response(200, stream=httpx2.ByteStream(b"provider-owned callback"))

    app = create_proxy(transport=httpx2.MockTransport(backend))
    with TestClient(app, base_url="http://localhost:4467") as browser:
        headers = {"Sec-Fetch-Site": "cross-site"}
        assert browser.get("/idps/callback?state=test", headers=headers).status_code == 200
        assert browser.post("/idps/callback", headers=headers).status_code == 403
        assert browser.get("/ui/v2/login", headers=headers).status_code == 403
        assert len(captured) == 1
        assert captured[0].url.path == "/idps/callback"
