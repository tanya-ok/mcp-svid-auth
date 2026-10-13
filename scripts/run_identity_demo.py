"""Real WebAuthn and OIDC exchanges with an ephemeral synthetic authenticator."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2

from scripts import zitadel_demo as identity
from scripts.lab_runtime import DemoRuntimeError
from scripts.oidc_gate import CALLBACK, ISSUER, PANEL_ORIGIN, SESSION_COOKIE

VIEWER = PANEL_ORIGIN
REPORT = identity.DATA / "identity-demo-report.json"


def require(condition: bool) -> None:
    if not condition:
        raise DemoRuntimeError("Human identity acceptance check failed")


class WebAuthnBrowser:
    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process

    def read(self) -> dict[str, Any]:
        if self.process.stdout is None:
            raise DemoRuntimeError("WebAuthn browser unavailable")
        with selectors.DefaultSelector() as ready:
            ready.register(self.process.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=45):
                raise DemoRuntimeError("WebAuthn browser unavailable")
        result: Any = json.loads(self.process.stdout.readline(1048576))
        if not isinstance(result, dict) or "error" in result:
            raise DemoRuntimeError("WebAuthn browser unavailable")
        return result

    def set_verified(self, verified: bool) -> None:
        if self.process.stdin is None:
            raise DemoRuntimeError("WebAuthn browser unavailable")
        self.process.stdin.write(
            json.dumps({"operation": "verification", "verified": verified}) + "\n"
        )
        self.process.stdin.flush()
        require(self.read().get("updated") is True)

    def credential(self, operation: str, options: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None:
            raise DemoRuntimeError("WebAuthn browser unavailable")
        self.process.stdin.write(json.dumps({"operation": operation, "options": options}) + "\n")
        self.process.stdin.flush()
        result = self.read().get("credential")
        if not isinstance(result, dict):
            raise DemoRuntimeError("WebAuthn browser unavailable")
        return result


@contextmanager
def virtual_authenticator() -> Iterator[WebAuthnBrowser]:
    executable = os.environ.get("PLAYWRIGHT_NODE_PATH") or shutil.which("node")
    if not executable:
        raise DemoRuntimeError("WebAuthn browser unavailable")
    process = subprocess.Popen(  # noqa: S603 - owned test helper, no shell or bearer argument
        [executable, str(Path(__file__).with_name("webauthn_test_browser.cjs"))],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        browser = WebAuthnBrowser(process)
        require(browser.read().get("ready") is True)
        yield browser
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


def register_passkey(
    provider: identity.Bootstrap, account: dict[str, Any], authenticator: WebAuthnBrowser
) -> None:
    user_id = account["user_id"]
    registration = provider.call("/v2/users/" + user_id + "/passkeys", {"domain": "localhost"})
    options = registration["publicKeyCredentialCreationOptions"]["publicKey"]
    require(options["authenticatorSelection"]["userVerification"] == "required")
    credential = authenticator.credential("register", options)
    provider.call(
        "/v2/users/" + user_id + "/passkeys/" + registration["passkeyId"],
        {"publicKeyCredential": credential, "passkeyName": "Ephemeral acceptance authenticator"},
    )


def challenge_session(provider: identity.Bootstrap, account: dict[str, Any]) -> dict[str, Any]:
    return provider.call(
        "/v2/sessions",
        {
            "checks": {
                "user": {"userId": account["user_id"]},
            },
            "challenges": {
                "webAuthN": {
                    "domain": "localhost",
                    "userVerificationRequirement": "USER_VERIFICATION_REQUIREMENT_REQUIRED",
                }
            },
            "lifetime": "300s",
        },
    )


def authenticate(
    browser: httpx2.Client,
    provider: identity.Bootstrap,
    account: dict[str, Any],
    authenticator: WebAuthnBrowser,
) -> httpx2.Response:
    login = browser.get(VIEWER + "/_auth/login")
    require(login.status_code == 303)
    authorization = login.headers["location"]
    parsed = urlsplit(authorization)
    require(parsed._replace(query="", fragment="").geturl() == ISSUER + "/oauth/v2/authorize")
    request = browser.get(authorization)
    require(request.status_code == 302)
    request_id = parse_qs(urlsplit(request.headers["location"]).query)["authRequest"][0]
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id) is not None)
    session = challenge_session(provider, account)
    try:
        options = session["challenges"]["webAuthN"]["publicKeyCredentialRequestOptions"][
            "publicKey"
        ]
        require(options["userVerification"] == "required")
        assertion = authenticator.credential("authenticate", options)
        updated = provider.call(
            "/v2/sessions/" + session["sessionId"],
            {
                "sessionToken": session["sessionToken"],
                "checks": {"webAuthN": {"credentialAssertionData": assertion}},
            },
            method="PATCH",
        )
        session["sessionToken"] = updated["sessionToken"]
        callback = provider.call(
            "/v2/oidc/auth_requests/" + request_id,
            {
                "session": {
                    "sessionId": session["sessionId"],
                    "sessionToken": session["sessionToken"],
                }
            },
        )["callbackUrl"]
        require(urlsplit(callback)._replace(query="", fragment="").geturl() == CALLBACK)
        return browser.get(callback)
    finally:
        provider.call(
            "/v2/sessions/" + session["sessionId"],
            {"sessionToken": session["sessionToken"]},
            method="DELETE",
        )


def require_rejected_check(response: httpx2.Response) -> None:
    value = response.json()
    # ZITADEL 4.19.4 reports WebAuthn validation failure as HTTP 500 / RPC INTERNAL.
    # A successful verified check immediately afterward distinguishes this from an outage.
    require(
        response.status_code in {400, 403, 500}
        and isinstance(value, dict)
        and type(value.get("code")) is int
        and value["code"] in {3, 7, 13}
        and "sessionToken" not in value
    )


def reject_unverified_or_replayed_assertion(
    provider: identity.Bootstrap, account: dict[str, Any], authenticator: WebAuthnBrowser
) -> None:
    session = challenge_session(provider, account)
    second: dict[str, Any] | None = None
    try:
        options = session["challenges"]["webAuthN"]["publicKeyCredentialRequestOptions"][
            "publicKey"
        ]
        require(options["userVerification"] == "required")
        authenticator.set_verified(False)
        # Deliberately downgrade only the browser request. The server challenge remains required.
        assertion = authenticator.credential(
            "authenticate", {**options, "userVerification": "discouraged"}
        )
        encoded = assertion["response"]["authenticatorData"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        require(len(raw) >= 37 and not raw[32] & 4)
        response = provider.client.patch(
            "/v2/sessions/" + session["sessionId"],
            json={
                "sessionToken": session["sessionToken"],
                "checks": {"webAuthN": {"credentialAssertionData": assertion}},
            },
        )
        require_rejected_check(response)
        authenticator.set_verified(True)
        assertion = authenticator.credential("authenticate", options)
        updated = provider.call(
            "/v2/sessions/" + session["sessionId"],
            {
                "sessionToken": session["sessionToken"],
                "checks": {"webAuthN": {"credentialAssertionData": assertion}},
            },
            method="PATCH",
        )
        session["sessionToken"] = updated["sessionToken"]
        second = challenge_session(provider, account)
        response = provider.client.patch(
            "/v2/sessions/" + second["sessionId"],
            json={
                "sessionToken": second["sessionToken"],
                "checks": {"webAuthN": {"credentialAssertionData": assertion}},
            },
        )
        require_rejected_check(response)
    finally:
        authenticator.set_verified(True)
        for value in (session, second):
            if value is not None:
                provider.call(
                    "/v2/sessions/" + value["sessionId"],
                    {"sessionToken": value["sessionToken"]},
                    method="DELETE",
                )


def run() -> None:
    config = identity.settings()
    require(config is not None)
    accounts = json.loads(identity.ACCOUNTS.read_text())
    provider = identity.Bootstrap(identity.read_bootstrap("login"))
    if config is None:
        raise DemoRuntimeError("Human identity profile unavailable")
    provider.verify_native_policy(config.org_id)
    outcomes: list[str] = []

    def passed(label: str, condition: bool) -> None:
        if not condition:
            print("FAIL: " + label, flush=True)
        require(condition)
        outcomes.append(label)
        print("PASS: " + label, flush=True)

    try:
        with (
            virtual_authenticator() as authenticator,
            httpx2.Client(trust_env=False, follow_redirects=False, timeout=20) as browser,
        ):
            for label in ("viewer", "unprivileged"):
                require("password" not in accounts[label])
                register_passkey(provider, accounts[label], authenticator)
            passed("Real WebAuthn registration requires user verification", True)
            passed(
                "Anonymous access denied", browser.get(VIEWER + "/_lab/snapshot").status_code == 401
            )
            login = authenticate(browser, provider, accounts["viewer"], authenticator)
            passed("Real verified passkey and PKCE exchange", login.status_code == 303)
            reject_unverified_or_replayed_assertion(provider, accounts["viewer"], authenticator)
            passed("Server rejects an unverified key and cross-challenge replay", True)
            session = browser.cookies.get(SESSION_COOKIE)
            passed(
                "Opaque browser session",
                session is not None and len(session) == 43 and "." not in session,
            )
            snapshot = browser.get(VIEWER + "/_lab/snapshot")
            passed(
                "Viewer role permits observation",
                snapshot.status_code == 200
                and snapshot.json().get("viewer", {}).get("role") == "viewer",
            )
            passed(
                "Secrets remain denied",
                browser.get(
                    VIEWER + "/clusters/main/api/v1/namespaces/security-lab/secrets"
                ).status_code
                == 403,
            )
            passed(
                "Mutations remain denied",
                browser.post(
                    VIEWER + "/clusters/main/api/v1/namespaces/security-lab/pods"
                ).status_code
                == 405,
            )
            passed(
                "Authorization callback cannot be replayed",
                browser.get(login.request.url).status_code == 403,
            )
            browser.post(VIEWER + "/_auth/logout")
            passed(
                "Local logout removes access",
                browser.get(VIEWER + "/_lab/snapshot").status_code == 401,
            )
            denied = authenticate(browser, provider, accounts["unprivileged"], authenticator)
            passed(
                "Real passkey user without approval and viewer is denied",
                denied.status_code == 403
                and browser.get(VIEWER + "/_lab/snapshot").status_code == 401,
            )
        identity.write_private(
            REPORT, {"checked_at": datetime.now(UTC).isoformat(), "passed": outcomes}
        )
    finally:
        provider.client.close()


def main() -> None:
    try:
        run()
    except (DemoRuntimeError, httpx2.HTTPError, OSError, ValueError, KeyError, TypeError):
        print(
            "Human identity acceptance failed; no credentials or response details emitted",
            flush=True,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
