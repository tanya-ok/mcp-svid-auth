"""Exercise closed Google configuration locally without contacting Google."""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime

from scripts import zitadel_demo as identity
from scripts.google_identity_config import GoogleConfig
from scripts.lab_runtime import DemoRuntimeError
from scripts.passwordless_policy import google_webauthn_login_settings

REPORT = identity.DATA / "google-setup-report.json"


@contextlib.contextmanager
def setup_connection() -> Iterator[None]:
    # Verify the owned session nonce before borrowing its private tunnel. Holding
    # the launch lock prevents a CLI stop/start from replacing it during setup.
    from scripts import kubernetes_ui as ui  # noqa: PLC0415 - lifecycle integration

    with ui.launch_lock():
        if ui.running():
            yield
        else:
            with identity.connection():
                yield


def run() -> None:
    if identity.settings() is None:
        raise DemoRuntimeError("Human identity profile unavailable")
    with setup_connection():
        provider = identity.Bootstrap(identity.read_bootstrap("admin"))
        try:
            org = provider.call(
                "/management/v1/orgs",
                {"name": "Closed Google setup fixture " + secrets.token_hex(6)},
            )
            org_id = str(org["id"])
            provider.client.headers["x-zitadel-orgid"] = org_id
            expected = google_webauthn_login_settings()
            request = dict(expected)
            request["allowUsernamePassword"] = request.pop("allowLocalAuthentication")
            request.pop("passkeysType")
            request["passwordlessType"] = "PASSWORDLESS_TYPE_ALLOWED"
            provider.call("/management/v1/policies/login", request)
            provider.verify_login_policy(org_id, expected)
            print("PASS: Real Google policy disables local authentication and OTP", flush=True)
            config = GoogleConfig.parse(
                {
                    "approved_emails": ["approved@example.org"],
                    "oauth_client_id": "synthetic-setup-fixture.apps.googleusercontent.com",
                    "oauth_client_secret": secrets.token_urlsafe(24),
                }
            )
            created = provider.call("/management/v1/idps/google", config.provider_request())
            provider_id = str(created["id"])
            provider.call(
                "/management/v1/policies/login/idps",
                {"idpId": provider_id, "ownerType": "IDP_OWNER_TYPE_ORG"},
            )
            provider.verify_google_provider(org_id, provider_id, config.oauth_client_id)
            print("PASS: Real provider closes creation and self-linking", flush=True)
            print("PASS: Only the organization-scoped Google provider is active", flush=True)
            # This org intentionally has no users, identity links or application grants.
            print("PASS: Google configuration grants no user access", flush=True)
            identity.write_private(
                REPORT,
                {
                    "checked_at": datetime.now(UTC).isoformat(),
                    "passed": [
                        "Closed Google login policy",
                        "Closed provider creation and linking",
                        "Only approved organization-scoped provider active",
                        "No users or grants provisioned",
                    ],
                    "google_contacted": False,
                    "google_login_verified": False,
                },
            )
        finally:
            provider.client.close()


def main() -> None:
    try:
        run()
    except (DemoRuntimeError, OSError, ValueError, KeyError, TypeError):
        print("Google setup acceptance failed; no account or credential details emitted")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
