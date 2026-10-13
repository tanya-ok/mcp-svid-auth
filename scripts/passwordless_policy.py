"""Fail-closed policy for a closed Google plus WebAuthn human sign-in profile.

Call the claim check only after validating the ZITADEL signature, issuer,
audience, nonce and token lifetime. It does not authenticate a JWT itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

MAX_AUTHENTICATION_AGE = 300
_IDENTIFIER = re.compile(r"[A-Za-z0-9@_-]{1,128}")


def google_webauthn_login_settings() -> dict[str, object]:
    """Return organization settings, not a passwordless-only local policy.

    In ZITADEL 4.19.4 disabling local authentication also disables standalone
    local passkey sign-in. WebAuthn remains the required second factor after
    an external identity provider. Never enable OTP as a fallback here.
    """
    return {
        "allowLocalAuthentication": False,
        "allowRegister": False,
        "allowExternalIdp": True,
        "forceMfa": True,
        "forceMfaLocalOnly": False,
        "passkeysType": "PASSKEYS_TYPE_ALLOWED",
        "hidePasswordReset": True,
        "allowDomainDiscovery": False,
        "disableLoginWithPhone": True,
        "secondFactors": [],
        "multiFactors": ["MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION"],
        "externalLoginCheckLifetime": "300s",
        "secondFactorCheckLifetime": "300s",
        "multiFactorCheckLifetime": "300s",
        "mfaInitSkipLifetime": "0s",
    }


def closed_google_provider_options() -> dict[str, object]:
    """Accept administrator-created identity links, never email auto-linking."""
    return {
        "isCreationAllowed": False,
        "isAutoCreation": False,
        "isLinkingAllowed": False,
        "isAutoUpdate": False,
        "autoLinking": "AUTO_LINKING_OPTION_UNSPECIFIED",
    }


def native_passkey_login_settings() -> dict[str, object]:
    """Use real local WebAuthn for synthetic tests before Google is configured.

    Local authentication must remain enabled for native passkeys. The users
    are created without passwords, and the application additionally rejects
    any token that contains password or OTP authentication evidence.
    """
    settings = google_webauthn_login_settings()
    settings.update({"allowLocalAuthentication": True, "allowExternalIdp": False})
    return settings


def require_google_webauthn_settings(settings: Mapping[str, object]) -> None:
    """Check effective organization settings read back from the provider."""
    require_login_settings(settings, google_webauthn_login_settings())


def require_native_passkey_settings(settings: Mapping[str, object]) -> None:
    """Check the effective policy for the synthetic native passkey profile."""
    require_login_settings(settings, native_passkey_login_settings())


def require_login_settings(settings: Mapping[str, object], expected: Mapping[str, object]) -> None:
    for name, required in expected.items():
        actual = settings.get(name)
        if type(actual) is not type(required) or actual != required:
            raise ValueError("Unsafe human login policy")


def require_closed_google_provider(options: Mapping[str, object]) -> None:
    """Check provider creation and linking separately from local registration."""
    for name, required in closed_google_provider_options().items():
        actual = options.get(name)
        if type(actual) is not type(required) or actual != required:
            raise ValueError("Unsafe external identity policy")


@dataclass(frozen=True)
class PasswordlessApproval:
    """Approve stable ZITADEL subjects, never user-entered email addresses."""

    approved_subjects: frozenset[str]

    def __post_init__(self) -> None:
        if not self.approved_subjects or any(
            not isinstance(subject, str) or not _IDENTIFIER.fullmatch(subject)
            for subject in self.approved_subjects
        ):
            raise ValueError("Invalid human approval policy")

    def require_verified_claims(self, claims: Mapping[str, object], *, now: float) -> str:
        """Require approval, fresh authentication and ZITADEL's WebAuthn AMR.

        ZITADEL maps both a verified local passkey and external IdP plus U2F
        to user+mfa. AMR alone cannot prove user verification or which IdP
        was used. This check must accompany the effective policy checks and
        the server's required WebAuthn user-verification challenge.
        """
        subject = claims.get("sub")
        if not isinstance(subject, str) or subject not in self.approved_subjects:
            raise ValueError("Human sign-in denied")
        methods = claims.get("amr")
        if (
            not isinstance(methods, list)
            or len(methods) != 2
            or not all(isinstance(method, str) for method in methods)
            or set(methods) != {"user", "mfa"}
        ):
            raise ValueError("Human sign-in denied")
        authenticated_at = claims.get("auth_time")
        if (
            type(authenticated_at) is not int
            or not 0 <= now - authenticated_at <= MAX_AUTHENTICATION_AGE
        ):
            raise ValueError("Human sign-in denied")
        return subject
