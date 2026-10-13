from __future__ import annotations

from typing import Any

import pytest

from scripts.passwordless_policy import (
    PasswordlessApproval,
    closed_google_provider_options,
    google_webauthn_login_settings,
    native_passkey_login_settings,
    require_closed_google_provider,
    require_google_webauthn_settings,
    require_native_passkey_settings,
)


@pytest.mark.parametrize("methods", [["user", "mfa"], ["mfa", "user"]])
def test_only_approved_fresh_webauthn_authentication_is_accepted(methods: list[str]) -> None:
    approval = PasswordlessApproval(frozenset({"approved-viewer"}))
    claims = {"sub": "approved-viewer", "amr": methods, "auth_time": 1000}
    assert approval.require_verified_claims(claims, now=1100) == "approved-viewer"


@pytest.mark.parametrize(
    "methods",
    [
        None,
        [],
        ["mfa"],
        ["user"],
        ["pwd"],
        ["pwd", "user", "mfa"],
        ["password", "user", "mfa"],
        ["otp", "mfa"],
        ["user", "otp", "mfa"],
        ["swk", "mfa"],
        ["user", "mfa", "mfa"],
        ["user", ["mfa"]],
        "user mfa",
        {"user": True, "mfa": True},
    ],
)
def test_password_otp_google_only_or_ambiguous_evidence_is_denied(methods: Any) -> None:
    approval = PasswordlessApproval(frozenset({"approved-viewer"}))
    with pytest.raises(ValueError, match=r"^Human sign-in denied$"):
        approval.require_verified_claims(
            {"sub": "approved-viewer", "amr": methods, "auth_time": 1000}, now=1100
        )


@pytest.mark.parametrize("subject", [None, "unapproved-viewer", [], "viewer@example.org"])
def test_email_or_a_valid_but_unapproved_identity_does_not_grant_access(subject: Any) -> None:
    approval = PasswordlessApproval(frozenset({"approved-viewer"}))
    with pytest.raises(ValueError, match=r"^Human sign-in denied$"):
        approval.require_verified_claims(
            {
                "sub": subject,
                "email": "approved@example.org",
                "email_verified": True,
                "amr": ["user", "mfa"],
                "auth_time": 1000,
            },
            now=1100,
        )


@pytest.mark.parametrize("authentication_time", [None, "1000", True, 1000.0, 699, 1101])
def test_stale_missing_future_or_malformed_authentication_time_is_denied(
    authentication_time: Any,
) -> None:
    approval = PasswordlessApproval(frozenset({"approved-viewer"}))
    with pytest.raises(ValueError, match=r"^Human sign-in denied$"):
        approval.require_verified_claims(
            {"sub": "approved-viewer", "amr": ["user", "mfa"], "auth_time": authentication_time},
            now=1100,
        )


@pytest.mark.parametrize("subjects", [frozenset(), frozenset({""}), frozenset({"bad\nsubject"})])
def test_missing_or_invalid_approval_configuration_is_denied(subjects: frozenset[str]) -> None:
    with pytest.raises(ValueError, match=r"^Invalid human approval policy$"):
        PasswordlessApproval(subjects)


@pytest.mark.parametrize(
    ("name", "unsafe"),
    [
        ("allowLocalAuthentication", True),
        ("allowRegister", True),
        ("allowExternalIdp", False),
        ("forceMfa", False),
        ("forceMfaLocalOnly", True),
        ("secondFactors", ["SECOND_FACTOR_TYPE_U2F", "SECOND_FACTOR_TYPE_OTP_SMS"]),
        ("secondFactors", ["SECOND_FACTOR_TYPE_OTP_EMAIL"]),
        ("secondFactors", ["SECOND_FACTOR_TYPE_RECOVERY_CODES"]),
        ("multiFactors", []),
        ("mfaInitSkipLifetime", "300s"),
        ("externalLoginCheckLifetime", "86400s"),
        ("allowRegister", 0),
    ],
)
def test_weakened_effective_login_policy_is_denied(name: str, unsafe: object) -> None:
    settings = google_webauthn_login_settings()
    settings[name] = unsafe
    with pytest.raises(ValueError, match=r"^Unsafe human login policy$"):
        require_google_webauthn_settings(settings)


@pytest.mark.parametrize(
    ("name", "unsafe"),
    [
        ("isCreationAllowed", True),
        ("isAutoCreation", True),
        ("isLinkingAllowed", True),
        ("autoLinking", "AUTO_LINKING_OPTION_EMAIL"),
    ],
)
def test_external_registration_and_account_linking_are_independently_denied(
    name: str,
    unsafe: object,
) -> None:
    options = closed_google_provider_options()
    options[name] = unsafe
    with pytest.raises(ValueError, match=r"^Unsafe external identity policy$"):
        require_closed_google_provider(options)


def test_missing_provider_and_login_settings_fail_closed() -> None:
    with pytest.raises(ValueError, match=r"^Unsafe human login policy$"):
        require_google_webauthn_settings({})
    with pytest.raises(ValueError, match=r"^Unsafe external identity policy$"):
        require_closed_google_provider({})


def test_native_policy_enables_passkeys_without_enabling_external_or_otp() -> None:
    policy = native_passkey_login_settings()
    require_native_passkey_settings(policy)
    assert policy["allowLocalAuthentication"] is True
    assert policy["allowExternalIdp"] is False
    assert policy["secondFactors"] == []
    assert policy["multiFactors"] == ["MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION"]
    with pytest.raises(ValueError):
        require_google_webauthn_settings(policy)


@pytest.mark.parametrize(
    "change",
    [{"secondFactors": ["SECOND_FACTOR_TYPE_U2F"]}, {"forceMfa": False}, {"allowRegister": True}],
)
def test_native_policy_rejects_non_verified_keys_or_weakened_settings(
    change: dict[str, object],
) -> None:
    policy = native_passkey_login_settings()
    policy.update(change)
    with pytest.raises(ValueError, match=r"^Unsafe human login policy$"):
        require_native_passkey_settings(policy)
