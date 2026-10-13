"""Inherited, cross-organization or weakened provider policies fail closed."""

from __future__ import annotations

import copy
from collections.abc import Iterator
from typing import Any
from unittest.mock import Mock

import pytest

from scripts.lab_runtime import DemoRuntimeError
from scripts.passwordless_policy import google_webauthn_login_settings
from scripts.zitadel_demo import Bootstrap


@pytest.fixture
def provider() -> Iterator[Bootstrap]:
    instance = Bootstrap("synthetic-test-only")
    yield instance
    instance.client.close()


def policy_response() -> dict[str, Any]:
    expected = google_webauthn_login_settings()
    # Proto JSON omits false booleans and empty lists, but keeps true requirements.
    policy = {name: value for name, value in expected.items() if value is not False and value != []}
    policy.pop("passkeysType")
    policy["passwordlessType"] = "PASSWORDLESS_TYPE_ALLOWED"
    policy["details"] = {"resourceOwner": "approved-org"}
    return {"policy": policy}


def google_response() -> dict[str, Any]:
    return {
        "idp": {
            "id": "approved-provider",
            "details": {"resourceOwner": "approved-org"},
            "state": "IDP_STATE_ACTIVE",
            "owner": "IDP_OWNER_TYPE_ORG",
            "type": "PROVIDER_TYPE_GOOGLE",
            "config": {
                "google": {
                    "clientId": "synthetic.apps.googleusercontent.com",
                    "scopes": ["openid", "profile", "email"],
                },
            },
        },
    }


def test_closed_proto_defaults_are_accepted(
    provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = policy_response()
    monkeypatch.setattr(provider, "call", Mock(return_value=response))
    provider.verify_login_policy("approved-org", google_webauthn_login_settings())
    monkeypatch.setattr(
        provider,
        "call",
        Mock(side_effect=[google_response(), {"result": [{"idpId": "approved-provider"}]}]),
    )
    provider.verify_google_provider(
        "approved-org", "approved-provider", "synthetic.apps.googleusercontent.com"
    )


@pytest.mark.parametrize("target", ["response", "policy"])
def test_inherited_instance_policy_is_rejected(
    target: str, provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = policy_response()
    (response if target == "response" else response["policy"])["isDefault"] = True
    monkeypatch.setattr(provider, "call", Mock(return_value=response))
    with pytest.raises(DemoRuntimeError, match="Unsafe human login policy"):
        provider.verify_login_policy("approved-org", google_webauthn_login_settings())


@pytest.mark.parametrize(
    "change",
    [
        {"details": {"resourceOwner": "another-org"}},
        {"details": {}},
        {"allowUsernamePassword": True},
        {"forceMfa": False},
        {"forceMfa": 1},
        {"forceMfaLocalOnly": True},
        {"secondFactors": ["SECOND_FACTOR_TYPE_OTP"]},
        {"multiFactors": ["MULTI_FACTOR_TYPE_U2F"]},
        {"mfaInitSkipLifetime": "300s"},
    ],
)
def test_wrong_owner_or_weakened_login_policy_is_rejected(
    change: dict[str, Any], provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = policy_response()
    response["policy"].update(change)
    monkeypatch.setattr(provider, "call", Mock(return_value=response))
    with pytest.raises((ValueError, DemoRuntimeError), match="Unsafe human login policy"):
        provider.verify_login_policy("approved-org", google_webauthn_login_settings())


@pytest.mark.parametrize(
    "change",
    [
        {"details": {"resourceOwner": "another-org"}},
        {"owner": "IDP_OWNER_TYPE_SYSTEM"},
        {"type": "PROVIDER_TYPE_OIDC"},
        {"state": "IDP_STATE_INACTIVE"},
        {"id": "another-provider"},
        {"config": {"options": {"isAutoCreation": True}}},
    ],
)
def test_inherited_wrong_or_inactive_provider_is_rejected(
    change: dict[str, Any], provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = google_response()
    response["idp"].update(change)
    monkeypatch.setattr(provider, "call", Mock(return_value=response))
    with pytest.raises(DemoRuntimeError, match="Unsafe external identity policy"):
        provider.verify_google_provider(
            "approved-org", "approved-provider", "synthetic.apps.googleusercontent.com"
        )


@pytest.mark.parametrize(
    "options",
    [
        {"isCreationAllowed": True},
        {"isLinkingAllowed": True},
        {"isAutoCreation": True},
        {"isAutoUpdate": True},
        {"autoLinking": "AUTO_LINKING_OPTION_EMAIL"},
        {"isAutoCreation": 0},
    ],
)
def test_self_service_linking_or_creation_is_rejected(
    options: dict[str, Any], provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = google_response()
    response["idp"]["config"]["options"] = copy.deepcopy(options)
    monkeypatch.setattr(provider, "call", Mock(return_value=response))
    with pytest.raises(ValueError, match="Unsafe external identity policy"):
        provider.verify_google_provider(
            "approved-org", "approved-provider", "synthetic.apps.googleusercontent.com"
        )


@pytest.mark.parametrize(
    "active",
    [
        {},
        {"result": []},
        {"result": [{"idpId": "another-provider"}]},
        {"result": [{"idpId": "approved-provider"}, {"idpId": "another-provider"}]},
    ],
)
def test_missing_wrong_or_additional_provider_is_rejected(
    active: dict[str, Any], provider: Bootstrap, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider, "call", Mock(side_effect=[google_response(), active]))
    with pytest.raises(DemoRuntimeError, match="Unsafe external identity policy"):
        provider.verify_google_provider(
            "approved-org", "approved-provider", "synthetic.apps.googleusercontent.com"
        )
