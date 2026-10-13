"""Private Google onboarding inputs; checking them never enables access."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.oidc_gate import ISSUER
from scripts.passwordless_policy import closed_google_provider_options
from scripts.zitadel_demo import DATA

CONFIG = DATA / "google-onboarding.json"
MAX_CONFIG_SIZE = 65536
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,160}\.apps\.googleusercontent\.com")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}")
_FIELDS = {"approved_emails", "oauth_client_id", "oauth_client_secret"}
_FAILURE = "Invalid private Google configuration"


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_FAILURE)
        result[key] = value
    return result


@dataclass(frozen=True)
class GoogleConfig:
    oauth_client_id: str = field(repr=False)
    oauth_client_secret: str = field(repr=False)
    approved_emails: frozenset[str] = field(repr=False)

    @classmethod
    def parse(cls, value: object) -> GoogleConfig:
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise ValueError(_FAILURE)
        client = value["oauth_client_id"]
        secret = value["oauth_client_secret"]
        emails = value["approved_emails"]
        if (
            not isinstance(client, str)
            or not _CLIENT.fullmatch(client)
            or not isinstance(secret, str)
            or not 1 <= len(secret) <= 200
            or not secret.isascii()
            or any(not 33 <= ord(character) <= 126 for character in secret)
            or not isinstance(emails, list)
            or not 1 <= len(emails) <= 20
            or not all(
                isinstance(email, str)
                and len(email) <= 254
                and _EMAIL.fullmatch(email)
                and ".." not in email
                and not email.startswith(".")
                and ".@" not in email
                for email in emails
            )
        ):
            raise ValueError(_FAILURE)
        approved = frozenset(email.lower() for email in emails)
        if len(approved) != len(emails):
            raise ValueError(_FAILURE)
        return cls(client, secret, approved)

    def provider_request(self) -> dict[str, object]:
        """Private API payload, never a preview or an identity-verification result."""
        return {
            "name": "Approved Google accounts",
            "clientId": self.oauth_client_id,
            "clientSecret": self.oauth_client_secret,
            "scopes": ["openid", "profile", "email"],
            "providerOptions": closed_google_provider_options(),
        }

    def public_summary(self) -> dict[str, object]:
        return {
            "approvedAccountCount": len(self.approved_emails),
            "callback": ISSUER + "/idps/callback",
            "scopes": ["openid", "profile", "email"],
            "providerOptions": closed_google_provider_options(),
            "identityProof": "Still required before linking or granting access",
            "applied": False,
        }


def read_private_config(path: Path) -> GoogleConfig:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
            or info.st_size > MAX_CONFIG_SIZE
        ):
            raise ValueError(_FAILURE)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            content = stream.read(MAX_CONFIG_SIZE + 1)
        if len(content) > MAX_CONFIG_SIZE:
            raise ValueError(_FAILURE)
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)
        return GoogleConfig.parse(value)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError(_FAILURE) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def create_template() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(
            {"approved_emails": [], "oauth_client_id": "", "oauth_client_secret": ""},
            stream,
            indent=2,
        )
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "check"))
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    try:
        if args.operation == "init":
            if args.config != CONFIG:
                raise ValueError(_FAILURE)
            create_template()
            print("Private blank template created: " + str(CONFIG))
        else:
            config = read_private_config(args.config)
            print(json.dumps(config.public_summary(), indent=2))
    except (OSError, ValueError):
        print("Google configuration unavailable; no account or credential details emitted")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
