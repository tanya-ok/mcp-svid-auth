"""Untrusted configuration cannot open registration or disclose credentials."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.google_identity_config import GoogleConfig, read_private_config


def configuration() -> dict[str, Any]:
    return {
        "approved_emails": ["Approved@example.org"],
        "oauth_client_id": "synthetic-fixture.apps.googleusercontent.com",
        "oauth_client_secret": "synthetic-test-only",
    }


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_public_output_and_repr_do_not_disclose_private_input(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    write(path, configuration())
    config = read_private_config(path)
    output = json.dumps(config.public_summary()) + repr(config)
    assert "synthetic-test-only" not in output
    assert "synthetic-fixture" not in output
    assert "example.org" not in output
    assert config.public_summary()["approvedAccountCount"] == 1
    assert config.public_summary()["applied"] is False
    assert config.approved_emails == frozenset({"approved@example.org"})
    payload = config.provider_request()
    assert payload["scopes"] == ["openid", "profile", "email"]
    options = payload["providerOptions"]
    assert isinstance(options, dict)
    assert options["isCreationAllowed"] is False
    assert options["isLinkingAllowed"] is False
    assert options["isAutoCreation"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"approved_emails": []},
        {"approved_emails": ["approved@example.org", "APPROVED@example.org"]},
        {"approved_emails": ["approved@example.org\n"]},
        {"approved_emails": ["approved..user@example.org"]},
        {"approved_emails": [".approved@example.org"]},
        {"approved_emails": [True]},
        {"approved_emails": "approved@example.org"},
        {"approved_emails": [f"user{i}@example.org" for i in range(21)]},
        {"oauth_client_id": "https://example.org"},
        {"oauth_client_id": "fixture.apps.googleusercontent.com.example.org"},
        {"oauth_client_secret": ""},
        {"oauth_client_secret": "secret\nvalue"},
        {"oauth_client_secret": "secret\x00value"},
        {"oauth_client_secret": "secret\x7fvalue"},
        {"oauth_client_secret": "x" * 201},
        {"oauth_client_secret": True},
        {"scopes": ["mail"]},
        {"isAutoCreation": True},
        {"role": "admin"},
    ],
)
def test_unsafe_or_ambiguous_config_is_rejected_without_echoing_it(
    change: dict[str, Any], tmp_path: Path
) -> None:
    value = configuration()
    value.update(change)
    path = tmp_path / "private.json"
    write(path, value)
    with pytest.raises(ValueError, match=r"^Invalid private Google configuration$"):
        read_private_config(path)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_readable_by_others_is_rejected(mode: int, tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    write(path, configuration())
    path.chmod(mode)
    with pytest.raises(ValueError, match=r"^Invalid private Google configuration$"):
        read_private_config(path)


def test_duplicate_keys_invalid_json_and_large_input_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    for body in (
        '{"oauth_client_secret":"first","oauth_client_secret":"second"}',
        '{"secret":',
        "x" * 65537,
    ):
        path.write_text(body)
        path.chmod(0o600)
        with pytest.raises(ValueError, match=r"^Invalid private Google configuration$"):
            read_private_config(path)


def test_symlinks_and_nonregular_files_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    write(source, configuration())
    link = tmp_path / "link.json"
    link.symlink_to(source)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    for path in (link, fifo, tmp_path, tmp_path / "absent"):
        with pytest.raises(ValueError, match=r"^Invalid private Google configuration$"):
            read_private_config(path)


def test_input_is_only_an_approval_pool_not_identity_proof() -> None:
    config = GoogleConfig.parse(configuration())
    assert (
        config.public_summary()["identityProof"]
        == "Still required before linking or granting access"
    )
    assert "google_subject" not in config.provider_request()
