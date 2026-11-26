"""Operator-provided signing keys: tokens survive a restart and a planned rotation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_svid_auth import authz
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer
from mcp_svid_auth.mcp_server import _find_key
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.signing_keys import SigningKeyError, load_signing_key, load_verification_key
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, RESEARCH, SERVER_A


def _key_file(
    directory: Path, name: str, curve: ec.EllipticCurve | None = None, mode: int = 0o600
) -> tuple[Path, Path]:
    key = ec.generate_private_key(curve or ec.SECP256R1())
    private = directory / f"{name}.key"
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    private.chmod(mode)
    public = directory / f"{name}.pub"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def _server(spire: LocalSvidIssuer, path: Path, published: list[Path] | None = None) -> AuthzServer:
    key, kid = load_signing_key(path)
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=None, component="authz"),
        signing_key=key,
        kid=kid,
        signing_rotation_seconds=0,
        published_keys=[load_verification_key(p) for p in published or []],
    )


def _issue(server: AuthzServer, spire: LocalSvidIssuer) -> str:
    body = server.issue(
        {
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": spire.mint(RESEARCH, ISSUER),
            "resource": SERVER_A,
            "scope": "notes:read",
        }
    )
    return str(body["access_token"])


def _verifies(token: str, jwks: dict[str, Any]) -> bool:
    key = _find_key(jwks, jwt.get_unverified_header(token)["kid"])
    if key is None:
        return False
    jwt.decode(token, key, algorithms=["ES256"], audience=SERVER_A, issuer=ISSUER)
    return True


def test_token_survives_a_restart_with_the_same_key(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    private, _ = _key_file(tmp_path, "active")
    token = _issue(_server(spire, private), spire)
    restarted = _server(spire, private)
    assert jwt.get_unverified_header(token)["kid"] == restarted.kid
    assert _verifies(token, restarted.jwks())


def test_rotation_overlap_publishes_the_previous_public_key(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    old_private, old_public = _key_file(tmp_path, "old")
    new_private, _ = _key_file(tmp_path, "new")
    old_token = _issue(_server(spire, old_private), spire)
    rotated = _server(spire, new_private, [old_public])
    assert _verifies(old_token, rotated.jwks())
    assert _verifies(_issue(rotated, spire), rotated.jwks())
    assert not _verifies(old_token, _server(spire, new_private).jwks())
    assert len(rotated.jwks()["keys"]) == 2


def test_previous_key_does_not_duplicate_the_active_key(tmp_path: Path) -> None:
    spire = LocalSvidIssuer()
    private, public = _key_file(tmp_path, "active")
    assert len(_server(spire, private, [public]).jwks()["keys"]) == 1


def test_kid_is_the_stable_thumbprint(tmp_path: Path) -> None:
    private, public = _key_file(tmp_path, "active")
    assert load_signing_key(private)[1] == load_signing_key(private)[1]
    assert load_verification_key(public)["kid"] == load_signing_key(private)[1]


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_key_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    private, _ = _key_file(tmp_path, "loose", mode=mode)
    with pytest.raises(SigningKeyError, match="group or others"):
        load_signing_key(private)


def test_wrong_curve_or_garbage_is_refused(tmp_path: Path) -> None:
    private, public = _key_file(tmp_path, "p384", curve=ec.SECP384R1())
    with pytest.raises(SigningKeyError, match="P-256"):
        load_signing_key(private)
    with pytest.raises(SigningKeyError, match="P-256"):
        load_verification_key(public)
    garbage = tmp_path / "garbage.key"
    garbage.write_text("not a key", encoding="utf-8")
    garbage.chmod(0o600)
    with pytest.raises(SigningKeyError, match="PEM"):
        load_signing_key(garbage)
    with pytest.raises(SigningKeyError, match="cannot be read"):
        load_signing_key(tmp_path / "missing.key")


@pytest.mark.parametrize(
    "extra",
    [
        ["--signing-key-file", "KEY"],
        ["--verification-key-file", "PUB"],
        ["--signing-key-file", "LOOSE", "--signing-rotation-seconds", "0"],
    ],
)
def test_cli_refuses_unsafe_key_options(tmp_path: Path, extra: list[str]) -> None:
    private, public = _key_file(tmp_path, "active")
    loose, _ = _key_file(tmp_path, "loose", mode=0o644)
    values = {"KEY": str(private), "PUB": str(public), "LOOSE": str(loose)}
    parser = authz.build_parser()
    args = parser.parse_args(
        ["--issuer", ISSUER, "--policy", "p.yaml", *[values.get(v, v) for v in extra]]
    )
    with pytest.raises(SystemExit):
        authz._key_options(args, parser)


def test_cli_loads_keys(tmp_path: Path) -> None:
    private, public = _key_file(tmp_path, "active")
    _, old_public = _key_file(tmp_path, "old")
    parser = authz.build_parser()
    args = parser.parse_args(
        [
            *("--issuer", ISSUER, "--policy", "p.yaml", "--signing-rotation-seconds", "0"),
            *("--signing-key-file", str(private), "--verification-key-file", str(old_public)),
        ]
    )
    options = authz._key_options(args, parser)
    assert options["kid"] == load_verification_key(public)["kid"]
    assert [k["kid"] for k in options["published_keys"]] == [
        load_verification_key(old_public)["kid"]
    ]
