"""Operator-provided access token signing keys that survive a restart.

The active key is a PEM P-256 private key the operator supplies, for example from a mounted
secret. Its `kid` is the RFC 7638 thumbprint, so every restart and every replica publishes the
same identifier. Previous public keys can be published for overlap during a planned rotation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_svid_auth.dpop import jwk_thumbprint
from mcp_svid_auth.files import MAX_KEY_FILE_BYTES, UnsafeFileError, read_file

MAX_PUBLISHED_KEYS = 4


class SigningKeyError(ValueError):
    """A signing or verification key file is unusable or unsafe."""


def _public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(key))
    return jwk


def key_id(key: ec.EllipticCurvePublicKey) -> str:
    return jwk_thumbprint(_public_jwk(key))


def load_signing_key(path: Path) -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Load a P-256 private key from an owner-only regular file (one descriptor, no symlink)."""
    try:
        data = read_file(path, max_bytes=MAX_KEY_FILE_BYTES, private=True)
    except UnsafeFileError as exc:
        raise SigningKeyError(f"signing key file unusable: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("signing key file is not an unencrypted PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("signing key must be EC P-256 for ES256")
    return key, key_id(key.public_key())


def load_verification_key(path: Path) -> dict[str, Any]:
    """A previous P-256 public key as a JWK for publication during rotation overlap."""
    try:
        data = read_file(path, max_bytes=MAX_KEY_FILE_BYTES)
    except UnsafeFileError as exc:
        raise SigningKeyError(f"verification key file unusable: {exc}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("verification key file is not a PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SigningKeyError("verification key must be EC P-256")
    jwk = _public_jwk(key)
    jwk.update({"kid": jwk_thumbprint(jwk), "use": "sig", "alg": "ES256"})
    return jwk
