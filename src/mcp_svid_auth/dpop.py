"""RFC 9449 DPoP proofs: creation, validation and replay tracking. ES256 only.

DPoP binds a token to a key. It does not authenticate the client (the JWT-SVID does that), does
not protect the request body, and does not help once an attacker also holds the proof key.
"""

from __future__ import annotations

import base64
import hashlib
import heapq
import hmac
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

DPOP_ALG = "ES256"
DPOP_TYP = "dpop+jwt"
MAX_PROOF_BYTES = 4096
MAX_JTI_LENGTH = 128
PROOF_MAX_AGE_SECONDS = 60
PROOF_MAX_FUTURE_SECONDS = 5
DEFAULT_PROOF_REPLAY_SIZE = 10_000
_DEFAULT_PORTS = {"http": 80, "https": 443}
_JWK_MEMBERS = {"kty", "crv", "x", "y"}
_REMOTE_KEY_HEADERS = {"jku", "x5u", "x5c", "kid"}


class DPoPError(Exception):
    """A proof was refused. The message is a fixed label, safe to log and return."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint of an EC public key: required members, sorted, no whitespace."""
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def access_token_hash(token: str) -> str:
    return _b64url(hashlib.sha256(token.encode("ascii")).digest())


def canonical_htu(url: str) -> str:
    """Scheme, host, port and path, per RFC 9449 section 4.3. Query and fragment are ignored."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise DPoPError("invalid_htu") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not host or parts.username or parts.password:
        raise DPoPError("invalid_htu")
    authority = host.lower()
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}{parts.path or '/'}"


def _proof_key(header: dict[str, Any]) -> tuple[Any, str]:
    if header.get("typ") != DPOP_TYP:
        raise DPoPError("invalid_typ")
    if header.get("alg") != DPOP_ALG:
        raise DPoPError("unsupported_alg")
    if _REMOTE_KEY_HEADERS & header.keys():
        raise DPoPError("remote_key_reference")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or set(jwk) != _JWK_MEMBERS:
        raise DPoPError("invalid_jwk")
    if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
        raise DPoPError("invalid_jwk")
    if not all(isinstance(jwk[name], str) for name in ("x", "y")):
        raise DPoPError("invalid_jwk")
    try:
        return jwt.PyJWK.from_dict(jwk, algorithm=DPOP_ALG), jwk_thumbprint(jwk)
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise DPoPError("invalid_jwk") from exc


@dataclass(frozen=True)
class VerifiedProof:
    jkt: str
    jti: str
    iat: int


def verify_proof(
    proof: str, *, htm: str, htu: str, now: float, access_token: str | None = None
) -> VerifiedProof:
    """Validate one proof. Replay tracking is separate: see `ProofReplayStore`."""
    if len(proof) > MAX_PROOF_BYTES or not proof.isascii():
        raise DPoPError("invalid_proof_size_or_encoding")
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as exc:
        raise DPoPError("malformed_proof") from exc
    key, jkt = _proof_key(header)
    try:
        claims = jwt.decode(
            proof,
            key,
            algorithms=[DPOP_ALG],
            options={
                "require": ["jti", "htm", "htu", "iat"],
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise DPoPError("invalid_proof_signature") from exc
    jti, iat = claims["jti"], claims["iat"]
    if not isinstance(jti, str) or not 0 < len(jti) <= MAX_JTI_LENGTH:
        raise DPoPError("invalid_jti")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise DPoPError("invalid_iat")
    if iat < now - PROOF_MAX_AGE_SECONDS or iat > now + PROOF_MAX_FUTURE_SECONDS:
        raise DPoPError("proof_not_fresh")
    if claims["htm"] != htm:
        raise DPoPError("htm_mismatch")
    if not isinstance(claims["htu"], str) or canonical_htu(claims["htu"]) != canonical_htu(htu):
        raise DPoPError("htu_mismatch")
    if access_token is not None:
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath, access_token_hash(access_token)
        ):
            raise DPoPError("ath_mismatch")
    return VerifiedProof(jkt=jkt, jti=jti, iat=iat)


@dataclass
class ProofReplayStore:
    """Seen (jkt, jti) pairs until the proof can no longer pass the freshness check.

    In-memory and per process: a restart or another replica does not share it, so a proof can be
    replayed there inside its freshness window. When full of live entries it fails closed.
    """

    max_entries: int = DEFAULT_PROOF_REPLAY_SIZE
    _expiry: dict[tuple[str, str], float] = field(default_factory=dict)
    _heap: list[tuple[float, tuple[str, str]]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            raise ValueError("replay store size must be positive")

    def __len__(self) -> int:
        return len(self._expiry)

    def add(self, proof: VerifiedProof, now: float) -> None:
        key = (proof.jkt, proof.jti)
        # Kept past the later of the two windows, so an accepted proof cannot pass twice.
        expires_at = max(now, proof.iat) + PROOF_MAX_AGE_SECONDS + PROOF_MAX_FUTURE_SECONDS
        with self._lock:
            while self._heap and self._heap[0][0] <= now:
                _, old = heapq.heappop(self._heap)
                self._expiry.pop(old, None)
            if key in self._expiry:
                raise DPoPError("proof_replayed")
            if len(self._expiry) >= self.max_entries:
                raise DPoPError("proof_replay_store_full")
            self._expiry[key] = expires_at
            heapq.heappush(self._heap, (expires_at, key))


@dataclass
class DPoPKey:
    """The client's proof key. It stays in process memory and is never written to disk."""

    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }

    @property
    def jkt(self) -> str:
        return jwk_thumbprint(self.public_jwk)

    def proof(self, htm: str, htu: str, access_token: str | None = None) -> str:
        claims: dict[str, Any] = {
            "jti": uuid.uuid4().hex,
            "htm": htm,
            "htu": canonical_htu(htu),
            "iat": int(time.time()),
        }
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        return jwt.encode(
            claims,
            self.private_key,
            algorithm=DPOP_ALG,
            headers={"typ": DPOP_TYP, "jwk": self.public_jwk},
        )


class DPoPAuth(httpx2.Auth):
    """Sends a fresh proof on every HTTP request, including any the transport repeats."""

    def __init__(self, token: str, key: DPoPKey) -> None:
        self.token = token
        self.key = key

    def auth_flow(self, request: httpx2.Request) -> Any:
        request.headers["Authorization"] = f"DPoP {self.token}"
        request.headers["DPoP"] = self.key.proof(request.method, str(request.url), self.token)
        yield request
