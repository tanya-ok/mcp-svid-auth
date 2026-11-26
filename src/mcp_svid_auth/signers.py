"""Remote access token signers: the private key never enters this process.

`Signer` is the seam: `sign(claims) -> compact JWS` and `public_jwks() -> JWKs to publish`.
The local key (`--signing-key-file`, or the ephemeral development key) stays inside
`AuthzServer`. `VaultTransitSigner` signs with an OpenBao or HashiCorp Vault transit key of type
`ecdsa-p256`. A cloud KMS adapter would implement the same two methods.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import httpx2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_svid_auth.dpop import jwk_thumbprint
from mcp_svid_auth.files import MAX_SECRET_FILE_BYTES, read_file

KEY_REFRESH_SECONDS = 60
MAX_PUBLISHED_VERSIONS = 4


class SignerError(Exception):
    """The signer could not sign or publish keys; the caller must refuse issuance."""


class Signer(Protocol):
    def sign(self, claims: dict[str, Any]) -> str: ...

    def public_jwks(self) -> list[dict[str, Any]]: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(pem: str) -> dict[str, Any]:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SignerError("transit key must be ecdsa-p256")
    jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(key))
    jwk.update({"kid": jwk_thumbprint(jwk), "use": "sig", "alg": "ES256"})
    return jwk


@dataclass
class VaultTransitSigner:
    """ES256 signatures from a transit engine (`POST transit/sign/<key>/sha2-256`, JWS format).

    The token is read from an owner-only file. Plain http is accepted only on loopback.
    """

    address: str
    key_name: str
    token_file: Path
    mount: str = "transit"
    verify: ssl.SSLContext | bool = True
    namespace: str | None = None
    clock: Callable[[], float] = time.monotonic
    transport: httpx2.BaseTransport | None = None
    _versions: dict[int, dict[str, Any]] = field(default_factory=dict)
    _latest: int = 0
    _fetched_at: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        parts = urlsplit(self.address)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("transit address must be an http(s) URL")
        if parts.scheme == "http" and not _loopback(parts.hostname):
            raise ValueError("transit address must use https unless it is on loopback")

    def _client(self) -> httpx2.Client:
        token = read_file(self.token_file, max_bytes=MAX_SECRET_FILE_BYTES, private=True)
        headers = {"X-Vault-Token": token.decode("utf-8").strip()}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return httpx2.Client(
            base_url=self.address.rstrip("/"),
            headers=headers,
            timeout=5,
            verify=self.verify,
            trust_env=False,
            follow_redirects=False,
            transport=self.transport,
        )

    def _path(self, action: str) -> str:
        return f"/v1/{quote(self.mount, safe='')}/{action}/{quote(self.key_name, safe='')}"

    def _refresh(self, *, force: bool = False) -> None:
        with self._lock:
            now = self.clock()
            if (
                not force
                and self._fetched_at is not None
                and now - self._fetched_at < KEY_REFRESH_SECONDS
            ):
                return
            try:
                with self._client() as client:
                    response = client.get(self._path("keys"))
                response.raise_for_status()
                data = response.json()["data"]
                if data.get("type") != "ecdsa-p256":
                    raise SignerError("transit key must be ecdsa-p256")
                versions = {
                    int(v): _jwk(str(entry["public_key"])) for v, entry in data["keys"].items()
                }
            except SignerError:
                raise
            except Exception as exc:
                raise SignerError(f"transit key unavailable: {type(exc).__name__}") from exc
            if not versions:
                raise SignerError("transit key has no versions")
            self._latest = max(versions)
            self._versions = versions
            self._fetched_at = now

    def public_jwks(self) -> list[dict[str, Any]]:
        self._refresh()
        newest = sorted(self._versions, reverse=True)[:MAX_PUBLISHED_VERSIONS]
        return [self._versions[v] for v in newest]

    def sign(self, claims: dict[str, Any]) -> str:
        self._refresh()
        version = self._latest
        kid = self._versions[version]["kid"]
        header = {"alg": "ES256", "typ": "at+jwt", "kid": kid}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        body = {
            "input": base64.b64encode(signing_input.encode()).decode(),
            "key_version": version,
            "marshaling_algorithm": "jws",
        }
        try:
            with self._client() as client:
                response = client.post(self._path("sign") + "/sha2-256", json=body)
            response.raise_for_status()
            signature = str(response.json()["data"]["signature"])
        except Exception as exc:
            raise SignerError(f"transit signing failed: {type(exc).__name__}") from exc
        prefix = f"vault:v{version}:"
        if not signature.startswith(prefix):
            raise SignerError("transit signed with an unexpected key version")
        return signing_input + "." + signature[len(prefix) :]


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
