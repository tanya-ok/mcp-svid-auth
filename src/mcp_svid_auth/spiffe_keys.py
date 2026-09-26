"""Where JWT-SVIDs and their verification keys come from.

Two modes:
- workload: the SPIFFE Workload API (a SPIRE agent socket).
- static: a JWKS file and a local signing key. Tests and the offline demo only.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from mcp_svid_auth.errors import AuthError

JWT_SVID_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384"]
_BUNDLE_CACHE_SECONDS = 30


def spiffe_trust_domain(spiffe_id: str) -> str:
    """Return the trust domain of a SPIFFE ID or raise AuthError."""
    if not spiffe_id.startswith("spiffe://"):
        raise AuthError("invalid_client", "sub is not a SPIFFE ID")
    rest = spiffe_id.removeprefix("spiffe://")
    domain, _, path = rest.partition("/")
    if not domain or not path or domain.lower() != domain or "?" in rest or "#" in rest:
        raise AuthError("invalid_client", "sub is not a valid SPIFFE ID")
    return domain


class KeyResolver(Protocol):
    """Finds the public key that signed a JWT-SVID."""

    def resolve(self, trust_domain: str, kid: str | None) -> Any: ...


class SvidSource(Protocol):
    """Hands out JWT-SVIDs for the calling workload."""

    def fetch(self, audience: str) -> str: ...


@dataclass
class StaticJwksResolver:
    """A fixed JWKS per trust domain. Test mode only."""

    bundles: dict[str, dict[str, Any]]

    @classmethod
    def from_file(cls, trust_domain: str, path: Path) -> StaticJwksResolver:
        return cls({trust_domain: json.loads(path.read_text(encoding="utf-8"))})

    def resolve(self, trust_domain: str, kid: str | None) -> Any:
        jwks = self.bundles.get(trust_domain)
        if jwks is None:
            raise AuthError("invalid_client", "unknown trust domain")
        for key in jwt.PyJWKSet.from_dict(jwks).keys:
            if kid is None or key.key_id == kid:
                return key.key
        raise AuthError("invalid_client", "unknown signing key")


@dataclass
class WorkloadApiResolver:
    """JWT bundles from the SPIFFE Workload API, cached briefly."""

    socket_path: str | None = None
    _cached_at: float = 0.0
    _bundles: Any = None

    def _bundle_set(self) -> Any:
        if self._bundles is None or time.monotonic() - self._cached_at > _BUNDLE_CACHE_SECONDS:
            from spiffe import WorkloadApiClient  # noqa: PLC0415

            client = WorkloadApiClient(socket_path=self.socket_path, default_timeout=5)
            try:
                self._bundles = client.fetch_jwt_bundles()
            finally:
                client.close()
            self._cached_at = time.monotonic()
        return self._bundles

    def resolve(self, trust_domain: str, kid: str | None) -> Any:
        from spiffe import TrustDomain  # noqa: PLC0415

        bundle = self._bundle_set().get_bundle_for_trust_domain(TrustDomain(trust_domain))
        if bundle is None:
            raise AuthError("invalid_client", "unknown trust domain")
        key = bundle.get_jwt_authority(kid)
        if key is None:
            raise AuthError("invalid_client", "unknown signing key")
        return key


@dataclass
class WorkloadApiSvidSource:
    """JWT-SVIDs from the SPIFFE Workload API."""

    socket_path: str | None = None

    def fetch(self, audience: str) -> str:
        from spiffe import WorkloadApiClient  # noqa: PLC0415

        client = WorkloadApiClient(socket_path=self.socket_path, default_timeout=5)
        try:
            token: str = client.fetch_jwt_svid(audience={audience}).token
        finally:
            client.close()
        return token


@dataclass
class LocalSvidIssuer:
    """Mints JWT-SVIDs with a local key. Stands in for SPIRE in tests and the offline demo."""

    trust_domain: str = "example.org"
    kid: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "jwt-svid", "alg": "ES256"})
        return {"keys": [jwk]}

    def resolver(self) -> StaticJwksResolver:
        return StaticJwksResolver({self.trust_domain: self.jwks()})

    def mint(self, spiffe_id: str, audience: str | list[str], ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {"sub": spiffe_id, "aud": audience, "iat": now, "exp": now + ttl}
        claims.update(extra)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})

    def source_for(self, spiffe_id: str) -> SvidSource:
        return _BoundSource(self, spiffe_id)


@dataclass
class _BoundSource:
    issuer: LocalSvidIssuer
    spiffe_id: str

    def fetch(self, audience: str) -> str:
        return self.issuer.mint(self.spiffe_id, audience)
