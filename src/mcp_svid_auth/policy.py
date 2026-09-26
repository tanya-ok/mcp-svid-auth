"""Allowlist policy: which SPIFFE IDs may get tokens for which resources and scopes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mcp_svid_auth.errors import AuthError


@dataclass(frozen=True)
class Policy:
    trust_domain: str
    grants: dict[str, dict[str, frozenset[str]]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        grants: dict[str, dict[str, frozenset[str]]] = {}
        for client in data.get("clients", []):
            resources = client.get("resources", {})
            grants[str(client["spiffe_id"])] = {
                str(uri).rstrip("/"): frozenset(str(s) for s in scopes)
                for uri, scopes in resources.items()
            }
        return cls(trust_domain=str(data["trust_domain"]), grants=grants)

    @classmethod
    def load(cls, path: Path) -> Policy:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"policy file {path} is not a mapping")
        return cls.from_dict(data)

    def grant(self, spiffe_id: str, resource: str, requested: set[str] | None) -> frozenset[str]:
        """Return the scopes to issue, or raise AuthError."""
        resources = self.grants.get(spiffe_id)
        if resources is None:
            raise AuthError("unauthorized_client", "SPIFFE ID is not allowlisted")
        allowed = resources.get(resource.rstrip("/"))
        if allowed is None:
            raise AuthError("invalid_target", "resource not allowed for this SPIFFE ID")
        if requested is None:
            return allowed
        if not requested <= allowed:
            raise AuthError("invalid_scope", "requested scope not allowed")
        return frozenset(requested)
