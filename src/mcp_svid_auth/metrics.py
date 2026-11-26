"""Prometheus text metrics derived from audit decisions, plus dependency gauges.

Every audit record increments `mcp_svid_decisions_total{component,decision,reason}`. The reason
label comes from a fixed vocabulary (`classify`), never from free text, so label cardinality is
bounded and no identifier reaches a metric. Gauges report dependency state at scrape time.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# Ordered: the first matching fragment decides the label.
_PATTERNS: tuple[tuple[str, str], ...] = (
    ("replay_store", "store_unavailable"),
    ("store_unavailable", "store_unavailable"),
    ("store unavailable", "store_unavailable"),
    ("store full", "store_full"),
    ("store_full", "store_full"),
    ("replayed", "replay"),
    ("budget exceeded", "rate_limited"),
    ("budget_exceeded", "rate_limited"),
    ("limit_reached", "rate_limited"),
    ("jwks_unavailable", "jwks_unavailable"),
    ("jwks_invalid", "jwks_invalid"),
    ("revoked_token", "revoked"),
    ("blocked_spiffe_id", "revoked"),
    ("credential revoked", "revoked"),
    ("revocation_unavailable", "revocation_unavailable"),
    ("revocation state unavailable", "revocation_unavailable"),
    ("signing unavailable", "signer_unavailable"),
    ("trust bundle unavailable", "trust_bundle_unavailable"),
    ("insufficient_scope", "insufficient_scope"),
    ("invalid_dpop_proof", "invalid_dpop_proof"),
    ("dpop_scheme_required", "invalid_dpop_proof"),
    ("token_expired_during_call", "token_expired"),
    ("invalid_token", "invalid_token"),
    ("missing_token", "missing_token"),
    ("unknown tool", "unknown_tool"),
    ("request body", "invalid_request"),
)
_OAUTH_ERRORS = frozenset(
    {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "invalid_scope",
        "invalid_target",
        "unauthorized_client",
        "unsupported_grant_type",
        "temporarily_unavailable",
    }
)
_DECISIONS = frozenset({"allow", "deny", "policy_reload"})
_COMPONENT_PREFIXES = ("authz", "mcp_server")


def classify(decision: str, reason: str) -> str:
    """Bounded reason label for a decision."""
    lowered = reason.lower()
    for fragment, label in _PATTERNS:
        if fragment in lowered:
            return label
    if decision == "allow":
        return "allowed"
    if decision == "policy_reload":
        return "failed" if lowered.startswith("failed") else "loaded"
    code = lowered.split(":", 1)[0].strip()
    return code if code in _OAUTH_ERRORS else "other"


@dataclass
class Metrics:
    _counts: dict[tuple[str, str, str], int] = field(default_factory=dict)
    _gauges: dict[str, Callable[[], float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, component: str, decision: str, reason: str) -> None:
        label = (
            component.split(":", 1)[0] if component.startswith(_COMPONENT_PREFIXES) else "other",
            decision if decision in _DECISIONS else "other",
            classify(decision, reason),
        )
        with self._lock:
            self._counts[label] = self._counts.get(label, 0) + 1

    def gauge(self, dependency: str, probe: Callable[[], float]) -> None:
        self._gauges[dependency] = probe

    def render(self, extra: Iterable[tuple[str, float]] = ()) -> str:
        lines = [
            "# HELP mcp_svid_decisions_total Audited decisions by bounded reason.",
            "# TYPE mcp_svid_decisions_total counter",
        ]
        with self._lock:
            counts = sorted(self._counts.items())
        for (component, decision, reason), value in counts:
            lines.append(
                f'mcp_svid_decisions_total{{component="{component}",decision="{decision}",'
                f'reason="{reason}"}} {value}'
            )
        lines += [
            "# HELP mcp_svid_dependency_up 1 when a dependency answered at scrape time.",
            "# TYPE mcp_svid_dependency_up gauge",
        ]
        values = [(name, _safe(probe)) for name, probe in sorted(self._gauges.items())]
        for name, up in [*values, *extra]:
            lines.append(f'mcp_svid_dependency_up{{dependency="{name}"}} {up:g}')
        return "\n".join(lines) + "\n"


def succeeds(call: Callable[[], object]) -> Callable[[], float]:
    """Gauge probe: 1 when `call` returns, 0 when it raises."""

    def probe() -> float:
        call()
        return 1.0

    return probe


def _safe(probe: Callable[[], float]) -> float:
    try:
        return float(probe())
    except Exception:
        return 0.0
