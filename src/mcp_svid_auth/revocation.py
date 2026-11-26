"""Access token revocation by `jti` and SPIFFE ID, and per-token tool call limits.

Both are per process and in memory. The revocation file is the shared source: every replica
that reads the same file converges within `poll_seconds`. A file that cannot be read or parsed
denies every check (fail closed) until a valid file is seen again.
"""

from __future__ import annotations

import hashlib
import heapq
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

MAX_REVOCATION_FILE_BYTES = 1024 * 1024
MAX_REVOCATION_ENTRIES = 100_000
DEFAULT_REVOCATION_POLL_SECONDS = 5.0
DEFAULT_TOKEN_USE_CACHE_SIZE = 100_000
_KEYS = {"revoked_jti", "blocked_spiffe_ids"}
# Keys read by RevocationList: (path, type, meaning). Rendered into docs/configuration.md.
SCHEMA: tuple[tuple[str, str, str], ...] = (
    ("revoked_jti", "list of strings", "Access token `jti` values refused before their `exp`"),
    (
        "blocked_spiffe_ids",
        "list of strings",
        "SPIFFE IDs refused as token subject, client or actor, and refused new tokens",
    ),
)

REVOKED_TOKEN = "revoked_token"  # noqa: S105 - audit reason, not a secret
BLOCKED_SPIFFE_ID = "blocked_spiffe_id"
UNAVAILABLE = "revocation_unavailable"


def _parse(data: bytes) -> tuple[frozenset[str], frozenset[str]]:
    if len(data) > MAX_REVOCATION_FILE_BYTES:
        raise ValueError("revocation file too large")
    value = yaml.safe_load(data.decode("utf-8")) if data.strip() else {}
    if not isinstance(value, dict) or not set(value) <= _KEYS:
        raise ValueError("revocation file must be a map with known keys only")
    lists: list[frozenset[str]] = []
    for key in ("revoked_jti", "blocked_spiffe_ids"):
        entries = value.get(key) or []
        if not isinstance(entries, list) or not all(
            isinstance(e, str) and 0 < len(e) <= 2048 for e in entries
        ):
            raise ValueError(f"{key} must be a list of non-empty strings")
        lists.append(frozenset(entries))
    if sum(len(entries) for entries in lists) > MAX_REVOCATION_ENTRIES:
        raise ValueError("too many revocation entries")
    return lists[0], lists[1]


@dataclass
class RevocationList:
    """Reads `path` again at most every `poll_seconds`; a changed file applies on the next check."""

    path: Path
    poll_seconds: float = DEFAULT_REVOCATION_POLL_SECONDS
    clock: Callable[[], float] = time.monotonic
    _jti: frozenset[str] = frozenset()
    _spiffe_ids: frozenset[str] = frozenset()
    _available: bool = False
    _digest: str | None = None
    _checked_at: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def load(
        cls, path: Path, poll_seconds: float = DEFAULT_REVOCATION_POLL_SECONDS
    ) -> RevocationList:
        """Strict first load: a missing or invalid file stops startup instead of allowing all."""
        revocations = cls(path, poll_seconds)
        revocations._jti, revocations._spiffe_ids = _parse(path.read_bytes())
        revocations._digest = hashlib.sha256(path.read_bytes()).hexdigest()
        revocations._available = True
        revocations._checked_at = revocations.clock()
        return revocations

    @property
    def available(self) -> bool:
        self.refresh()
        return self._available

    def refresh(self) -> None:
        with self._lock:
            now = self.clock()
            if self._checked_at is not None and now - self._checked_at < self.poll_seconds:
                return
            self._checked_at = now
            try:
                data = self.path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if digest == self._digest and self._available:
                    return
                self._jti, self._spiffe_ids = _parse(data)
            except (OSError, ValueError, UnicodeError, yaml.YAMLError):
                self._available = False
                self._digest = None
                return
            self._digest = digest
            self._available = True

    def check(self, *, jti: str | None, subjects: Iterable[str | None]) -> str | None:
        """None when allowed, otherwise a fixed audit reason."""
        self.refresh()
        if not self._available:
            return UNAVAILABLE
        if jti is not None and jti in self._jti:
            return REVOKED_TOKEN
        if any(s is not None and s in self._spiffe_ids for s in subjects):
            return BLOCKED_SPIFFE_ID
        return None


class TokenUseError(Exception):
    """A token exceeded its call limit, or the use store is full (fail closed)."""


@dataclass
class TokenUseCounter:
    """Counts tool calls per access token `jti` until the token expires.

    With `max_calls` = 1 each token authorizes one tool call, so a token copied after its
    legitimate use is refused. Memory is bounded by `max_entries`; when full of live tokens,
    new tokens are refused instead of forgetting counts.
    """

    max_calls: int
    max_entries: int = DEFAULT_TOKEN_USE_CACHE_SIZE
    _uses: dict[str, int] = field(default_factory=dict)
    _heap: list[tuple[float, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.max_calls < 1 or self.max_entries < 1:
            raise ValueError("token use limits must be positive")

    def __len__(self) -> int:
        return len(self._uses)

    def consume(self, jti: str, expires_at: float, calls: int, now: float) -> None:
        with self._lock:
            while self._heap and self._heap[0][0] <= now:
                _, old = heapq.heappop(self._heap)
                self._uses.pop(old, None)
            used = self._uses.get(jti)
            if used is None and len(self._uses) >= self.max_entries:
                raise TokenUseError("token_use_store_full")
            if (used or 0) + calls > self.max_calls:
                raise TokenUseError("token_call_limit_reached")
            if used is None:
                heapq.heappush(self._heap, (expires_at, jti))
            self._uses[jti] = (used or 0) + calls
