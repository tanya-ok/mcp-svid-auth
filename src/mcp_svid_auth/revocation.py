"""Access token revocation by `jti` and SPIFFE ID, and per-token tool call limits.

Both are per process and in memory. The revocation file is the shared source: every replica
that reads the same file converges within `poll_seconds`. A file that cannot be read or parsed
denies every check (fail closed) until a valid file is seen again.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import heapq
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcp_svid_auth.files import MAX_KEY_FILE_BYTES, read_file
from mcp_svid_auth.state import SharedState, StateUnavailableError

MAX_REVOCATION_FILE_BYTES = 1024 * 1024
MAX_REVOCATION_ENTRIES = 100_000
DEFAULT_REVOCATION_POLL_SECONDS = 5.0
DEFAULT_TOKEN_USE_CACHE_SIZE = 100_000
DEFAULT_TOKEN_USE_SUBJECT_LIMIT = 1000
MIN_POLL_SECONDS = 0.5
MAX_POLL_SECONDS = 300.0
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
    # An empty file is what a non-atomic rewrite leaves behind: refuse it, never "revoke nothing".
    value = yaml.safe_load(data.decode("utf-8")) if data.strip() else None
    if not isinstance(value, dict) or set(value) != _KEYS:
        raise ValueError("revocation file must be a map with exactly the known keys")
    lists: list[frozenset[str]] = []
    for key in ("revoked_jti", "blocked_spiffe_ids"):
        entries = value[key] if value[key] is not None else []
        if not isinstance(entries, list) or not all(
            isinstance(e, str) and 0 < len(e) <= 2048 for e in entries
        ):
            raise ValueError(f"{key} must be a list of non-empty strings")
        lists.append(frozenset(entries))
    if sum(len(entries) for entries in lists) > MAX_REVOCATION_ENTRIES:
        raise ValueError("too many revocation entries")
    return lists[0], lists[1]


def load_revocation_key(path: Path | None) -> Ed25519PublicKey | None:
    if path is None:
        return None
    key = serialization.load_pem_public_key(read_file(path, max_bytes=MAX_KEY_FILE_BYTES))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("revocation public key must be Ed25519")
    return key


def poll_seconds_arg(value: str) -> float:
    """argparse type for --revocation-poll-seconds: finite, within the supported range."""
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if not MIN_POLL_SECONDS <= number <= MAX_POLL_SECONDS:
        raise argparse.ArgumentTypeError(
            f"must be between {MIN_POLL_SECONDS} and {MAX_POLL_SECONDS} seconds"
        )
    return number


@dataclass
class RevocationList:
    """Reads `path` again at most every `poll_seconds`; a changed file applies on the next check.

    With `public_key`, the file must carry a detached Ed25519 signature in `<path>.sig`
    (base64 of the raw signature over the exact file bytes); otherwise every check fails closed.
    """

    path: Path
    poll_seconds: float = DEFAULT_REVOCATION_POLL_SECONDS
    clock: Callable[[], float] = time.monotonic
    public_key: Ed25519PublicKey | None = None
    _jti: frozenset[str] = frozenset()
    _spiffe_ids: frozenset[str] = frozenset()
    _available: bool = False
    _digest: str | None = None
    _checked_at: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if not MIN_POLL_SECONDS <= self.poll_seconds <= MAX_POLL_SECONDS:
            raise ValueError("revocation poll interval out of range")

    @classmethod
    def load(
        cls,
        path: Path,
        poll_seconds: float = DEFAULT_REVOCATION_POLL_SECONDS,
        public_key: Ed25519PublicKey | None = None,
    ) -> RevocationList:
        """Strict first load: a missing or invalid file stops startup instead of allowing all."""
        revocations = cls(path, poll_seconds, public_key=public_key)
        data = revocations._read()
        revocations._jti, revocations._spiffe_ids = _parse(data)
        revocations._digest = hashlib.sha256(data).hexdigest()
        revocations._available = True
        revocations._checked_at = revocations.clock()
        return revocations

    def _read(self) -> bytes:
        """One bounded, no-follow read; the parsed and hashed bytes are the same bytes."""
        data = read_file(self.path, max_bytes=MAX_REVOCATION_FILE_BYTES)
        if self.public_key is not None:
            signature_path = self.path.with_name(self.path.name + ".sig")
            encoded = read_file(signature_path, max_bytes=512).strip()
            try:
                self.public_key.verify(base64.b64decode(encoded, validate=True), data)
            except (InvalidSignature, ValueError) as exc:
                raise ValueError("revocation file signature invalid") from exc
        return data

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
                data = self._read()
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
    shared: SharedState | None = None
    # Live tokens one subject may hold in the in-process store, so one workload cannot fill it.
    per_subject_limit: int = DEFAULT_TOKEN_USE_SUBJECT_LIMIT
    _uses: dict[str, int] = field(default_factory=dict)
    _owners: dict[str, str] = field(default_factory=dict)
    _subjects: dict[str, int] = field(default_factory=dict)
    _heap: list[tuple[float, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.max_calls < 1 or self.max_entries < 1 or self.per_subject_limit < 1:
            raise ValueError("token use limits must be positive")

    def __len__(self) -> int:
        return len(self._uses)

    def consume(
        self, jti: str, expires_at: float, calls: int, now: float, subject: str = ""
    ) -> None:
        if self.shared is not None:
            try:
                within = self.shared.add_up_to("calls", jti, calls, self.max_calls, expires_at)
            except StateUnavailableError:
                raise TokenUseError("token_use_store_unavailable") from None
            if not within:
                raise TokenUseError("token_call_limit_reached")
            return
        with self._lock:
            while self._heap and self._heap[0][0] <= now:
                _, old = heapq.heappop(self._heap)
                self._uses.pop(old, None)
                owner = self._owners.pop(old, None)
                if owner is not None:
                    self._subjects[owner] -= 1
                    if not self._subjects[owner]:
                        del self._subjects[owner]
            used = self._uses.get(jti)
            if used is None and self._subjects.get(subject, 0) >= self.per_subject_limit:
                raise TokenUseError("token_use_subject_limit_reached")
            if used is None and len(self._uses) >= self.max_entries:
                raise TokenUseError("token_use_store_full")
            if (used or 0) + calls > self.max_calls:
                raise TokenUseError("token_call_limit_reached")
            if used is None:
                heapq.heappush(self._heap, (expires_at, jti))
                self._owners[jti] = subject
                self._subjects[subject] = self._subjects.get(subject, 0) + 1
            self._uses[jti] = (used or 0) + calls
