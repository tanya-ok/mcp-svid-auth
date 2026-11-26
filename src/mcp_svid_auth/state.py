"""Replay and rate-limit state shared by replicas, with fail-closed semantics.

The in-process classes (`ReplayCache`, `ProofReplayStore`, `TokenUseCounter`, `WindowBudget`)
stay the default. With a `SharedState`, they delegate to it so every replica sees the same
seen-sets and counters. Any store error raises `StateUnavailableError`; callers deny the
request instead of skipping the check.

`ValkeyState` works with Valkey and Redis 7+. Each operation is one atomic command or script.
The store must not evict keys (`maxmemory-policy noeviction`): an evicted replay entry would
let a credential pass twice, so startup refuses any other policy it can read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mcp_svid_auth.files import MAX_KEY_FILE_BYTES, MAX_SECRET_FILE_BYTES, read_file

DEFAULT_PREFIX = "mcp-svid-auth"
_ADD_UP_TO = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local amount = tonumber(ARGV[1])
if current + amount > tonumber(ARGV[2]) then
  return 0
end
redis.call('INCRBY', KEYS[1], amount)
if current == 0 then
  redis.call('PEXPIREAT', KEYS[1], ARGV[3])
end
return 1
"""


class StateUnavailableError(Exception):
    """The shared store could not answer; the caller must deny."""


class SharedState(Protocol):
    def add_once(self, namespace: str, key: str, expires_at: float) -> bool:
        """Record `key` until `expires_at` (Unix seconds). False if it was already recorded."""
        ...

    def add_up_to(
        self, namespace: str, key: str, amount: int, limit: int, expires_at: float
    ) -> bool:
        """Add `amount` to a counter kept until `expires_at` unless the result exceeds `limit`."""
        ...

    def ping(self) -> None: ...


@dataclass
class ValkeyState:
    """SharedState on a Valkey or Redis server through redis-py."""

    client: Any
    prefix: str = DEFAULT_PREFIX

    def __post_init__(self) -> None:
        self._script = self.client.register_script(_ADD_UP_TO)

    @classmethod
    def from_url(  # noqa: PLR0913
        cls,
        url: str,
        *,
        prefix: str = DEFAULT_PREFIX,
        password_file: Path | None = None,
        ca_file: Path | None = None,
        cert_file: Path | None = None,
        key_file: Path | None = None,
        timeout: float = 2.0,
    ) -> ValkeyState:
        """Connect and check the eviction policy. TLS (`rediss://`) keeps certificate checks."""
        import redis  # noqa: PLC0415 - optional dependency

        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            raise ValueError("put the store password in a file, not in the URL")
        options: dict[str, Any] = {
            "socket_timeout": timeout,
            "socket_connect_timeout": timeout,
            "retry_on_timeout": False,
        }
        if password_file is not None:
            secret = read_file(password_file, max_bytes=MAX_SECRET_FILE_BYTES, private=True)
            options["password"] = secret.decode("utf-8").strip()
        if url.startswith("rediss://"):
            options["ssl_cert_reqs"] = "required"
            options["ssl_check_hostname"] = True
            if ca_file is not None:
                read_file(ca_file, max_bytes=MAX_KEY_FILE_BYTES)
                options["ssl_ca_certs"] = str(ca_file)
            if cert_file is not None:
                read_file(cert_file, max_bytes=MAX_KEY_FILE_BYTES)
                if key_file is not None:
                    read_file(key_file, max_bytes=MAX_KEY_FILE_BYTES, private=True)
                options["ssl_certfile"] = str(cert_file)
                options["ssl_keyfile"] = str(key_file) if key_file else None
        elif ca_file or cert_file:
            raise ValueError("store TLS options need a rediss:// URL")
        state = cls(redis.Redis.from_url(url, **options), prefix)
        state.check_eviction_policy()
        return state

    def _key(self, namespace: str, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest()
        return f"{self.prefix}:{namespace}:{digest}"

    def _call(self, operation: Any) -> Any:
        try:
            return operation()
        except Exception as exc:  # any client or server error must deny
            raise StateUnavailableError(type(exc).__name__) from exc

    def add_once(self, namespace: str, key: str, expires_at: float) -> bool:
        stored = self._call(
            lambda: self.client.set(
                self._key(namespace, key), b"1", nx=True, pxat=_millis(expires_at)
            )
        )
        return bool(stored)

    def add_up_to(
        self, namespace: str, key: str, amount: int, limit: int, expires_at: float
    ) -> bool:
        result = self._call(
            lambda: self._script(
                keys=[self._key(namespace, key)], args=[amount, limit, _millis(expires_at)]
            )
        )
        return int(result) == 1

    def ping(self) -> None:
        self._call(self.client.ping)

    def check_eviction_policy(self) -> None:
        """Refuse a store that evicts keys; announce when the policy cannot be read."""
        try:
            policy = self.client.config_get("maxmemory-policy").get("maxmemory-policy")
        except Exception as exc:
            self.ping()
            print(
                json.dumps({"event": "store_policy_unknown", "error": type(exc).__name__}),
                file=sys.stderr,
            )
            return
        if policy != "noeviction":
            raise StateUnavailableError("store maxmemory-policy must be noeviction")


def _millis(expires_at: float) -> int:
    return max(1, int(expires_at * 1000) + 1)


def add_state_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-store-url",
        help="redis:// or rediss:// URL of a Valkey or Redis store shared by replicas; "
        "default in-process state",
    )
    parser.add_argument(
        "--state-store-password-file", type=Path, help="file holding the store password"
    )
    parser.add_argument("--state-store-ca-file", type=Path, help="PEM CA bundle for rediss://")
    parser.add_argument(
        "--state-store-cert", type=Path, help="PEM client certificate for store mTLS"
    )
    parser.add_argument("--state-store-key", type=Path, help="PEM key for --state-store-cert")
    parser.add_argument(
        "--state-store-prefix",
        default=DEFAULT_PREFIX,
        help="key prefix; replicas of one deployment must use the same value",
    )


def state_from_args(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> SharedState | None:
    if not args.state_store_url:
        if any((args.state_store_password_file, args.state_store_ca_file, args.state_store_cert)):
            parser.error("store options need --state-store-url")
        return None
    if (args.state_store_cert is None) != (args.state_store_key is None):
        parser.error("--state-store-cert and --state-store-key must be given together")
    try:
        return ValkeyState.from_url(
            args.state_store_url,
            prefix=args.state_store_prefix,
            password_file=args.state_store_password_file,
            ca_file=args.state_store_ca_file,
            cert_file=args.state_store_cert,
            key_file=args.state_store_key,
        )
    except (ValueError, OSError, StateUnavailableError) as exc:
        parser.error(f"state store unusable: {exc}")
