"""Fixed-window cost bounds, independent of unverified identities.

Per process by default. With a shared store the window is wall-clock seconds and the count is
shared by every replica; a store error refuses the request.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_svid_auth.state import SharedState, StateUnavailableError


@dataclass
class WindowBudget:
    limit: int
    max_keys: int = 10_000
    clock: Callable[[], float] = time.monotonic
    shared: SharedState | None = None
    name: str = "budget"
    wall_clock: Callable[[], float] = time.time
    _window: int = -1
    _counts: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.limit < 1 or self.max_keys < 1:
            raise ValueError("request budgets must be positive")

    def take(self, key: str = "global") -> bool:
        if self.shared is not None:
            window = int(self.wall_clock())
            try:
                return self.shared.add_up_to(
                    self.name, f"{window}\n{key}", 1, self.limit, window + 2
                )
            except StateUnavailableError:
                return False
        with self._lock:
            window = int(self.clock())
            if window != self._window:
                self._counts.clear()
                self._window = window
            count = self._counts.get(key, 0)
            if count >= self.limit or (
                key not in self._counts and len(self._counts) >= self.max_keys
            ):
                return False
            self._counts[key] = count + 1
            return True
