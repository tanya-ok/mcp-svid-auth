"""Append-only JSON lines audit log."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class AuditLog:
    """Writes one JSON object per line. Path None means stderr."""

    path: Path | None = None
    component: str = "mcp_server"
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def write(
        self, *, spiffe_id: str | None, tool: str | None, decision: str, reason: str
    ) -> dict[str, str | None]:
        entry: dict[str, str | None] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "component": self.component,
            "spiffe_id": spiffe_id,
            "tool": tool,
            "decision": decision,
            "reason": reason,
        }
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with self._lock:
            if self.path is None:
                sys.stderr.write(line)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        return entry
