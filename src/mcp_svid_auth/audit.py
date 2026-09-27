"""Append-only, hash-chained JSON lines audit log, and its verifier.

Chain construction follows draft-sharif-agent-audit-trail-05: every record carries a random
`record_id`, the previous record's id as `parent_record_id` and `prev_hash` =
hex(SHA-256(JCS(previous record as stored))). The genesis record has both set to null. The
field set is this project's own, not the full AAT record.

One writer per file. A writer that opens an existing file continues its chain from the last
line and refuses to write if that line does not parse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

Record = dict[str, Any]


def canonical(record: Record) -> bytes:
    """RFC 8785 (JCS) serialization for the value types audit records use: strings and null."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def record_hash(record: Record) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


class AuditChainError(Exception):
    """An existing audit file cannot be continued."""


@dataclass
class AuditLog:
    """Writes one hash-chained JSON object per line. Path None means stderr."""

    path: Path | None = None
    component: str = "mcp_server"
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last: Record | None = None
    _loaded: bool = False

    def write(
        self, *, spiffe_id: str | None, tool: str | None, decision: str, reason: str
    ) -> Record:
        with self._lock:
            self._load_tail()
            last = self._last
            entry: Record = {
                "record_id": str(uuid.uuid4()),
                "parent_record_id": last["record_id"] if last else None,
                "prev_hash": record_hash(last) if last else None,
                "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "component": self.component,
                "spiffe_id": spiffe_id,
                "tool": tool,
                "decision": decision,
                "reason": reason,
            }
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n"
            if self.path is None:
                sys.stderr.write(line)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            self._last = entry
        return entry

    def _load_tail(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.path is None or not self.path.exists():
            return
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return
        try:
            last = json.loads(lines[-1])
        except ValueError as exc:
            raise AuditChainError(f"{self.path}: last line is not JSON") from exc
        if not isinstance(last, dict) or not isinstance(last.get("record_id"), str):
            raise AuditChainError(f"{self.path}: last line is not a chained record")
        self._last = last


def verify_lines(lines: Iterable[str]) -> tuple[int, list[str]]:
    """Check a chain. Returns (records checked, problems); no problems means intact."""
    problems: list[str] = []
    previous: Record | None = None
    count = 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            problems.append(f"line {number}: empty line")
            continue
        try:
            record = json.loads(line)
        except ValueError:
            problems.append(f"line {number}: not JSON")
            previous = None
            continue
        if not isinstance(record, dict):
            problems.append(f"line {number}: not an object")
            previous = None
            continue
        count += 1
        expected_parent = previous["record_id"] if previous else None
        expected_hash = record_hash(previous) if previous else None
        if record.get("parent_record_id") != expected_parent:
            problems.append(f"line {number}: parent_record_id does not match the previous record")
        if record.get("prev_hash") != expected_hash:
            problems.append(f"line {number}: prev_hash does not match the previous record")
        if previous and str(record.get("timestamp", "")) < str(previous.get("timestamp", "")):
            problems.append(f"line {number}: timestamp earlier than the previous record")
        previous = record
    return count, problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-audit-verify",
        description="Verify the hash chain of audit log files written with --audit-log",
    )
    parser.add_argument("files", nargs="+", type=Path, help="audit log files, one chain each")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    failed = False
    for path in args.files:
        count, problems = verify_lines(path.read_text(encoding="utf-8").splitlines())
        for problem in problems:
            print(f"{path}: {problem}")
        print(f"{path}: {count} records, {'intact' if not problems else 'BROKEN'}")
        failed = failed or bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
