"""Append-only, hash-chained JSON lines audit log, and its verifier.

Chain construction follows draft-sharif-agent-audit-trail-05: every record carries a random
`record_id`, the previous record's id as `parent_record_id` and `prev_hash` =
hex(SHA-256(JCS(previous record as stored))). The genesis record has both set to null. The
field set is this project's own, not the full AAT record.

One writer per file. Resuming checks the entire existing chain and refuses every write while
that chain is invalid or its last line lacks a trailing newline. A separately protected
terminal checkpoint detects suffix deletion and chain replacement up to that checkpoint.
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
FIELDS = {
    "record_id",
    "parent_record_id",
    "prev_hash",
    "timestamp",
    "component",
    "spiffe_id",
    "tool",
    "decision",
    "reason",
}


def _valid_record(record: Any) -> bool:
    if not isinstance(record, dict) or set(record) != FIELDS:
        return False
    if any(
        not isinstance(record[k], str)
        for k in ("record_id", "timestamp", "component", "decision", "reason")
    ):
        return False
    if any(
        record[k] is not None and not isinstance(record[k], str)
        for k in ("parent_record_id", "prev_hash", "spiffe_id", "tool")
    ):
        return False
    try:
        for value in record.values():
            if isinstance(value, str):
                value.encode("utf-8")
    except UnicodeError:
        return False
    try:
        stamp = datetime.fromisoformat(record["timestamp"])
    except ValueError:
        return False
    return bool(record["record_id"]) and stamp.utcoffset() is not None


@dataclass(frozen=True)
class Checkpoint:
    """Trusted terminal state, stored outside the log writer's control."""

    records: int
    last_record_id: str | None
    last_hash: str | None

    def to_json(self) -> str:
        return (
            json.dumps(
                {
                    "version": 1,
                    "records": self.records,
                    "last_record_id": self.last_record_id,
                    "last_hash": self.last_hash,
                },
                sort_keys=True,
            )
            + "\n"
        )

    @classmethod
    def from_json(cls, text: str) -> Checkpoint:
        value = json.loads(text)
        if not isinstance(value, dict) or set(value) != {
            "version",
            "records",
            "last_record_id",
            "last_hash",
        }:
            raise ValueError("invalid checkpoint")
        n, rid, digest = value["records"], value["last_record_id"], value["last_hash"]
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError("invalid checkpoint")
        if type(n) is not int or n < 0:
            raise ValueError("invalid checkpoint")
        if n == 0:
            if rid is not None or digest is not None:
                raise ValueError("invalid checkpoint")
        elif (
            not isinstance(rid, str)
            or not rid
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("invalid checkpoint")
        return cls(n, rid, digest)


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
        # Marked loaded only after a clean chain check, so a corrupt file fails every write.
        if self._loaded:
            return
        if self.path is None or not self.path.exists():
            self._loaded = True
            return
        data = self.path.read_text(encoding="utf-8")
        if data and not data.endswith("\n"):
            raise AuditChainError("existing audit chain has an incomplete last line")
        lines = data.splitlines()
        _, problems = verify_lines(lines)
        if problems:
            raise AuditChainError("existing audit chain is invalid")
        self._last = json.loads(lines[-1]) if lines else None
        self._loaded = True


def verify_lines(
    lines: Iterable[str], checkpoint: Checkpoint | None = None
) -> tuple[int, list[str]]:
    """Check links and, if supplied, the exact terminal state trusted by the operator."""
    problems: list[str] = []
    previous: Record | None = None
    count = 0
    seen: set[str] = set()
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
        if not _valid_record(record):
            problems.append(f"line {number}: invalid record schema")
            previous = None
            continue
        count += 1
        if record["record_id"] in seen:
            problems.append(f"line {number}: duplicate record_id")
        seen.add(record["record_id"])
        expected_parent = previous["record_id"] if previous else None
        expected_hash = record_hash(previous) if previous else None
        if record.get("parent_record_id") != expected_parent:
            problems.append(f"line {number}: parent_record_id does not match the previous record")
        if record.get("prev_hash") != expected_hash:
            problems.append(f"line {number}: prev_hash does not match the previous record")
        if previous and datetime.fromisoformat(record["timestamp"]) < datetime.fromisoformat(
            previous["timestamp"]
        ):
            problems.append(f"line {number}: timestamp earlier than the previous record")
        previous = record
    if checkpoint is not None:
        terminal = Checkpoint(
            count,
            previous["record_id"] if previous else None,
            record_hash(previous) if previous else None,
        )
        if terminal != checkpoint:
            problems.append("terminal state does not match trusted checkpoint")
    return count, problems


def create_checkpoint(lines: Iterable[str]) -> Checkpoint:
    materialized = list(lines)
    count, problems = verify_lines(materialized)
    if problems:
        raise AuditChainError("cannot checkpoint an invalid audit chain")
    last = json.loads(materialized[-1]) if materialized else None
    return Checkpoint(
        count, last["record_id"] if last else None, record_hash(last) if last else None
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-audit-verify",
        description="Verify the hash chain of audit log files written with --audit-log",
    )
    parser.add_argument("files", nargs="+", type=Path, help="audit log files, one chain each")
    options = parser.add_mutually_exclusive_group()
    options.add_argument(
        "--checkpoint",
        type=Path,
        help="verify one complete log against a separately trusted terminal checkpoint",
    )
    options.add_argument(
        "--write-checkpoint",
        type=Path,
        help="create a new terminal checkpoint for one valid log; refuses to overwrite",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.checkpoint or args.write_checkpoint) and len(args.files) != 1:
        parser.error("a checkpoint requires exactly one log file")
    checkpoint = None
    if args.checkpoint:
        try:
            checkpoint = Checkpoint.from_json(args.checkpoint.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("checkpoint cannot be read or is invalid")
            sys.exit(1)
    failed = False
    for path in args.files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            print("audit log cannot be read")
            failed = True
            continue
        count, problems = verify_lines(lines, checkpoint)
        if args.write_checkpoint and not problems:
            try:
                with args.write_checkpoint.open("x", encoding="utf-8") as output:
                    output.write(create_checkpoint(lines).to_json())
            except OSError:
                problems.append(
                    "checkpoint cannot be created; existing files are never overwritten"
                )
        for problem in problems:
            print(f"{path}: {problem}")
        print(f"{path}: {count} records, {'intact' if not problems else 'BROKEN'}")
        failed = failed or bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
