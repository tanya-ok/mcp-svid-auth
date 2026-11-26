"""Append-only, hash-chained JSON lines audit log, and its verifier.

Chain construction follows draft-sharif-agent-audit-trail-05: every record carries a random
`record_id`, the previous record's id as `parent_record_id` and `prev_hash` =
hex(SHA-256(JCS(previous record as stored))). The genesis record has both set to null. The
field set is this project's own, not the full AAT record; see
docs/architecture/contracts/audit-event.md.

One writer per file, enforced with an exclusive lock on `<file>.lock`; each replica writes its
own file and names itself in `replica_id`. Every record is flushed and fsynced. Resuming checks
the links of the last `TAIL_BYTES` of the file and refuses every write while they are invalid
or the last line lacks a trailing newline; `mcp-svid-audit-verify` checks the whole file.

A terminal checkpoint detects suffix deletion and chain replacement up to that checkpoint. A
signed checkpoint carries a sequence number, a creation time and the hash of the previous
checkpoint; a verifier that also enforces a high-water mark (`--min-sequence`, `--min-records`
or `--max-age`) detects an older genuine checkpoint presented with a truncated log.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import socket
import sys
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcp_svid_auth.files import MAX_KEY_FILE_BYTES, read_file

Record = dict[str, Any]
SCHEMA_VERSION = "2"
FIELDS_V1 = {
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
FIELDS = FIELDS_V1 | {"schema_version", "replica_id"}
TAIL_BYTES = 1024 * 1024
MAX_CHECKPOINT_BYTES = 4096
_HEX = frozenset("0123456789" + "abcdef")


def _valid_shape(record: Any) -> bool:
    if not isinstance(record, dict) or set(record) not in (FIELDS_V1, FIELDS):
        return False
    required = ["record_id", "timestamp", "component", "decision", "reason"]
    if "schema_version" in record:
        if record["schema_version"] != SCHEMA_VERSION:
            return False
        required.append("replica_id")
    return all(isinstance(record[k], str) for k in required)


def _valid_record(record: Any) -> bool:
    if not _valid_shape(record):
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


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


@dataclass(frozen=True)
class Checkpoint:
    """Trusted terminal state of one log file.

    Version 1 is unsigned: records, last record ID and hash. Version 2 is signed by an Ed25519
    checkpoint key the log writer never holds, and adds `sequence`, `created_at` and
    `previous` (SHA-256 of the previous signed checkpoint), so checkpoints form a chain.
    """

    records: int
    last_record_id: str | None
    last_hash: str | None
    key_id: str | None = None
    signature: str | None = None
    sequence: int = 0
    created_at: str | None = None
    previous: str | None = None

    @property
    def signed(self) -> bool:
        return self.signature is not None

    def terminal(self) -> tuple[int, str | None, str | None]:
        return self.records, self.last_record_id, self.last_hash

    def _signed_body(self) -> dict[str, Any]:
        return {
            "version": 2,
            "records": self.records,
            "last_record_id": self.last_record_id,
            "last_hash": self.last_hash,
            "key_id": self.key_id,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "previous": self.previous,
        }

    def to_json(self) -> str:
        if not self.signed:
            body: dict[str, Any] = {
                "version": 1,
                "records": self.records,
                "last_record_id": self.last_record_id,
                "last_hash": self.last_hash,
            }
        else:
            body = {**self._signed_body(), "signature": self.signature}
        return json.dumps(body, sort_keys=True) + "\n"

    def digest(self) -> str:
        """Identifier used as `previous` by the next checkpoint."""
        return hashlib.sha256(canonical(self._signed_body())).hexdigest()

    def sign(
        self,
        key: Ed25519PrivateKey,
        *,
        previous: Checkpoint | None = None,
        now: datetime | None = None,
    ) -> Checkpoint:
        unsigned = replace(
            self,
            key_id=public_key_id(key.public_key()),
            sequence=(previous.sequence + 1) if previous else 1,
            created_at=(now or datetime.now(UTC)).isoformat(timespec="seconds"),
            previous=previous.digest() if previous else None,
            signature=None,
        )
        raw = key.sign(_signed_bytes(unsigned))
        return replace(unsigned, signature=base64.urlsafe_b64encode(raw).rstrip(b"=").decode())

    def signature_valid(self, key: Ed25519PublicKey) -> bool:
        if self.signature is None or self.key_id != public_key_id(key):
            return False
        try:
            raw = base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
            key.verify(raw, _signed_bytes(self))
        except (InvalidSignature, ValueError):
            return False
        return True

    @classmethod
    def from_json(cls, text: str) -> Checkpoint:
        value = json.loads(text)
        base = {"version", "records", "last_record_id", "last_hash"}
        signed_keys = base | {"key_id", "signature", "sequence", "created_at", "previous"}
        if not isinstance(value, dict) or set(value) not in (base, signed_keys):
            raise ValueError("invalid checkpoint")
        n, rid, digest = value["records"], value["last_record_id"], value["last_hash"]
        signed = "signature" in value
        if type(value["version"]) is not int or value["version"] != (2 if signed else 1):
            raise ValueError("invalid checkpoint")
        if type(n) is not int or n < 0:
            raise ValueError("invalid checkpoint")
        if n == 0:
            if rid is not None or digest is not None:
                raise ValueError("invalid checkpoint")
        elif not isinstance(rid, str) or not rid or not _is_digest(digest):
            raise ValueError("invalid checkpoint")
        if not signed:
            return cls(n, rid, digest)
        key_id, signature = value["key_id"], value["signature"]
        sequence, created_at, previous = value["sequence"], value["created_at"], value["previous"]
        if not isinstance(key_id, str) or not isinstance(signature, str) or not signature:
            raise ValueError("invalid checkpoint")
        if type(sequence) is not int or sequence < 1:
            raise ValueError("invalid checkpoint")
        if (sequence == 1) != (previous is None) or (
            previous is not None and not _is_digest(previous)
        ):
            raise ValueError("invalid checkpoint")
        try:
            stamp = datetime.fromisoformat(created_at)
        except (TypeError, ValueError):
            raise ValueError("invalid checkpoint") from None
        if stamp.utcoffset() is None:
            raise ValueError("invalid checkpoint")
        return cls(n, rid, digest, key_id, signature, sequence, created_at, previous)


def _signed_bytes(checkpoint: Checkpoint) -> bytes:
    """Domain-separated JCS bytes of every field except the signature."""
    return b"mcp-svid-auth audit checkpoint\n" + canonical(checkpoint._signed_body())


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:32]


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    data = read_file(path, max_bytes=MAX_KEY_FILE_BYTES, private=True)
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("checkpoint signing key must be Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(read_file(path, max_bytes=MAX_KEY_FILE_BYTES))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("checkpoint public key must be Ed25519")
    return key


def canonical(record: Record) -> bytes:
    """RFC 8785 (JCS) serialization for audit values: strings, null and small integers."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def record_hash(record: Record) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


class AuditChainError(Exception):
    """An existing audit file cannot be continued."""


def default_replica_id() -> str:
    return os.environ.get("HOSTNAME") or socket.gethostname() or "replica"


@dataclass
class AuditLog:
    """Writes one hash-chained JSON object per line. Path None means stderr."""

    path: Path | None = None
    component: str = "mcp_server"
    replica_id: str = field(default_factory=default_replica_id)
    fsync: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last: Record | None = None
    _loaded: bool = False
    _writer_lock: int | None = None

    def write(
        self, *, spiffe_id: str | None, tool: str | None, decision: str, reason: str
    ) -> Record:
        with self._lock:
            self._load_tail()
            last = self._last
            entry: Record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": str(uuid.uuid4()),
                "parent_record_id": last["record_id"] if last else None,
                "prev_hash": record_hash(last) if last else None,
                "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "component": self.component,
                "replica_id": self.replica_id,
                "spiffe_id": spiffe_id,
                "tool": tool,
                "decision": decision,
                "reason": reason,
            }
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n"
            if self.path is None:
                sys.stderr.write(line)
            else:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    if self.fsync:
                        os.fsync(fh.fileno())
            self._last = entry
        return entry

    def close(self) -> None:
        with self._lock:
            if self._writer_lock is not None:
                os.close(self._writer_lock)
                self._writer_lock = None
            self._loaded = False
            self._last = None

    def _acquire_writer_lock(self, path: Path) -> None:
        lock_path = path.with_name(path.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise AuditChainError("another writer holds this audit log") from None
        self._writer_lock = fd

    def _load_tail(self) -> None:
        # Marked loaded only after a clean tail check, so a corrupt file fails every write.
        if self._loaded:
            return
        if self.path is None:
            self._loaded = True
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._writer_lock is None:
            self._acquire_writer_lock(self.path)
        lines = _tail_lines(self.path)
        problems = _link_problems(lines)
        if problems:
            raise AuditChainError("existing audit chain is invalid")
        self._last = json.loads(lines[-1]) if lines else None
        self._loaded = True


def _tail_lines(path: Path) -> list[str]:
    """Complete lines of the last TAIL_BYTES; refuses an unterminated last line."""
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            start = max(0, size - TAIL_BYTES)
            handle.seek(start)
            data = handle.read()
    except FileNotFoundError:
        return []
    if data and not data.endswith(b"\n"):
        raise AuditChainError("existing audit chain has an incomplete last line")
    lines = data.decode("utf-8").splitlines()
    return lines[1:] if start > 0 else lines


def _link_problems(lines: list[str]) -> list[str]:
    """Schema and links between consecutive records only (no genesis requirement)."""
    problems: list[str] = []
    previous: Record | None = None
    for number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except ValueError:
            return [f"line {number}: not JSON"]
        if not _valid_record(record):
            return [f"line {number}: invalid record schema"]
        if previous is not None and (
            record["parent_record_id"] != previous["record_id"]
            or record["prev_hash"] != record_hash(previous)
        ):
            problems.append(f"line {number}: link does not match the previous record")
        previous = record
    return problems


def _expected_link(
    previous: Record | None, count: int, continues_from: Checkpoint | None
) -> tuple[str | None, str | None]:
    if previous is not None:
        return previous["record_id"], record_hash(previous)
    if count == 1 and continues_from is not None:
        return continues_from.last_record_id, continues_from.last_hash
    return None, None


def verify_lines(
    lines: Iterable[str],
    checkpoint: Checkpoint | None = None,
    *,
    continues_from: Checkpoint | None = None,
) -> tuple[int, list[str]]:
    """Check links and, if supplied, the exact terminal state trusted by the operator.

    `continues_from` is the checkpoint of the file this one was rotated from: the first record
    must then link to its last record instead of being a genesis record.
    """
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
        expected_parent, expected_hash = _expected_link(previous, count, continues_from)
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
        terminal = (
            count,
            previous["record_id"] if previous else None,
            record_hash(previous) if previous else None,
        )
        if terminal != checkpoint.terminal():
            problems.append("terminal state does not match trusted checkpoint")
    return count, problems


def create_checkpoint(
    lines: Iterable[str], *, continues_from: Checkpoint | None = None
) -> Checkpoint:
    materialized = list(lines)
    count, problems = verify_lines(materialized, continues_from=continues_from)
    if problems:
        raise AuditChainError("cannot checkpoint an invalid audit chain")
    last = json.loads(materialized[-1]) if materialized else None
    return Checkpoint(
        count, last["record_id"] if last else None, record_hash(last) if last else None
    )


def _ancestor_problem(lines: list[str], previous: Checkpoint) -> str | None:
    """The previous checkpoint's terminal record must appear at its position in this file."""
    if previous.records == 0:
        return None
    if previous.records > len(lines):
        return "previous checkpoint covers more records than this log"
    record = json.loads(lines[previous.records - 1])
    if (record.get("record_id"), record_hash(record)) != (
        previous.last_record_id,
        previous.last_hash,
    ):
        return "previous checkpoint is not an ancestor of this log"
    return None


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
    parser.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 PEM private key that signs a new checkpoint; keep it away from log writers",
    )
    parser.add_argument(
        "--previous-checkpoint",
        type=Path,
        help="with --write-checkpoint: last signed checkpoint, so the new one continues its chain",
    )
    parser.add_argument(
        "--checkpoint-public-key",
        type=Path,
        help="Ed25519 PEM public key; checkpoints must carry a valid signature by it",
    )
    parser.add_argument(
        "--continues-from",
        type=Path,
        help="checkpoint of the file this log was rotated from; its last record is the parent",
    )
    parser.add_argument(
        "--min-sequence",
        type=int,
        help="high-water mark: refuse a signed checkpoint with a lower sequence",
    )
    parser.add_argument(
        "--min-records", type=int, help="high-water mark: refuse fewer records than this"
    )
    parser.add_argument(
        "--max-age",
        type=int,
        metavar="SECONDS",
        help="refuse a signed checkpoint created longer ago than this",
    )
    return parser


def _load_checkpoint(path: Path, public_key: Ed25519PublicKey | None, label: str) -> Checkpoint:
    """Load a checkpoint; with a public key its signature must verify. Exits on error."""
    try:
        data = read_file(path, max_bytes=MAX_CHECKPOINT_BYTES)
        checkpoint = Checkpoint.from_json(data.decode("utf-8"))
    except (ValueError, UnicodeError):
        print(f"{label} cannot be read or is invalid")
        sys.exit(1)
    if public_key is not None and not checkpoint.signature_valid(public_key):
        print(f"{label} signature is missing or invalid")
        sys.exit(1)
    return checkpoint


def _freshness_problems(
    checkpoint: Checkpoint | None, count: int, args: argparse.Namespace
) -> list[str]:
    problems: list[str] = []
    if args.min_records is not None and count < args.min_records:
        problems.append(f"fewer records than the high-water mark {args.min_records}")
    if checkpoint is None:
        return problems
    if args.min_sequence is not None and (
        not checkpoint.signed or checkpoint.sequence < args.min_sequence
    ):
        problems.append(f"checkpoint sequence below the high-water mark {args.min_sequence}")
    if args.max_age is not None:
        created = datetime.fromisoformat(checkpoint.created_at) if checkpoint.created_at else None
        if created is None or datetime.now(UTC) - created > timedelta(seconds=args.max_age):
            problems.append("checkpoint older than --max-age")
    return problems


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if (args.checkpoint or args.write_checkpoint) and len(args.files) != 1:
        parser.error("a checkpoint requires exactly one log file")
    if args.signing_key and not args.write_checkpoint:
        parser.error("--signing-key needs --write-checkpoint")
    if args.previous_checkpoint and not args.signing_key:
        parser.error("--previous-checkpoint needs --signing-key")
    if (args.min_sequence is not None or args.max_age is not None) and not (
        args.checkpoint and args.checkpoint_public_key
    ):
        parser.error("--min-sequence and --max-age need --checkpoint and --checkpoint-public-key")
    if args.checkpoint_public_key and not (args.checkpoint or args.continues_from):
        parser.error("--checkpoint-public-key needs --checkpoint or --continues-from")
    if args.continues_from and len(args.files) != 1:
        parser.error("--continues-from requires exactly one log file")


def _write(
    path: Path,
    lines: list[str],
    args: argparse.Namespace,
    continues_from: Checkpoint | None,
    previous: Checkpoint | None,
) -> list[str]:
    try:
        signing_key = load_signing_key(args.signing_key) if args.signing_key else None
    except (ValueError, TypeError):
        return ["checkpoint signing key cannot be read or is not Ed25519"]
    if previous is not None:
        if signing_key is None or not previous.signature_valid(signing_key.public_key()):
            return ["previous checkpoint is not signed by this key"]
        if continues_from is None:
            problem = _ancestor_problem(lines, previous)
            if problem:
                return [problem]
    created = create_checkpoint(lines, continues_from=continues_from)
    if signing_key is not None:
        created = created.sign(signing_key, previous=previous)
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(created.to_json())
    except OSError:
        return ["checkpoint cannot be created; existing files are never overwritten"]
    return []


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)
    try:
        public_key = (
            load_public_key(args.checkpoint_public_key) if args.checkpoint_public_key else None
        )
    except (ValueError, TypeError):
        print("checkpoint public key cannot be read or is not Ed25519")
        sys.exit(1)
    checkpoint = (
        _load_checkpoint(args.checkpoint, public_key, "checkpoint") if args.checkpoint else None
    )
    continues_from = (
        _load_checkpoint(args.continues_from, public_key, "previous file checkpoint")
        if args.continues_from
        else None
    )
    previous = (
        _load_checkpoint(args.previous_checkpoint, None, "previous checkpoint")
        if args.previous_checkpoint
        else None
    )
    failed = False
    for path in args.files:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            print("audit log cannot be read")
            failed = True
            continue
        count, problems = verify_lines(lines, checkpoint, continues_from=continues_from)
        problems += _freshness_problems(checkpoint, count, args)
        if args.write_checkpoint and not problems:
            problems += _write(args.write_checkpoint, lines, args, continues_from, previous)
        for problem in problems:
            print(f"{path}: {problem}")
        print(f"{path}: {count} records, {'intact' if not problems else 'BROKEN'}")
        failed = failed or bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
