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
import base64
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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcp_svid_auth.files import MAX_KEY_FILE_BYTES, read_file

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
    """Trusted terminal state, stored outside the log writer's control.

    Version 1 is unsigned. Version 2 adds an Ed25519 signature by a checkpoint key the log
    writer never holds, so a replaced checkpoint is detected wherever it is stored.
    """

    records: int
    last_record_id: str | None
    last_hash: str | None
    key_id: str | None = None
    signature: str | None = None

    def _body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "version": 2 if self.signature is not None else 1,
            "records": self.records,
            "last_record_id": self.last_record_id,
            "last_hash": self.last_hash,
        }
        if self.signature is not None:
            body["key_id"] = self.key_id
        return body

    def terminal(self) -> tuple[int, str | None, str | None]:
        return self.records, self.last_record_id, self.last_hash

    def to_json(self) -> str:
        body = self._body()
        if self.signature is not None:
            body["signature"] = self.signature
        return json.dumps(body, sort_keys=True) + "\n"

    def sign(self, key: Ed25519PrivateKey) -> Checkpoint:
        key_id = public_key_id(key.public_key())
        raw = key.sign(_signed_bytes(self, key_id))
        signature = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return Checkpoint(self.records, self.last_record_id, self.last_hash, key_id, signature)

    def signature_valid(self, key: Ed25519PublicKey) -> bool:
        if self.signature is None or self.key_id != public_key_id(key):
            return False
        try:
            raw = base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
            key.verify(raw, _signed_bytes(self, self.key_id))
        except (InvalidSignature, ValueError):
            return False
        return True

    @classmethod
    def from_json(cls, text: str) -> Checkpoint:
        value = json.loads(text)
        base = {"version", "records", "last_record_id", "last_hash"}
        if not isinstance(value, dict) or set(value) not in (base, base | {"key_id", "signature"}):
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
        elif (
            not isinstance(rid, str)
            or not rid
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("invalid checkpoint")
        if not signed:
            return cls(n, rid, digest)
        key_id, signature = value["key_id"], value["signature"]
        if not isinstance(key_id, str) or not isinstance(signature, str) or not signature:
            raise ValueError("invalid checkpoint")
        return cls(n, rid, digest, key_id, signature)


def _signed_bytes(checkpoint: Checkpoint, key_id: str | None) -> bytes:
    """Domain-separated JCS bytes of the terminal state and key identifier."""
    body = {
        "version": 2,
        "records": checkpoint.records,
        "last_record_id": checkpoint.last_record_id,
        "last_hash": checkpoint.last_hash,
        "key_id": key_id,
    }
    return b"mcp-svid-auth audit checkpoint\n" + canonical(body)


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
        if terminal.terminal() != checkpoint.terminal():
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
    parser.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 PEM private key that signs a new checkpoint; keep it away from log writers",
    )
    parser.add_argument(
        "--checkpoint-public-key",
        type=Path,
        help="Ed25519 PEM public key; the checkpoint must carry a valid signature by it",
    )
    return parser


def _read_checkpoint(path: Path | None, public_key_path: Path | None) -> Checkpoint | None:
    """Load the trusted checkpoint; with a public key its signature must verify. Exits on error."""
    if path is None:
        return None
    try:
        checkpoint = Checkpoint.from_json(path.read_text(encoding="utf-8"))
        public_key = load_public_key(public_key_path) if public_key_path else None
    except (OSError, ValueError, TypeError):
        print("checkpoint or its public key cannot be read or is invalid")
        sys.exit(1)
    if public_key is not None and not checkpoint.signature_valid(public_key):
        print("checkpoint signature is missing or invalid")
        sys.exit(1)
    return checkpoint


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.checkpoint or args.write_checkpoint) and len(args.files) != 1:
        parser.error("a checkpoint requires exactly one log file")
    if args.signing_key and not args.write_checkpoint:
        parser.error("--signing-key needs --write-checkpoint")
    if args.checkpoint_public_key and not args.checkpoint:
        parser.error("--checkpoint-public-key needs --checkpoint")
    checkpoint = _read_checkpoint(args.checkpoint, args.checkpoint_public_key)
    try:
        signing_key = load_signing_key(args.signing_key) if args.signing_key else None
    except (OSError, ValueError, TypeError):
        print("checkpoint signing key cannot be read or is not Ed25519")
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
                    created = create_checkpoint(lines)
                    if signing_key is not None:
                        created = created.sign(signing_key)
                    output.write(created.to_json())
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
