"""Checkpoint freshness, single writer, fsync, bounded resume and rotation."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_svid_auth import audit
from mcp_svid_auth.audit import AuditChainError, AuditLog, Checkpoint, verify_lines


def _write(log: AuditLog, n: int, *, close: bool = True) -> None:
    for i in range(n):
        log.write(spiffe_id=None, tool=None, decision="allow", reason=f"event {i}")
    if close:
        log.close()


def _keys(directory: Path) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private, public = directory / "cp.key", directory / "cp.pub"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def _run(*argv: str | Path) -> int:
    with pytest.raises(SystemExit) as exit_info:
        audit.main([str(a) for a in argv])
    return int(exit_info.value.code or 0)


def test_older_genuine_checkpoint_with_truncated_log_is_caught_by_high_water(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "a.jsonl"
    log = AuditLog(path=log_path)
    private, public = _keys(tmp_path)
    _write(log, 3)
    cp1, cp2 = tmp_path / "cp1.json", tmp_path / "cp2.json"
    assert _run(log_path, "--write-checkpoint", cp1, "--signing-key", private) == 0
    _write(log, 2)
    assert (
        _run(
            *(log_path, "--write-checkpoint", cp2, "--signing-key", private),
            *("--previous-checkpoint", cp1),
        )
        == 0
    )
    second = Checkpoint.from_json(cp2.read_text(encoding="utf-8"))
    first = Checkpoint.from_json(cp1.read_text(encoding="utf-8"))
    assert (first.sequence, second.sequence) == (1, 2)
    assert second.previous == first.digest()

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    verify = (log_path, "--checkpoint", cp1, "--checkpoint-public-key", public)
    # Without a high-water mark the stale checkpoint still matches the truncated log.
    assert _run(*verify) == 0
    assert _run(*verify, "--min-sequence", "2") == 1
    assert _run(*verify, "--min-records", "5") == 1


def test_checkpoint_older_than_max_age_is_refused(tmp_path: Path) -> None:
    log_path = tmp_path / "a.jsonl"
    _write(AuditLog(path=log_path), 2)
    key = Ed25519PrivateKey.generate()
    private, public = _keys(tmp_path)
    key = audit.load_signing_key(private)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    old = audit.create_checkpoint(lines).sign(key, now=datetime.now(UTC) - timedelta(hours=2))
    fresh = audit.create_checkpoint(lines).sign(key)
    for name, checkpoint, code in (("old.json", old, 1), ("fresh.json", fresh, 0)):
        (tmp_path / name).write_text(checkpoint.to_json(), encoding="utf-8")
        args = (log_path, "--checkpoint", tmp_path / name, "--checkpoint-public-key", public)
        assert _run(*args, "--max-age", "3600") == code


def test_sequence_time_and_previous_are_signed(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed = Checkpoint(1, "r", "a" * 64).sign(key)
    for change in (
        {"sequence": 7, "previous": "b" * 64},
        {"created_at": "2030-01-01T00:00:00+00:00"},
    ):
        value = {**json.loads(signed.to_json()), **change}
        assert not Checkpoint.from_json(json.dumps(value)).signature_valid(key.public_key())
    for bad in ({"sequence": 0}, {"sequence": 2}, {"previous": "b" * 64}, {"created_at": "x"}):
        value = {**json.loads(signed.to_json()), **bad}
        with pytest.raises(ValueError, match="invalid checkpoint"):
            Checkpoint.from_json(json.dumps(value))


def test_previous_checkpoint_must_be_an_ancestor_signed_by_the_same_key(tmp_path: Path) -> None:
    private, _ = _keys(tmp_path)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_private, _ = _keys(other_dir)
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _write(AuditLog(path=a), 2)
    _write(AuditLog(path=b), 3)
    cp_a = tmp_path / "a.cp"
    assert _run(a, "--write-checkpoint", cp_a, "--signing-key", private) == 0
    args = ("--previous-checkpoint", cp_a)
    assert _run(b, "--write-checkpoint", tmp_path / "x.cp", "--signing-key", private, *args) == 1
    assert (
        _run(a, "--write-checkpoint", tmp_path / "y.cp", "--signing-key", other_private, *args) == 1
    )


def test_second_writer_on_one_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    first = AuditLog(path=path, replica_id="authz-0")
    _write(first, 1, close=False)
    second = AuditLog(path=path, replica_id="authz-1")
    with pytest.raises(AuditChainError, match="another writer"):
        _write(second, 1)
    first.close()
    _write(second, 1)
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [r["replica_id"] for r in records] == ["authz-0", "authz-1"]
    assert {r["schema_version"] for r in records} == {"2"}
    assert verify_lines(path.read_text(encoding="utf-8").splitlines()) == (2, [])


def test_every_record_is_fsynced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "fsync", calls.append)
    _write(AuditLog(path=tmp_path / "a.jsonl"), 3)
    assert len(calls) == 3


def test_version_1_records_still_verify(tmp_path: Path) -> None:
    previous = None
    lines = []
    for i in range(2):
        record = {
            "record_id": f"r{i}",
            "parent_record_id": previous["record_id"] if previous else None,
            "prev_hash": audit.record_hash(previous) if previous else None,
            "timestamp": "2026-10-01T00:00:00.000+00:00",
            "component": "authz",
            "spiffe_id": None,
            "tool": None,
            "decision": "allow",
            "reason": "r",
        }
        lines.append(json.dumps(record))
        previous = record
    assert verify_lines(lines) == (2, [])


def test_resume_checks_a_bounded_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "TAIL_BYTES", 2000)
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path=path), 30)
    lines = path.read_text(encoding="utf-8").splitlines()
    early = lines.copy()
    early[0] = early[0].replace("event 0", "event X")
    path.write_text("\n".join(early) + "\n", encoding="utf-8")
    resumed = AuditLog(path=path)
    _write(resumed, 1)
    resumed.close()
    assert verify_lines(path.read_text(encoding="utf-8").splitlines())[1]
    late = path.read_text(encoding="utf-8").splitlines()
    late[-2] = late[-2].replace("event 29", "event Y")
    path.write_text("\n".join(late) + "\n", encoding="utf-8")
    with pytest.raises(AuditChainError, match="invalid"):
        _write(AuditLog(path=path), 1)


def test_rotate_and_checkpoint_procedure(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    path, archive = tmp_path / "notes.jsonl", tmp_path / "notes.1.jsonl"
    log = AuditLog(path=path)
    _write(log, 3, close=False)
    path.rename(archive)
    _write(log, 2)
    archive_cp, current_cp = tmp_path / "notes.1.cp", tmp_path / "notes.cp"
    assert _run(archive, "--write-checkpoint", archive_cp, "--signing-key", private) == 0
    continuing = ("--continues-from", archive_cp, "--checkpoint-public-key", public)
    assert _run(path, *continuing) == 0
    assert _run(path) == 1
    assert (
        _run(
            *(path, "--write-checkpoint", current_cp, "--signing-key", private),
            *("--continues-from", archive_cp, "--previous-checkpoint", archive_cp),
        )
        == 0
    )
    assert Checkpoint.from_json(current_cp.read_text(encoding="utf-8")).sequence == 2
    # A forged archive checkpoint cannot be used to splice in another history.
    forged = tmp_path / "forged.cp"
    forged.write_text(
        Checkpoint(3, "x", "c" * 64).sign(Ed25519PrivateKey.generate()).to_json(), encoding="utf-8"
    )
    assert _run(path, "--continues-from", forged, "--checkpoint-public-key", public) == 1
