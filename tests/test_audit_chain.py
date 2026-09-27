"""Hash-chained audit log: chain construction, resume, tamper detection, verify command."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from mcp_svid_auth import audit
from mcp_svid_auth.audit import AuditChainError, AuditLog, canonical, record_hash, verify_lines


def _write(log: AuditLog, n: int) -> None:
    for i in range(n):
        log.write(spiffe_id=f"spiffe://example.org/w/{i}", tool="t", decision="allow", reason="r")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_genesis_and_links(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path=path), 3)
    records = [json.loads(line) for line in _lines(path)]
    assert records[0]["parent_record_id"] is None
    assert records[0]["prev_hash"] is None
    for prev, cur in itertools.pairwise(records):
        assert cur["parent_record_id"] == prev["record_id"]
        assert cur["prev_hash"] == record_hash(prev)
        assert len(cur["prev_hash"]) == 64
    assert verify_lines(_lines(path)) == (3, [])


def test_canonical_form_is_sorted_and_compact() -> None:
    assert canonical({"b": None, "a": "xé"}) == '{"a":"xé","b":null}'.encode()


def test_resume_continues_chain_across_writers(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path=path), 2)
    _write(AuditLog(path=path), 2)
    assert verify_lines(_lines(path)) == (4, [])


def test_resume_refuses_corrupt_tail(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(AuditChainError):
        _write(AuditLog(path=path), 1)


@pytest.mark.parametrize(
    "tail", ["{not json\n", '{"record_id":"x"}\n{"record_id":', '{"record_id":"x"}']
)
def test_corrupt_tail_fails_every_write(tmp_path: Path, tail: str) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text(tail, encoding="utf-8")
    log = AuditLog(path=path)
    for _ in range(2):
        with pytest.raises(AuditChainError):
            _write(log, 1)
    assert path.read_text(encoding="utf-8") == tail


def _tampered(tmp_path: Path, change: Any) -> list[str]:
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path=path), 4)
    lines = _lines(path)
    change(lines)
    return verify_lines(lines)[1]


def test_edited_record_is_detected(tmp_path: Path) -> None:
    def edit(lines: list[str]) -> None:
        lines[1] = lines[1].replace('"allow"', '"deny"')

    assert _tampered(tmp_path, edit) == ["line 3: prev_hash does not match the previous record"]


def test_deleted_record_is_detected(tmp_path: Path) -> None:
    problems = _tampered(tmp_path, lambda lines: lines.pop(1))
    assert "line 2: parent_record_id does not match the previous record" in problems
    assert "line 2: prev_hash does not match the previous record" in problems


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    def swap(lines: list[str]) -> None:
        lines[1], lines[2] = lines[2], lines[1]

    assert _tampered(tmp_path, swap)


def test_truncated_head_is_detected(tmp_path: Path) -> None:
    problems = _tampered(tmp_path, lambda lines: lines.pop(0))
    assert problems[0].startswith("line 1: parent_record_id")


def test_timestamp_going_backwards_is_reported() -> None:
    first: dict[str, Any] = {"record_id": "1", "parent_record_id": None, "prev_hash": None}
    first["timestamp"] = "2026-09-27T10:00:01.000+00:00"
    second = {
        "record_id": "2",
        "parent_record_id": "1",
        "prev_hash": record_hash(first),
        "timestamp": "2026-09-27T10:00:00.000+00:00",
    }
    _, problems = verify_lines([json.dumps(first), json.dumps(second)])
    assert problems == ["line 2: timestamp earlier than the previous record"]


def test_verify_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.jsonl"
    bad = tmp_path / "bad.jsonl"
    _write(AuditLog(path=good), 2)
    _write(AuditLog(path=bad), 2)
    bad.write_text(bad.read_text(encoding="utf-8").replace("allow", "deny", 1), encoding="utf-8")
    with pytest.raises(SystemExit) as ok:
        audit.main([str(good)])
    assert ok.value.code == 0
    with pytest.raises(SystemExit) as broken:
        audit.main([str(good), str(bad)])
    assert broken.value.code == 1
    out = capsys.readouterr().out
    assert f"{good}: 2 records, intact" in out
    assert f"{bad}: 2 records, BROKEN" in out


def test_server_audit_trail_verifies(tmp_path: Path) -> None:
    path = tmp_path / "authz.jsonl"
    log = AuditLog(path=path, component="authz")
    log.write(spiffe_id=None, tool=None, decision="deny", reason="missing_token")
    log.write(spiffe_id="unverified:x", tool=None, decision="deny", reason='quote " and \\')
    assert verify_lines(_lines(path)) == (2, [])
