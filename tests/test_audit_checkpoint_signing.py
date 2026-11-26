"""Signed terminal checkpoints: a checkpoint replaced by the log writer is detected."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_svid_auth import audit
from mcp_svid_auth.audit import AuditLog, Checkpoint, create_checkpoint, verify_lines


def _log(path: Path, n: int) -> list[str]:
    log = AuditLog(path=path, component="test")
    for i in range(n):
        log.write(spiffe_id=None, tool=None, decision="allow", reason=f"event {i}")
    return path.read_text(encoding="utf-8").splitlines()


def _keys(directory: Path, label: str) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private = directory / f"{label}.key"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = directory / f"{label}.pub"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def _run(argv: list[str]) -> tuple[int, str]:
    with pytest.raises(SystemExit) as exit_info:
        audit.main(argv)
    return int(exit_info.value.code or 0), ""


def test_signature_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed = create_checkpoint(_log(tmp_path / "a.jsonl", 3)).sign(key)
    parsed = Checkpoint.from_json(signed.to_json())
    assert parsed == signed
    assert json.loads(signed.to_json())["version"] == 2
    assert parsed.signature_valid(key.public_key())
    assert not parsed.signature_valid(Ed25519PrivateKey.generate().public_key())
    forged = Checkpoint(2, parsed.last_record_id, parsed.last_hash, parsed.key_id, parsed.signature)
    assert not forged.signature_valid(key.public_key())
    unsigned = Checkpoint(parsed.records, parsed.last_record_id, parsed.last_hash)
    assert not unsigned.signature_valid(key.public_key())
    assert json.loads(unsigned.to_json())["version"] == 1


@pytest.mark.parametrize(
    "change",
    [{"version": 1}, {"signature": ""}, {"key_id": 5}, {"extra": "x"}],
)
def test_malformed_signed_checkpoints_are_rejected(
    tmp_path: Path, change: dict[str, object]
) -> None:
    signed = create_checkpoint(_log(tmp_path / "a.jsonl", 1)).sign(Ed25519PrivateKey.generate())
    value = {**json.loads(signed.to_json()), **change}
    with pytest.raises(ValueError, match="invalid checkpoint"):
        Checkpoint.from_json(json.dumps(value))


def test_unsigned_checkpoint_still_checks_terminal_state(tmp_path: Path) -> None:
    lines = _log(tmp_path / "a.jsonl", 3)
    signed = create_checkpoint(lines).sign(Ed25519PrivateKey.generate())
    assert verify_lines(lines, signed)[1] == []
    assert verify_lines(lines[:-1], signed)[1] == [
        "terminal state does not match trusted checkpoint"
    ]


def test_cli_signs_and_verifies_a_checkpoint(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    _log(log, 3)
    private, public = _keys(tmp_path, "operator")
    checkpoint = tmp_path / "a.checkpoint.json"
    argv = [str(log), "--write-checkpoint", str(checkpoint), "--signing-key", str(private)]
    assert _run(argv)[0] == 0
    assert "signature" in json.loads(checkpoint.read_text(encoding="utf-8"))
    verify = [str(log), "--checkpoint", str(checkpoint), "--checkpoint-public-key", str(public)]
    assert _run(verify)[0] == 0


def test_writer_cannot_replace_a_signed_checkpoint(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    lines = _log(log, 4)
    private, public = _keys(tmp_path, "operator")
    attacker_private, _ = _keys(tmp_path, "attacker")
    checkpoint = tmp_path / "a.checkpoint.json"
    assert (
        _run([str(log), "--write-checkpoint", str(checkpoint), "--signing-key", str(private)])[0]
        == 0
    )
    verify = [str(log), "--checkpoint", str(checkpoint), "--checkpoint-public-key", str(public)]

    # Suffix deletion against the genuine checkpoint.
    log.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert _run(verify)[0] == 1

    # The writer rebuilds an unsigned checkpoint for the truncated log.
    checkpoint.write_text(create_checkpoint(lines[:-1]).to_json(), encoding="utf-8")
    assert _run(verify)[0] == 1

    # The writer signs a replacement with a key of its own.
    checkpoint.unlink()
    forged = [str(log), "--write-checkpoint", str(checkpoint), "--signing-key"]
    assert _run([*forged, str(attacker_private)])[0] == 0
    assert _run(verify)[0] == 1

    # Without the public key only the terminal state is compared, so the forgery passes.
    assert _run([str(log), "--checkpoint", str(checkpoint)])[0] == 0


def test_cli_refuses_non_ed25519_keys_and_flag_misuse(tmp_path: Path) -> None:
    log = tmp_path / "a.jsonl"
    _log(log, 1)
    ec_key = tmp_path / "ec.key"
    ec_key.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    out = tmp_path / "c.json"
    assert _run([str(log), "--write-checkpoint", str(out), "--signing-key", str(ec_key)])[0] == 1
    assert not out.exists()
    _, public = _keys(tmp_path, "operator")
    assert _run([str(log), "--signing-key", str(ec_key)])[0] == 2
    assert _run([str(log), "--checkpoint-public-key", str(public)])[0] == 2
