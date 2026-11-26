"""Revocation file reading: one read per load, bounded, no symlinks, signatures, ranges."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_svid_auth import authz, files, mcp_server, revocation
from mcp_svid_auth.revocation import (
    MAX_REVOCATION_FILE_BYTES,
    REVOKED_TOKEN,
    UNAVAILABLE,
    RevocationList,
    TokenUseCounter,
    TokenUseError,
    poll_seconds_arg,
)

EMPTY = json.dumps({"revoked_jti": [], "blocked_spiffe_ids": []}).encode()
REVOKED = json.dumps({"revoked_jti": ["j1"], "blocked_spiffe_ids": []}).encode()


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def _advance(loaded: RevocationList) -> Clock:
    clock = Clock()
    loaded.clock = clock
    loaded._checked_at = clock()
    clock.now += 5
    return clock


def test_load_parses_and_hashes_the_same_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "r.json"
    path.write_bytes(EMPTY)
    reads: list[bytes] = [EMPTY, REVOKED]
    real = files.read_file

    def racing_read(target: Path, **kwargs: Any) -> bytes:
        # The file changes after the first read, as a concurrent rewrite would.
        return reads.pop(0) if reads else real(target, **kwargs)

    monkeypatch.setattr(revocation, "read_file", racing_read)
    loaded = RevocationList.load(path)
    assert loaded._digest == hashlib.sha256(EMPTY).hexdigest()
    path.write_bytes(REVOKED)
    _advance(loaded)
    assert loaded.check(jti="j1", subjects=[]) == REVOKED_TOKEN


def test_symlink_fifo_and_oversized_files_fail_closed_without_blocking(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_bytes(EMPTY)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="cannot be opened"):
        RevocationList.load(link)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="not a regular file"):
        RevocationList.load(fifo)
    huge = tmp_path / "huge.json"
    with huge.open("wb") as handle:
        handle.truncate(MAX_REVOCATION_FILE_BYTES * 64)
    with pytest.raises(ValueError, match="larger than"):
        RevocationList.load(huge)
    zero = tmp_path / "zero.json"
    zero.symlink_to("/dev/zero")
    with pytest.raises(ValueError, match="cannot be opened"):
        RevocationList.load(zero)


def test_replaced_by_symlink_after_load_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_bytes(EMPTY)
    loaded = RevocationList.load(path)
    path.unlink()
    path.symlink_to("/dev/zero")
    _advance(loaded)
    assert loaded.check(jti="x", subjects=[]) == UNAVAILABLE


def _sign(path: Path, key: Ed25519PrivateKey, data: bytes) -> None:
    path.write_bytes(data)
    signature = base64.b64encode(key.sign(data))
    path.with_name(path.name + ".sig").write_bytes(signature + b"\n")


def test_signed_revocation_file(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "r.json"
    _sign(path, key, REVOKED)
    loaded = RevocationList.load(path, public_key=key.public_key())
    assert loaded.check(jti="j1", subjects=[]) == REVOKED_TOKEN
    clock = _advance(loaded)
    # A writer of the file without the key cannot un-revoke.
    path.write_bytes(EMPTY)
    assert loaded.check(jti="j1", subjects=[]) == UNAVAILABLE
    _sign(path, Ed25519PrivateKey.generate(), EMPTY)
    clock.now += 5
    assert loaded.check(jti="j1", subjects=[]) == UNAVAILABLE
    _sign(path, key, EMPTY)
    clock.now += 5
    assert loaded.check(jti="j1", subjects=[]) is None
    (tmp_path / "r.json.sig").unlink()
    with pytest.raises(ValueError, match="cannot be opened"):
        RevocationList.load(path, public_key=key.public_key())


@pytest.mark.parametrize("value", ["inf", "nan", "0", "-1", "0.4", "301", "x"])
def test_poll_interval_out_of_range_is_refused(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        poll_seconds_arg(value)
    authz_args = ["--issuer", "http://authz.test", "--policy", "p.yaml"]
    mcp_args = ["--resource", "http://notes.test/mcp", "--issuer", "http://authz.test"]
    for module, argv in ((authz, authz_args), (mcp_server, mcp_args)):
        with pytest.raises(SystemExit):
            module.build_parser().parse_args([*argv, "--revocation-poll-seconds", value])


def test_poll_interval_bounds_are_accepted(tmp_path: Path) -> None:
    assert poll_seconds_arg("0.5") == 0.5
    assert poll_seconds_arg("300") == 300
    with pytest.raises(ValueError, match="range"):
        RevocationList(tmp_path / "r.json", poll_seconds=float("inf"))


def test_one_subject_cannot_fill_the_token_use_store() -> None:
    counter = TokenUseCounter(5, max_entries=10, per_subject_limit=3)
    for i in range(3):
        counter.consume(f"noisy-{i}", 100, 1, 0, subject="noisy")
    with pytest.raises(TokenUseError, match="subject_limit"):
        counter.consume("noisy-3", 100, 1, 0, subject="noisy")
    counter.consume("quiet-0", 100, 1, 0, subject="quiet")
    counter.consume("noisy-0", 100, 1, 1, subject="noisy")
    counter.consume("noisy-4", 200, 1, 150, subject="noisy")
    assert len(counter) == 1
