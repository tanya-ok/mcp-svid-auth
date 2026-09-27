from __future__ import annotations

import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from mcp_svid_auth.stdio_wrapper import EXIT_TOKEN_EXPIRED, Refresher, run_wrapped, write_token


def _ok() -> dict[str, Any]:
    return {"access_token": "tok", "expires_in": 300}


def _child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


@pytest.fixture
def token_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def test_token_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "token"
    write_token(path, "abc")
    assert path.read_text(encoding="utf-8") == "abc"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_refresher_rewrites_before_expiry(tmp_path: Path) -> None:
    issued: list[str] = []

    def fetch() -> dict[str, Any]:
        issued.append(f"t{len(issued)}")
        return {"access_token": issued[-1], "expires_in": 300}

    refresher = Refresher(fetch, tmp_path / "token", margin=60)
    assert refresher.refresh_once() == "t0"
    assert 235 <= refresher.next_delay() <= 240
    refresher.expires_at = time.time() + 30  # inside the margin: retry soon
    assert refresher.next_delay() == 5.0
    assert refresher.tick()
    assert (tmp_path / "token").read_text(encoding="utf-8") == "t1"


def test_refresher_fails_closed_after_expiry(tmp_path: Path) -> None:
    expired_calls: list[bool] = []

    def fetch() -> dict[str, Any]:
        raise ConnectionError("authz down")

    path = tmp_path / "token"
    write_token(path, "old")
    refresher = Refresher(fetch, path, on_expired=lambda: expired_calls.append(True))
    refresher.expires_at = time.time() + 30
    assert refresher.tick()  # failure before expiry: keep the token, retry
    assert path.exists()
    refresher.expires_at = time.time() - 1
    assert not refresher.tick()
    assert not path.exists()
    assert refresher.expired.is_set()
    assert expired_calls == [True]


def test_child_gets_only_token_file_by_default(
    tmp_path: Path, token_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MCP_ACCESS_TOKEN", "leaked-from-parent")
    out = tmp_path / "seen.txt"
    code = (
        "import os, pathlib; p = os.environ['MCP_ACCESS_TOKEN_FILE'];"
        f"pathlib.Path({str(out)!r}).write_text("
        "'|'.join([os.environ.get('MCP_ACCESS_TOKEN', '-'), pathlib.Path(p).read_text(), p]))"
    )
    assert run_wrapped(_child(code), _ok) == 0
    env_token, file_token, file_path = out.read_text(encoding="utf-8").split("|")
    assert env_token == "-"
    assert file_token == "tok"
    assert Path(file_path).parent.parent == token_root
    assert list(token_root.iterdir()) == []


def test_env_export_is_opt_in(tmp_path: Path, token_root: Path) -> None:
    out = tmp_path / "seen.txt"
    code = (
        f"import os, pathlib; pathlib.Path({str(out)!r}).write_text(os.environ['MCP_ACCESS_TOKEN'])"
    )
    assert run_wrapped(_child(code), _ok, export_token_env=True) == 0
    assert out.read_text(encoding="utf-8") == "tok"


def test_child_exit_code_is_propagated(token_root: Path) -> None:
    assert run_wrapped(_child("raise SystemExit(3)"), _ok) == 3


def test_wrapper_exits_nonzero_when_token_expires(token_root: Path) -> None:
    calls = 0

    def fetch() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"access_token": "short", "expires_in": 1}
        raise ConnectionError("authz down")

    assert run_wrapped(_child("import time; time.sleep(30)"), fetch, margin=0) == EXIT_TOKEN_EXPIRED
    assert list(token_root.iterdir()) == []


def test_cleanup_when_child_cannot_start(token_root: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_wrapped(["/nonexistent/binary"], _ok)
    assert list(token_root.iterdir()) == []


def test_cleanup_when_first_fetch_fails(token_root: Path) -> None:
    def fetch() -> dict[str, Any]:
        raise ConnectionError("authz down")

    with pytest.raises(ConnectionError):
        run_wrapped(_child("pass"), fetch)
    assert list(token_root.iterdir()) == []


def test_env_export_stops_child_when_exported_token_expires(token_root: Path) -> None:
    issued: list[int] = []

    def fetch() -> dict[str, Any]:
        issued.append(1)
        return {"access_token": f"t{len(issued)}", "expires_in": 1}

    started = time.monotonic()
    code = run_wrapped(_child("import time; time.sleep(30)"), fetch, export_token_env=True)
    assert code == EXIT_TOKEN_EXPIRED
    assert time.monotonic() - started < 10
    assert list(token_root.iterdir()) == []


def test_file_mode_child_outlives_first_token(token_root: Path) -> None:
    def fetch() -> dict[str, Any]:
        return {"access_token": "t", "expires_in": 1}

    code = run_wrapped(_child("import time; time.sleep(2)"), fetch, margin=0)
    assert code == 0
