from __future__ import annotations

import stat
import time
from pathlib import Path
from typing import Any

from mcp_svid_auth.stdio_wrapper import Refresher, write_token


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
    refresher.expires_at = time.time()  # pretend we are at expiry
    assert refresher.next_delay() == 5.0
    refresher.refresh_once()
    assert (tmp_path / "token").read_text(encoding="utf-8") == "t1"
