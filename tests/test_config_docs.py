"""docs/configuration.md must match what scripts/gen_config_docs.py generates from the code."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_config_docs_in_sync() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_config_docs.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
