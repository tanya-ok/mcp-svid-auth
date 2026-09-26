"""The anonymization gate. Any hit is a stop.

Pattern half runs everywhere. Denylist half runs only where tests/denylist.txt exists: that file
is git-ignored and holds, one per line, the real names this repository must never contain.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
DENYLIST = ROOT / "tests" / "denylist.txt"

PATTERNS: dict[str, re.Pattern[str]] = {
    "account id": re.compile(r"\b\d{12}\b"),
    "ARN": re.compile("arn" + r":aws(?:-[a-z]+)*:"),
    "internal host": re.compile(r"\.internal\b"),
    "concrete secret reference": re.compile(r"\b(?:op|vault)://[A-Za-z0-9]"),
    "secret name suffix": re.compile(r"secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}\b"),
    "em or en dash": re.compile("[\u2013\u2014]"),
    "private key block": re.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
SKIP_DIRS = {".git", ".venv", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


def _git(*args: str) -> str | None:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        return None
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout if result.returncode == 0 else None


def _files() -> list[Path]:
    listed = _git("ls-files", "--cached", "--others", "--exclude-standard")
    if listed is not None:
        candidates = [ROOT / line for line in listed.splitlines() if line]
    else:
        candidates = [p for p in ROOT.rglob("*") if p.is_file() and not SKIP_DIRS & set(p.parts)]
    return [p for p in candidates if p.is_file() and p.resolve() not in {SELF, DENYLIST}]


def _history() -> str:
    # Messages and diffs, not author headers: authorship is deliberate, content is what leaks.
    args = (
        "log",
        "-p",
        "--all",
        "--format=%B",
        "--",
        ".",
        ":(exclude)tests/test_no_identifiers.py",
    )
    return _git(*args) or ""


def _denylist() -> list[str]:
    if not DENYLIST.exists():
        return []
    lines = DENYLIST.read_text(encoding="utf-8").splitlines()
    return [line.strip().lower() for line in lines if line.strip() and not line.startswith("#")]


def _hits(text: str, where: str, terms: list[str]) -> list[str]:
    found = [f"{where}: {label}" for label, rx in PATTERNS.items() if rx.search(text)]
    lowered = text.lower()
    found += [f"{where}: denylisted term #{i + 1}" for i, t in enumerate(terms) if t in lowered]
    return found


def test_working_tree_is_clean() -> None:
    terms = _denylist()
    hits: list[str] = []
    for path in _files():
        text = path.read_bytes().decode("utf-8", errors="ignore")
        hits += _hits(text, str(path.relative_to(ROOT)), terms)
    assert not hits, "\n".join(hits)


def test_history_is_clean() -> None:
    history = _history()
    if not history:
        pytest.skip("no git history yet")
    hits = _hits(history, "git history", _denylist())
    assert not hits, "\n".join(hits)


def test_denylist_present_locally() -> None:
    if not DENYLIST.exists():
        pytest.skip("tests/denylist.txt absent; denylist half not run (expected in CI)")
    assert _denylist(), "tests/denylist.txt exists but is empty"
