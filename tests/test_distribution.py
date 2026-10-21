"""Publication archives must not carry local workspace or generated state."""

import tomllib
from pathlib import Path

import pytest

from scripts.check_dist import check_member


@pytest.mark.parametrize(
    "name",
    [
        "mcp_svid_auth-0.1.0/.ai-assurance/evidence.json",
        "mcp_svid_auth-0.1.0/.ai-assurance/lock.json",
        "mcp_svid_auth-0.1.0/.beads/issues.jsonl",
        "mcp_svid_auth-0.1.0/.beads/dolt/database",
        "mcp_svid_auth-0.1.0/.data/report.json",
        "mcp_svid_auth-0.1.0/deploy/.data/jwks.json",
        "mcp_svid_auth-0.1.0/site/index.html",
        "mcp_svid_auth-0.1.0/.venv-docs/bin/python",
        "mcp_svid_auth-0.1.0/tests/denylist.txt",
        "../outside.py",
        "/absolute.py",
    ],
)
def test_local_metadata_cannot_be_distributed(name: str) -> None:
    with pytest.raises(SystemExit, match="unexpected private or generated"):
        check_member(name, b"synthetic content")


def test_public_runtime_and_documentation_remain_distributable() -> None:
    check_member("mcp_svid_auth/authz.py", b"# Public runtime source")
    check_member("mcp_svid_auth-0.1.0/docs/index.md", b"# Public overview")
    check_member("mcp_svid_auth-0.1.0/uv.lock", b"version = 1")


def test_assurance_state_is_excluded_from_sdist() -> None:
    metadata = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert "/.ai-assurance" in metadata["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]
