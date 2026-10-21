"""Validate publication artifacts without uploading them."""

from __future__ import annotations

import hashlib
import re
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_PARTS = {
    ".ai-assurance",
    ".git",
    ".venv",
    ".venv-docs",
    "node_modules",
    ".data",
    ".beads",
    "site",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}


def check_member(name: str, data: bytes) -> None:
    parts = Path(name).parts
    if (
        set(parts) & FORBIDDEN_PARTS
        or "denylist.txt" in parts
        or name.startswith("/")
        or ".." in parts
    ):
        raise SystemExit("unexpected private or generated file in distribution")
    # Generated private keys must never be present in a source or wheel archive.
    if re.search(rb"-----BEGIN [A-Z ]*" + rb"PRIVATE KEY-----", data):
        raise SystemExit("private key marker in distribution")


def main() -> None:
    directory = ROOT / "dist"
    wheels, sources = sorted(directory.glob("*.whl")), sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise SystemExit("expected one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as wheel:
        for member in wheel.namelist():
            check_member(member, wheel.read(member))
        if "mcp_svid_auth/pinned_transport.py" not in wheel.namelist():
            raise SystemExit("wheel is missing a runtime module")
        metadata = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or b"License-Expression: Apache-2.0" not in wheel.read(metadata[0]):
            raise SystemExit("wheel metadata is missing the license")
    with tarfile.open(sources[0]) as source:
        members = source.getmembers()
        for entry in members:
            if entry.issym() or entry.islnk():
                raise SystemExit("source archive contains a link")
            if entry.isfile():
                stream = source.extractfile(entry)
                if stream is None:
                    raise SystemExit("source archive member cannot be read")
                check_member(entry.name, stream.read())
        if not any(m.name.endswith("/uv.lock") for m in members):
            raise SystemExit("source distribution is missing the lock file")
    artifacts = [*wheels, *sources]
    (directory / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in artifacts
        )
    )
    print("PASS: wheel and source archive contents, license, runtime module and checksums")


if __name__ == "__main__":
    main()
