"""Bounded, descriptor-based reads of configuration and key files.

One `open` with O_NOFOLLOW (a symlink as the last component is refused) and O_NONBLOCK (a FIFO
cannot block the open), then `fstat` on that descriptor: the checks and the read apply to the
same file. Only regular files are read, and never more than `max_bytes` + 1 bytes.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_KEY_FILE_BYTES = 64 * 1024
MAX_SECRET_FILE_BYTES = 4096


class UnsafeFileError(ValueError):
    """A file is not a regular file, too large, or too widely accessible."""


def read_file(path: Path, *, max_bytes: int, private: bool = False) -> bytes:
    """Read `path`. With `private`, the file must belong to this user and have no group or
    other permissions (secrets and private keys)."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UnsafeFileError(f"{path.name}: cannot be opened ({type(exc).__name__})") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeFileError(f"{path.name}: not a regular file")
        if private and info.st_uid != os.getuid():
            raise UnsafeFileError(f"{path.name}: must be owned by the service user")
        if private and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise UnsafeFileError(f"{path.name}: must not be accessible to group or others")
        if info.st_size > max_bytes:
            raise UnsafeFileError(f"{path.name}: larger than {max_bytes} bytes")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise UnsafeFileError(f"{path.name}: larger than {max_bytes} bytes")
        return data
    finally:
        os.close(fd)
