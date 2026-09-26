"""Launch a local stdio MCP server with a short-lived token instead of a static key.

The wrapper fetches an access token for an upstream resource using its own JWT-SVID, then
starts the child with:
- MCP_ACCESS_TOKEN: the token at start time,
- MCP_ACCESS_TOKEN_FILE: a 0600 file the wrapper rewrites before each expiry.

stdin and stdout are inherited, so the MCP stdio stream flows directly between host and child.

Limitation: environment variables cannot change inside a running process. A child that reads
MCP_ACCESS_TOKEN once holds an expired token after the TTL. Children must re-read
MCP_ACCESS_TOKEN_FILE per upstream call to benefit from refresh.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_svid_auth.agent_client import fetch_access_token
from mcp_svid_auth.spiffe_keys import SvidSource, WorkloadApiSvidSource

TokenFetcher = Callable[[], dict[str, Any]]


def write_token(path: Path, token: str) -> None:
    """Atomically replace the token file, readable by owner only."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    tmp.replace(path)


class Refresher:
    """Keeps the token file fresh until stopped."""

    def __init__(self, fetch: TokenFetcher, path: Path, margin: int = 60) -> None:
        self.fetch = fetch
        self.path = path
        self.margin = margin
        self.stop = threading.Event()
        self.expires_at = 0.0

    def refresh_once(self) -> str:
        body = self.fetch()
        write_token(self.path, body["access_token"])
        self.expires_at = time.time() + int(body["expires_in"])
        return str(body["access_token"])

    def next_delay(self) -> float:
        return max(5.0, self.expires_at - time.time() - self.margin)

    def run(self) -> None:
        while not self.stop.wait(self.next_delay()):
            try:
                self.refresh_once()
            except Exception as exc:  # keep the child running, retry soon
                print(f"mcp-svid-stdio: refresh failed: {exc}", file=sys.stderr)
                self.expires_at = time.time() + self.margin + 5


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run a stdio MCP server with a short-lived token from the Workload API",
        usage="%(prog)s --resource URI [options] -- command [args...]",
    )
    parser.add_argument("--resource", required=True, help="upstream resource the child calls")
    parser.add_argument("--scope")
    parser.add_argument("--socket", help="Workload API socket, default SPIFFE_ENDPOINT_SOCKET")
    parser.add_argument("--refresh-margin", type=int, default=60, help="seconds before expiry")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing child command after --")

    source: SvidSource = WorkloadApiSvidSource(socket_path=args.socket)

    def fetch() -> dict[str, Any]:
        return asyncio.run(fetch_access_token(args.resource, source, scope=args.scope))

    token_dir = Path(tempfile.mkdtemp(prefix="mcp-svid-"))
    refresher = Refresher(fetch, token_dir / "token", margin=args.refresh_margin)
    token = refresher.refresh_once()
    env = dict(os.environ)
    env["MCP_ACCESS_TOKEN"] = token
    env["MCP_ACCESS_TOKEN_FILE"] = str(refresher.path)

    thread = threading.Thread(target=refresher.run, daemon=True)
    thread.start()
    child = subprocess.Popen(command, env=env)  # noqa: S603 - operator supplied command
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda s, _f: child.send_signal(s))
    code = child.wait()
    refresher.stop.set()
    refresher.path.unlink(missing_ok=True)
    token_dir.rmdir()
    sys.exit(code)


if __name__ == "__main__":
    main()
