"""Launch a local stdio MCP server with a short-lived token instead of a static key.

The wrapper fetches an access token for an upstream resource using its own JWT-SVID, writes it
to a 0600 file in a private temp dir, and starts the child with MCP_ACCESS_TOKEN_FILE pointing
at it. The file is rewritten before each expiry. stdin and stdout are inherited, so the MCP
stdio stream flows directly between host and child.

Fail closed: if refresh keeps failing until the token expires, the wrapper deletes the file,
terminates the child and exits with EXIT_TOKEN_EXPIRED.

--export-token-env also sets MCP_ACCESS_TOKEN. That is weaker: the value is visible in the
process environment to the same UID, is inherited by grandchildren, and is never refreshed, so
a child that reads it holds an expired token after the TTL.
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
EXIT_TOKEN_EXPIRED = 75  # EX_TEMPFAIL


def write_token(path: Path, token: str) -> None:
    """Atomically replace the token file, readable by owner only."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    tmp.replace(path)


class Refresher:
    """Keeps the token file fresh until stopped. Deletes it once the token has expired."""

    def __init__(
        self,
        fetch: TokenFetcher,
        path: Path,
        margin: int = 60,
        on_expired: Callable[[], None] = lambda: None,
    ) -> None:
        self.fetch = fetch
        self.path = path
        self.margin = margin
        self.on_expired = on_expired
        self.stop = threading.Event()
        self.expired = threading.Event()
        self.expires_at = 0.0

    def refresh_once(self) -> str:
        body = self.fetch()
        write_token(self.path, body["access_token"])
        self.expires_at = time.time() + int(body["expires_in"])
        return str(body["access_token"])

    def next_delay(self) -> float:
        remaining = self.expires_at - time.time()
        if remaining - self.margin > 0:
            return remaining - self.margin
        # Inside the margin: retry often until expiry.
        return max(0.5, min(5.0, remaining))

    def tick(self) -> bool:
        """One refresh attempt. Returns False once the token expired without a refresh."""
        try:
            self.refresh_once()
        except Exception as exc:
            print(f"mcp-svid-stdio: refresh failed: {type(exc).__name__}", file=sys.stderr)
            if time.time() >= self.expires_at:
                self.path.unlink(missing_ok=True)
                self.expired.set()
                self.on_expired()
                return False
        return True

    def run(self) -> None:
        while not self.stop.wait(self.next_delay()):
            if not self.tick():
                return


def run_wrapped(
    command: list[str],
    fetch: TokenFetcher,
    *,
    margin: int = 60,
    export_token_env: bool = False,
    on_child: Callable[[subprocess.Popen[bytes]], None] = lambda _c: None,
) -> int:
    """Run `command` with a refreshed token file. Returns the exit code to use."""
    token_dir = Path(tempfile.mkdtemp(prefix="mcp-svid-"))
    child: subprocess.Popen[bytes] | None = None
    refresher = Refresher(fetch, token_dir / "token", margin=margin)
    try:
        token = refresher.refresh_once()
        env = dict(os.environ)
        env.pop("MCP_ACCESS_TOKEN", None)
        env["MCP_ACCESS_TOKEN_FILE"] = str(refresher.path)
        if export_token_env:
            env["MCP_ACCESS_TOKEN"] = token
        child = subprocess.Popen(command, env=env)  # noqa: S603 - operator supplied command
        running = child
        refresher.on_expired = running.terminate
        on_child(running)
        thread = threading.Thread(target=refresher.run, daemon=True)
        thread.start()
        code = running.wait()
        refresher.stop.set()
        thread.join(timeout=5)
        return EXIT_TOKEN_EXPIRED if refresher.expired.is_set() else code
    finally:
        refresher.stop.set()
        if child is not None and child.poll() is None:
            child.terminate()
        for leftover in (refresher.path, refresher.path.with_suffix(".tmp")):
            leftover.unlink(missing_ok=True)
        token_dir.rmdir()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-svid-stdio",
        description="Run a stdio MCP server with a short-lived token from the Workload API",
        usage="%(prog)s --resource URI --scope SCOPE [options] -- command [args...]",
    )
    parser.add_argument("--resource", required=True, help="upstream resource the child calls")
    parser.add_argument("--scope", required=True, help="space separated scopes")
    parser.add_argument("--socket", help="Workload API socket, default SPIFFE_ENDPOINT_SOCKET")
    parser.add_argument(
        "--refresh-margin", type=int, default=60, help="seconds before expiry to refresh"
    )
    parser.add_argument(
        "--export-token-env",
        action="store_true",
        help="also set MCP_ACCESS_TOKEN (weaker: visible in the environment, never refreshed)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="child command, after --")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing child command after --")

    source: SvidSource = WorkloadApiSvidSource(socket_path=args.socket)

    def fetch() -> dict[str, Any]:
        return asyncio.run(fetch_access_token(args.resource, source, scope=args.scope))

    def forward_signals(child: subprocess.Popen[bytes]) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda s, _f: child.send_signal(s))

    sys.exit(
        run_wrapped(
            command,
            fetch,
            margin=args.refresh_margin,
            export_token_env=args.export_token_env,
            on_child=forward_signals,
        )
    )


if __name__ == "__main__":
    main()
