"""Policy reload: grant revocation takes effect for new token requests without a restart."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer, install_policy_reload
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, READER, RESEARCH, SERVER_A

WITHOUT_RESEARCH = {
    "trust_domain": "example.org",
    "clients": [{"spiffe_id": READER, "resources": {SERVER_A: ["notes:read"]}}],
}


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    return path


@pytest.fixture
def server(policy_file: Path, spire: LocalSvidIssuer, tmp_path: Path) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.load(policy_file),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        policy_path=policy_file,
    )


def _token(server: AuthzServer, spire: LocalSvidIssuer, who: str = RESEARCH) -> tuple[int, Any]:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": spire.mint(who, ISSUER),
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    with TestClient(server.app()) as client:
        response = client.post("/token", data=form)
    return response.status_code, response.json()


def _reloads(tmp_path: Path) -> list[str]:
    lines = (tmp_path / "authz.jsonl").read_text(encoding="utf-8").splitlines()
    return [e["reason"] for e in map(json.loads, lines) if e["decision"] == "policy_reload"]


def test_unchanged_file_is_not_reloaded(server: AuthzServer) -> None:
    assert server.reload_policy() is False


def test_removed_grant_denies_new_tokens(
    server: AuthzServer, spire: LocalSvidIssuer, policy_file: Path, tmp_path: Path
) -> None:
    assert _token(server, spire)[0] == 200
    policy_file.write_text(yaml.safe_dump(WITHOUT_RESEARCH), encoding="utf-8")
    assert server.reload_policy() is True
    status, body = _token(server, spire)
    assert (status, body["error"]) == (400, "unauthorized_client")
    assert _token(server, spire, READER)[0] == 200
    assert _reloads(tmp_path)[0].startswith("loaded sha256=")
    assert _reloads(tmp_path)[0].endswith("clients=1")


def test_invalid_file_fails_closed_until_fixed(
    server: AuthzServer, spire: LocalSvidIssuer, policy_file: Path, tmp_path: Path
) -> None:
    policy_file.write_text("- not a mapping\n", encoding="utf-8")
    assert server.reload_policy() is True
    assert _token(server, spire)[1]["error"] == "unauthorized_client"
    assert _token(server, spire, READER)[1]["error"] == "unauthorized_client"
    policy_file.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    assert server.reload_policy() is True
    assert _token(server, spire)[0] == 200
    reasons = _reloads(tmp_path)
    assert reasons[0] == "failed: ValueError; denying all token requests"
    assert reasons[1].startswith("loaded")


def test_missing_file_fails_closed(
    server: AuthzServer, spire: LocalSvidIssuer, policy_file: Path, tmp_path: Path
) -> None:
    policy_file.unlink()
    assert server.reload_policy() is True
    assert _token(server, spire)[1]["error"] == "unauthorized_client"
    assert _reloads(tmp_path) == ["failed: FileNotFoundError; denying all token requests"]


def test_watcher_picks_up_change(
    server: AuthzServer, spire: LocalSvidIssuer, policy_file: Path
) -> None:
    stop = threading.Event()
    thread = threading.Thread(target=server.watch_policy, args=(0.02, stop), daemon=True)
    thread.start()
    try:
        policy_file.write_text(yaml.safe_dump(WITHOUT_RESEARCH), encoding="utf-8")
        for _ in range(200):
            if RESEARCH not in server.policy.grants:
                break
            stop.wait(0.01)
    finally:
        stop.set()
        thread.join(timeout=2)
    assert RESEARCH not in server.policy.grants


def _wait_for(predicate: Callable[[], bool], seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_sighup_forces_reload(server: AuthzServer, tmp_path: Path) -> None:
    previous = signal.getsignal(signal.SIGHUP)
    reloader = install_policy_reload(server, poll_seconds=0)
    try:
        signal.raise_signal(signal.SIGHUP)
        assert _wait_for((tmp_path / "authz.jsonl").exists)
    finally:
        reloader.stop()
        signal.signal(signal.SIGHUP, previous)
    assert len(_reloads(tmp_path)) == 1


_SIGHUP_UNDER_LOCK = """
import signal, sys, time
from pathlib import Path
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import AuthzServer, install_policy_reload
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import StaticJwksResolver

policy_path = Path(sys.argv[1])
audit_path = Path(sys.argv[2])
policy = Policy.load(policy_path)
server = AuthzServer(
    issuer="https://authz.example.org",
    policy=policy,
    resolver=StaticJwksResolver({policy.trust_domain: {"keys": []}}),
    audit=AuditLog(path=audit_path, component="authz"),
    policy_path=policy_path,
)
reloader = install_policy_reload(server, poll_seconds=0)
with server.audit._lock, server._reload_lock:
    signal.raise_signal(signal.SIGHUP)
    signal.raise_signal(signal.SIGHUP)
deadline = time.monotonic() + 5
while not audit_path.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
reloader.stop()
print("done")
"""


def test_sighup_while_audit_lock_held_does_not_deadlock(policy_file: Path, tmp_path: Path) -> None:
    audit_path = tmp_path / "sub.jsonl"
    result = subprocess.run(
        [sys.executable, "-c", _SIGHUP_UNDER_LOCK, str(policy_file), str(audit_path)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "done"
    reasons = [json.loads(line)["reason"] for line in audit_path.read_text().splitlines()]
    assert reasons and reasons[0].startswith("loaded sha256=")


def test_cli_poll_default() -> None:
    from mcp_svid_auth.authz import build_parser  # noqa: PLC0415

    args = build_parser().parse_args(["--issuer", ISSUER, "--policy", "p.yaml"])
    assert args.policy_poll_seconds == 5.0
