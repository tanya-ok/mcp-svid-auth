"""Shared replay and rate-limit state against a real Valkey or Redis server.

Skipped when neither `valkey-server` nor `redis-server` is installed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import redis
from starlette.testclient import TestClient

from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer, ReplayCache
from mcp_svid_auth.budgets import WindowBudget
from mcp_svid_auth.dpop import DPoPError, ProofReplayStore, VerifiedProof
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.revocation import TokenUseCounter, TokenUseError
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from mcp_svid_auth.state import StateUnavailableError, ValkeyState
from tests.conftest import ISSUER, POLICY, RESEARCH, SERVER_A
from tests.test_tls_listeners import Pki, make_pki

BINARY = shutil.which("valkey-server") or shutil.which("redis-server")
pytestmark = pytest.mark.skipif(BINARY is None, reason="no valkey-server or redis-server")
PASSWORD = "synthetic-test-password"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class Server:
    port: int
    process: subprocess.Popen[bytes]
    password_file: Path
    tls_port: int | None = None

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.port}/0"

    def state(self, prefix: str = "test") -> ValkeyState:
        return ValkeyState.from_url(self.url, prefix=prefix, password_file=self.password_file)

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(10)


def _start(tmp_path: Path, *extra: str, policy: str = "noeviction") -> Server:
    assert BINARY is not None
    port = _free_port()
    password_file = tmp_path / f"store-password-{port}"
    password_file.write_text(PASSWORD + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    args = [BINARY, "--port", str(port), "--bind", "127.0.0.1", "--save", ""]
    args += ["--appendonly", "no", "--requirepass", PASSWORD, "--maxmemory-policy", policy]
    args += ["--dir", str(tmp_path), *extra]
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server = Server(port, process, password_file)
    client = redis.Redis(port=port, password=PASSWORD, socket_timeout=1)
    for _ in range(200):
        try:
            client.ping()
            return server
        except redis.RedisError:
            time.sleep(0.02)
    server.stop()
    pytest.fail("store did not start")


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Server]:
    server = _start(tmp_path)
    yield server
    server.stop()


def _proof(jti: str) -> VerifiedProof:
    return VerifiedProof(jkt="thumbprint", jti=jti, iat=int(time.time()))


def test_add_once_is_shared_and_expires(store: Server) -> None:
    a, b = store.state(), store.state()
    expires = time.time() + 0.3
    assert a.add_once("ns", "k", expires)
    assert not b.add_once("ns", "k", expires)
    assert a.add_once("other", "k", expires)
    time.sleep(0.5)
    assert b.add_once("ns", "k", time.time() + 5)


def test_add_up_to_is_atomic_under_concurrency(store: Server) -> None:
    state = store.state()
    results: list[bool] = []
    lock = threading.Lock()

    def work() -> None:
        outcome = state.add_up_to("calls", "jti", 1, 10, time.time() + 30)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=work) for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 10
    assert not state.add_up_to("calls", "jti2", 3, 2, time.time() + 30)


def _authz(spire: LocalSvidIssuer, state: ValkeyState | None) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=None, component="authz"),
        replay_cache=ReplayCache(shared=state),
        state=state,
    )


def _exchange(server: AuthzServer, assertion: str) -> tuple[int, dict[str, object]]:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": assertion,
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    with TestClient(server.app()) as client:
        response = client.post("/token", data=form)
    return response.status_code, response.json()


def test_two_authz_instances_share_the_svid_seen_set(store: Server) -> None:
    spire = LocalSvidIssuer()
    first, second = _authz(spire, store.state()), _authz(spire, store.state())
    assertion = spire.mint(RESEARCH, ISSUER)
    assert _exchange(first, assertion)[0] == 200
    status, body = _exchange(second, assertion)
    assert (status, body["error"]) == (401, "invalid_client")
    # Without shared state the second replica accepts the replay: the gap this closes.
    isolated = _authz(spire, None), _authz(spire, None)
    replayed = spire.mint(RESEARCH, ISSUER)
    assert [_exchange(server, replayed)[0] for server in isolated] == [200, 200]


def test_proofs_calls_and_budgets_are_shared(store: Server) -> None:
    proofs = ProofReplayStore(shared=store.state()), ProofReplayStore(shared=store.state())
    proofs[0].add(_proof("p1"), time.time())
    with pytest.raises(DPoPError, match="proof_replayed"):
        proofs[1].add(_proof("p1"), time.time())
    counters = TokenUseCounter(2, shared=store.state()), TokenUseCounter(2, shared=store.state())
    counters[0].consume("t1", time.time() + 30, 1, time.time())
    counters[1].consume("t1", time.time() + 30, 1, time.time())
    with pytest.raises(TokenUseError, match="call_limit"):
        counters[0].consume("t1", time.time() + 30, 1, time.time())
    now = time.time()
    budgets = [
        WindowBudget(3, shared=store.state(), name="b", wall_clock=lambda: now) for _ in range(2)
    ]
    assert [budgets[i % 2].take("subject") for i in range(6)] == [True] * 3 + [False] * 3
    assert budgets[0].take("other subject")


def test_store_outage_fails_closed(tmp_path: Path) -> None:
    server = _start(tmp_path)
    spire = LocalSvidIssuer()
    state = server.state()
    authz = _authz(spire, state)
    proofs = ProofReplayStore(shared=state)
    counter = TokenUseCounter(5, shared=state)
    budget = WindowBudget(5, shared=state)
    server.stop()
    status, body = _exchange(authz, spire.mint(RESEARCH, ISSUER))
    assert (status, body["error"]) == (503, "temporarily_unavailable")
    with pytest.raises(DPoPError, match="unavailable"):
        proofs.add(_proof("p"), time.time())
    with pytest.raises(TokenUseError, match="unavailable"):
        counter.consume("t", time.time() + 30, 1, time.time())
    assert not budget.take()
    with TestClient(authz.app()) as client:
        ready = client.get("/readyz")
    assert (ready.status_code, ready.json()) == (503, {"status": "state_store_unavailable"})


def test_evicting_store_is_refused(tmp_path: Path) -> None:
    server = _start(tmp_path, policy="allkeys-lru")
    try:
        with pytest.raises(StateUnavailableError, match="noeviction"):
            server.state()
    finally:
        server.stop()


def test_store_credentials_are_required_and_kept_out_of_urls(store: Server, tmp_path: Path) -> None:
    with pytest.raises(StateUnavailableError):
        ValkeyState.from_url(store.url)
    with pytest.raises(ValueError, match="password in a file"):
        ValkeyState.from_url(f"redis://user:{PASSWORD}@127.0.0.1:{store.port}/0")
    loose = tmp_path / "loose-password"
    loose.write_text(PASSWORD, encoding="utf-8")
    loose.chmod(0o644)
    with pytest.raises(ValueError, match="group or others"):
        ValkeyState.from_url(store.url, password_file=loose)
    with pytest.raises(ValueError, match="rediss"):
        ValkeyState.from_url(store.url, password_file=store.password_file, ca_file=loose)


def _tls_server(tmp_path: Path, pki: Pki) -> Server:
    port = _free_port()
    server = _start(
        tmp_path,
        *("--tls-port", str(port), "--tls-cert-file", str(pki.server[0])),
        *("--tls-key-file", str(pki.server[1]), "--tls-ca-cert-file", str(pki.ca.path)),
        *("--tls-auth-clients", "no"),
    )
    server.tls_port = port
    return server


def test_tls_store_verifies_the_server_certificate(tmp_path: Path) -> None:
    pki = make_pki(tmp_path)
    try:
        server = _tls_server(tmp_path, pki)
    except BaseException:
        pytest.skip("store binary built without TLS")
    try:
        url = f"rediss://localhost:{server.tls_port}/0"
        state = ValkeyState.from_url(url, password_file=server.password_file, ca_file=pki.ca.path)
        assert state.add_once("tls", "k", time.time() + 5)
        with pytest.raises(StateUnavailableError):
            ValkeyState.from_url(url, password_file=server.password_file, ca_file=pki.other_ca.path)
    finally:
        server.stop()


def test_password_file_must_be_private(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text(PASSWORD, encoding="utf-8")
    secret.chmod(0o600)
    secret.chmod(0o640)
    with pytest.raises(ValueError, match="group or others"):
        ValkeyState.from_url("redis://127.0.0.1:1/0", password_file=secret)
