"""Transit signer against a real OpenBao or Vault dev server; key source CLI rules.

Server tests are skipped when neither `bao` nor `vault` is installed.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from starlette.testclient import TestClient

from mcp_svid_auth import authz
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE, AuthzServer
from mcp_svid_auth.mcp_server import _find_key
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.signers import SignerError, VaultTransitSigner
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, RESEARCH, SERVER_A

BINARY = shutil.which("bao") or shutil.which("vault")
needs_server = pytest.mark.skipif(BINARY is None, reason="no bao or vault binary")
ROOT_TOKEN = "synthetic-dev-root-token"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class Transit:
    address: str
    token_file: Path
    process: subprocess.Popen[bytes]

    def api(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        with httpx2.Client(base_url=self.address, headers={"X-Vault-Token": ROOT_TOKEN}) as c:
            response = c.request(method, path, json=body)
        response.raise_for_status()
        return response.json() if response.content else None

    def signer(self, key: str = "access-tokens") -> VaultTransitSigner:
        return VaultTransitSigner(address=self.address, key_name=key, token_file=self.token_file)

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(10)


@pytest.fixture
def transit(tmp_path: Path) -> Iterator[Transit]:
    assert BINARY is not None
    port = _free_port()
    home = tmp_path / "home"
    home.mkdir()
    process = subprocess.Popen(
        [
            BINARY,
            *("server", "-dev", f"-dev-root-token-id={ROOT_TOKEN}"),
            f"-dev-listen-address=127.0.0.1:{port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "HOME": str(home)},
    )
    token_file = tmp_path / "transit-token"
    token_file.write_text(ROOT_TOKEN + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    server = Transit(f"http://127.0.0.1:{port}", token_file, process)
    for _ in range(300):
        try:
            server.api("GET", "/v1/sys/health")
            break
        except httpx2.HTTPError:
            time.sleep(0.05)
    else:
        server.stop()
        pytest.fail("transit server did not start")
    server.api("POST", "/v1/sys/mounts/transit", {"type": "transit"})
    server.api("POST", "/v1/transit/keys/access-tokens", {"type": "ecdsa-p256"})
    yield server
    server.stop()


def _authz(signer: VaultTransitSigner | None, spire: LocalSvidIssuer) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=None, component="authz"),
        signing_rotation_seconds=0,
        signer=signer,
    )


def _token(server: AuthzServer, spire: LocalSvidIssuer) -> Any:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": spire.mint(RESEARCH, ISSUER),
        "resource": SERVER_A,
        "scope": "notes:read",
    }
    with TestClient(server.app()) as client:
        return client.post("/token", data=form)


def _verify(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    key = _find_key(jwks, jwt.get_unverified_header(token)["kid"])
    assert key is not None, "kid not published"
    claims: dict[str, Any] = jwt.decode(
        token, key, algorithms=["ES256"], audience=SERVER_A, issuer=ISSUER
    )
    return claims


@needs_server
def test_two_replicas_share_one_transit_key(transit: Transit) -> None:
    spire = LocalSvidIssuer()
    first, second = _authz(transit.signer(), spire), _authz(transit.signer(), spire)
    response = _token(first, spire)
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert jwt.get_unverified_header(token)["typ"] == "at+jwt"
    assert _verify(token, second.jwks())["sub"] == RESEARCH
    assert first.jwks() == second.jwks()


@needs_server
def test_transit_rotation_keeps_old_tokens_valid(transit: Transit) -> None:
    spire = LocalSvidIssuer()
    signer = transit.signer()
    server = _authz(signer, spire)
    old = _token(server, spire).json()["access_token"]
    transit.api("POST", "/v1/transit/keys/access-tokens/rotate")
    signer._refresh(force=True)
    new = _token(server, spire).json()["access_token"]
    assert jwt.get_unverified_header(old)["kid"] != jwt.get_unverified_header(new)["kid"]
    jwks = server.jwks()
    assert _verify(old, jwks) and _verify(new, jwks)


@needs_server
def test_transit_outage_fails_closed(transit: Transit) -> None:
    spire = LocalSvidIssuer()
    server = _authz(transit.signer(), spire)
    assert _token(server, spire).status_code == 200
    transit.stop()
    server.signer._fetched_at = None  # type: ignore[union-attr]
    response = _token(server, spire)
    assert (response.status_code, response.json()["error"]) == (503, "temporarily_unavailable")
    with TestClient(server.app()) as client:
        assert client.get("/jwks.json").status_code == 503
        assert client.get("/readyz").json() == {"status": "signer_unavailable"}


@needs_server
def test_wrong_key_type_or_token_is_refused(transit: Transit, tmp_path: Path) -> None:
    transit.api("POST", "/v1/transit/keys/rsa-key", {"type": "rsa-2048"})
    with pytest.raises(SignerError, match="ecdsa-p256"):
        transit.signer("rsa-key").public_jwks()
    wrong = tmp_path / "wrong-token"
    wrong.write_text("not-the-token", encoding="utf-8")
    wrong.chmod(0o600)
    bad = VaultTransitSigner(address=transit.address, key_name="access-tokens", token_file=wrong)
    with pytest.raises(SignerError, match="unavailable"):
        bad.public_jwks()


def test_transit_address_and_token_file_rules(tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("t", encoding="utf-8")
    token.chmod(0o644)
    with pytest.raises(ValueError, match="https"):
        VaultTransitSigner(address="http://vault.example.org", key_name="k", token_file=token)
    signer = VaultTransitSigner(address="http://127.0.0.1:1", key_name="k", token_file=token)
    with pytest.raises(SignerError, match="UnsafeFileError"):
        signer.public_jwks()


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--dev-ephemeral-signing-key", "--transit-address", "https://vault.example.org"],
        ["--transit-address", "https://vault.example.org", "--signing-rotation-seconds", "0"],
        ["--dev-ephemeral-signing-key", "--verification-key-file", "old.pub"],
    ],
)
def test_exactly_one_usable_key_source_is_required(extra: list[str]) -> None:
    parser = authz.build_parser()
    args = parser.parse_args(["--issuer", ISSUER, "--policy", "p.yaml", *extra])
    with pytest.raises(SystemExit):
        authz._key_options(args, parser)


def test_development_key_is_announced(capsys: pytest.CaptureFixture[str]) -> None:
    parser = authz.build_parser()
    args = parser.parse_args(
        ["--issuer", ISSUER, "--policy", "p.yaml", "--dev-ephemeral-signing-key"]
    )
    assert authz._key_options(args, parser) == {}
    assert '"ephemeral_signing_key"' in capsys.readouterr().err
