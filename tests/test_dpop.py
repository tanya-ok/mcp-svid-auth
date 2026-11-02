"""RFC 9449 sender constraint: proof rules, issuance binding and resource enforcement."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.testclient import TestClient

from mcp_svid_auth.agent_client import TokenRequestError, call_tool, fetch_access_token
from mcp_svid_auth.audit import AuditLog
from mcp_svid_auth.authz import (
    CLIENT_ASSERTION_TYPE,
    TOKEN_EXCHANGE_GRANT,
    AuthzServer,
)
from mcp_svid_auth.dpop import (
    MAX_PROOF_BYTES,
    PROOF_MAX_AGE_SECONDS,
    PROOF_MAX_FUTURE_SECONDS,
    DPoPError,
    DPoPKey,
    ProofReplayStore,
    VerifiedProof,
    access_token_hash,
    canonical_htu,
    jwk_thumbprint,
    verify_proof,
)
from mcp_svid_auth.mcp_server import create_app
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import (
    DEV_URLS,
    ISSUER,
    POLICY,
    READER,
    RESEARCH,
    SERVER_A,
    HostRouter,
    _running,
)

TOKEN_URL = f"{ISSUER}/token"
RW = "notes:read notes:write"
FAKE_AT = "synthetic.at.value"
OTHER_AT = "other.at.value"
AUTHZ_TEST = "authz.test"


def _custom_proof(
    key: DPoPKey,
    *,
    headers: dict[str, Any] | None = None,
    claims: dict[str, Any] | None = None,
    algorithm: str = "ES256",
    signer: Any = None,
) -> str:
    body = {"jti": "synthetic-jti", "htm": "POST", "htu": SERVER_A, "iat": int(time.time())}
    body.update(claims or {})
    head = {"typ": "dpop+jwt", "jwk": key.public_jwk}
    head.update(headers or {})
    return jwt.encode(body, signer or key.private_key, algorithm=algorithm, headers=head)


def _verify(proof: str, **kwargs: Any) -> VerifiedProof:
    args: dict[str, Any] = {"htm": "POST", "htu": SERVER_A, "now": time.time()}
    args.update(kwargs)
    return verify_proof(proof, **args)


class TestProofRules:
    def test_valid_proof_returns_the_key_thumbprint(self) -> None:
        key = DPoPKey()
        assert _verify(key.proof("POST", SERVER_A)).jkt == key.jkt

    def test_thumbprint_matches_rfc_7638_example_shape(self) -> None:
        jwk = {"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB", "ignored": "x"}
        assert jwk_thumbprint(jwk) == jwk_thumbprint({**jwk, "ignored": "y"})
        assert "=" not in jwk_thumbprint(jwk)

    def test_ath_binds_the_proof_to_one_token(self) -> None:
        key = DPoPKey()
        proof = key.proof("POST", SERVER_A, FAKE_AT)
        assert _verify(proof, access_token=FAKE_AT).jkt == key.jkt
        with pytest.raises(DPoPError, match="ath_mismatch"):
            _verify(proof, access_token=OTHER_AT)
        with pytest.raises(DPoPError, match="ath_mismatch"):
            _verify(key.proof("POST", SERVER_A), access_token=FAKE_AT)

    @pytest.mark.parametrize(
        ("kwargs", "label"),
        [
            ({"htm": "GET"}, "htm_mismatch"),
            ({"htu": "http://notes-b.test/mcp"}, "htu_mismatch"),
            ({"htu": "http://notes-a.test/other"}, "htu_mismatch"),
        ],
    )
    def test_method_and_uri_must_match(self, kwargs: dict[str, str], label: str) -> None:
        with pytest.raises(DPoPError, match=label):
            _verify(DPoPKey().proof("POST", SERVER_A), **kwargs)

    @pytest.mark.parametrize(
        "variant",
        [
            f"{SERVER_A}?a=1",
            f"{SERVER_A}#fragment",
            "HTTP://NOTES-A.TEST/mcp",
            "http://notes-a.test:80/mcp",
        ],
    )
    def test_uri_comparison_ignores_query_fragment_case_and_default_port(
        self, variant: str
    ) -> None:
        proof = _custom_proof(DPoPKey(), claims={"htu": variant})
        assert _verify(proof).jti == "synthetic-jti"

    def test_uri_comparison_keeps_a_different_port(self) -> None:
        assert canonical_htu("https://a.test:8443/mcp") != canonical_htu("https://a.test/mcp")

    @pytest.mark.parametrize("url", ["ftp://a.test/x", "http://user:pw@a.test/x", "http://[bad"])
    def test_invalid_uri_is_refused(self, url: str) -> None:
        with pytest.raises(DPoPError, match="invalid_htu"):
            canonical_htu(url)

    def test_wrong_typ(self) -> None:
        with pytest.raises(DPoPError, match="invalid_typ"):
            _verify(_custom_proof(DPoPKey(), headers={"typ": "JWT"}))

    def test_other_algorithm_is_refused(self) -> None:
        key = DPoPKey()
        proof = jwt.encode(
            {"jti": "x", "htm": "POST", "htu": SERVER_A, "iat": int(time.time())},
            secrets.token_urlsafe(48),
            algorithm="HS256",
            headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
        )
        with pytest.raises(DPoPError, match="unsupported_alg"):
            _verify(proof)

    def test_signature_from_another_key_is_refused(self) -> None:
        proof = _custom_proof(DPoPKey(), signer=ec.generate_private_key(ec.SECP256R1()))
        with pytest.raises(DPoPError, match="invalid_proof_signature"):
            _verify(proof)

    @pytest.mark.parametrize("member", ["jku", "x5u", "x5c", "kid"])
    def test_remote_key_references_are_refused(self, member: str) -> None:
        proof = _custom_proof(DPoPKey(), headers={member: "http://attacker.test/key"})
        with pytest.raises(DPoPError, match="remote_key_reference"):
            _verify(proof)

    @pytest.mark.parametrize(
        "jwk",
        [
            None,
            "not-a-key",
            {"kty": "EC", "crv": "P-256", "x": "AA"},
            {"kty": "RSA", "crv": "P-256", "x": "AA", "y": "BB"},
            {"kty": "EC", "crv": "P-384", "x": "AA", "y": "BB"},
            {"kty": "EC", "crv": "P-256", "x": 1, "y": 2},
            {"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB"},
        ],
    )
    def test_malformed_jwk_is_refused(self, jwk: Any) -> None:
        proof = _custom_proof(DPoPKey(), headers={"jwk": jwk})
        with pytest.raises(DPoPError, match="invalid_jwk"):
            _verify(proof)

    def test_private_key_material_is_refused(self) -> None:
        key = DPoPKey()
        proof = _custom_proof(key, headers={"jwk": {**key.public_jwk, "d": "c2VjcmV0"}})
        with pytest.raises(DPoPError, match="invalid_jwk"):
            _verify(proof)

    def test_oversized_or_garbage_proof_is_refused(self) -> None:
        with pytest.raises(DPoPError, match="invalid_proof_size"):
            _verify("a" * (MAX_PROOF_BYTES + 1))
        with pytest.raises(DPoPError, match="invalid_proof_size"):
            _verify("proof-é")
        with pytest.raises(DPoPError, match="malformed_proof"):
            _verify("not.a.jwt")

    @pytest.mark.parametrize("offset", [-(PROOF_MAX_AGE_SECONDS + 5), PROOF_MAX_FUTURE_SECONDS + 5])
    def test_stale_or_future_proof_is_refused(self, offset: int) -> None:
        now = time.time()
        proof = _custom_proof(DPoPKey(), claims={"iat": int(now) + offset})
        with pytest.raises(DPoPError, match="proof_not_fresh"):
            _verify(proof, now=now)

    @pytest.mark.parametrize(
        ("claims", "label"),
        [
            ({"iat": True}, "invalid_iat"),
            ({"iat": "soon"}, "invalid_iat"),
            ({"jti": ""}, "invalid_jti"),
            ({"jti": "x" * 129}, "invalid_jti"),
        ],
    )
    def test_invalid_claim_types_are_refused(self, claims: dict[str, Any], label: str) -> None:
        with pytest.raises(DPoPError, match=label):
            _verify(_custom_proof(DPoPKey(), claims=claims))


class TestReplayStore:
    def _proof(self, jti: str = "one", iat: int = 1000) -> VerifiedProof:
        return VerifiedProof(jkt="key", jti=jti, iat=iat)

    def test_second_use_is_refused(self) -> None:
        store = ProofReplayStore()
        store.add(self._proof(), 1000)
        with pytest.raises(DPoPError, match="proof_replayed"):
            store.add(self._proof(), 1001)

    def test_same_jti_from_another_key_is_separate(self) -> None:
        store = ProofReplayStore()
        store.add(self._proof(), 1000)
        store.add(VerifiedProof(jkt="other", jti="one", iat=1000), 1000)
        assert len(store) == 2

    def test_full_store_fails_closed_and_keeps_live_entries(self) -> None:
        store = ProofReplayStore(max_entries=1)
        store.add(self._proof("one"), 1000)
        with pytest.raises(DPoPError, match="proof_replay_store_full"):
            store.add(self._proof("two"), 1001)
        with pytest.raises(DPoPError, match="proof_replayed"):
            store.add(self._proof("one"), 1002)

    def test_expired_entries_free_space_only_after_the_freshness_window(self) -> None:
        store = ProofReplayStore(max_entries=1)
        store.add(self._proof("one"), 1000)
        window = PROOF_MAX_AGE_SECONDS + PROOF_MAX_FUTURE_SECONDS
        with pytest.raises(DPoPError):
            store.add(self._proof("two", 1000 + window - 1), 1000 + window - 1)
        store.add(self._proof("two", 1000 + window), 1000 + window)
        assert len(store) == 1

    def test_invalid_size_is_refused(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            ProofReplayStore(max_entries=0)


def _token_form(spire: LocalSvidIssuer, *, resource: str = SERVER_A) -> dict[str, str]:
    return {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": spire.mint(RESEARCH, ISSUER),
        "resource": resource,
        "scope": "notes:read",
    }


@pytest.fixture
def dpop_authz(spire: LocalSvidIssuer, tmp_path: Path) -> AuthzServer:
    return AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        audit=AuditLog(path=tmp_path / "authz.jsonl", component="authz"),
        dpop_required=True,
        token_exchange=True,
    )


class TestIssuance:
    def _post(
        self, authz: AuthzServer, form: dict[str, str], headers: list[tuple[str, str]] | None = None
    ) -> tuple[int, dict[str, Any]]:
        with TestClient(authz.app(), base_url=ISSUER) as client:
            response = client.post(
                "/token",
                content=httpx2.QueryParams(form).__str__(),
                headers=[("content-type", "application/x-www-form-urlencoded"), *(headers or [])],
            )
        return response.status_code, response.json()

    def test_valid_proof_binds_the_token_to_the_key(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer
    ) -> None:
        key = DPoPKey()
        status, body = self._post(
            dpop_authz, _token_form(spire), [("DPoP", key.proof("POST", TOKEN_URL))]
        )
        assert status == 200
        assert body["token_type"] == "DPoP"
        assert body["expires_in"] == 300
        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        assert claims["cnf"] == {"jkt": key.jkt}
        assert claims["aud"] == SERVER_A
        assert claims["scope"] == "notes:read"
        assert claims["exp"] - claims["iat"] == 300

    @pytest.mark.parametrize("count", [0, 2])
    def test_exactly_one_proof_is_required(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, count: int
    ) -> None:
        key = DPoPKey()
        headers = [("DPoP", key.proof("POST", TOKEN_URL)) for _ in range(count)]
        status, body = self._post(dpop_authz, _token_form(spire), headers)
        assert (status, body["error"]) == (400, "invalid_dpop_proof")

    def test_proof_for_another_endpoint_is_refused(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer
    ) -> None:
        proof = DPoPKey().proof("POST", SERVER_A)
        status, body = self._post(dpop_authz, _token_form(spire), [("DPoP", proof)])
        assert (status, body["error"]) == (400, "invalid_dpop_proof")
        assert "htu" not in body["error_description"]

    def test_proof_replay_at_the_token_endpoint_is_refused(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer
    ) -> None:
        proof = DPoPKey().proof("POST", TOKEN_URL)
        assert self._post(dpop_authz, _token_form(spire), [("DPoP", proof)])[0] == 200
        status, body = self._post(dpop_authz, _token_form(spire), [("DPoP", proof)])
        assert (status, body["error"]) == (400, "invalid_dpop_proof")

    def test_proof_does_not_replace_svid_authentication(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer
    ) -> None:
        form = {**_token_form(spire), "client_assertion": "not.a.svid"}
        status, body = self._post(dpop_authz, form, [("DPoP", DPoPKey().proof("POST", TOKEN_URL))])
        assert status == 401
        assert body["error"] == "invalid_client"

    def test_metadata_advertises_the_algorithm(self, dpop_authz: AuthzServer) -> None:
        assert dpop_authz.metadata()["dpop_signing_alg_values_supported"] == ["ES256"]

    def test_bound_subject_token_cannot_be_exchanged(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer
    ) -> None:
        _, issued = self._post(
            dpop_authz, _token_form(spire), [("DPoP", DPoPKey().proof("POST", TOKEN_URL))]
        )
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": spire.mint(READER, ISSUER),
            "subject_token": issued["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": SERVER_A,
            "scope": "notes:read",
        }
        status, body = self._post(dpop_authz, form, [("DPoP", DPoPKey().proof("POST", TOKEN_URL))])
        assert (status, body["error"]) == (400, "invalid_request")
        assert "sender-constrained" in body["error_description"]


class DPoPWorld:
    def __init__(self, authz: AuthzServer, spire: LocalSvidIssuer, router: HostRouter) -> None:
        self.authz = authz
        self.spire = spire
        self.router = router

    def http(self, **kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.router), **kwargs)

    async def token(self, key: DPoPKey, scope: str = "notes:read") -> str:
        body = await fetch_access_token(
            SERVER_A,
            self.spire.source_for(RESEARCH),
            scope=scope,
            spiffe_id=RESEARCH,
            http=self.http,
            url_policy=DEV_URLS,
            trusted_issuers=[ISSUER],
            dpop=key,
        )
        return str(body["access_token"])

    async def post(self, headers: dict[str, str] | list[tuple[str, str]]) -> httpx2.Response:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        accept = [("accept", "application/json, text/event-stream")]
        pairs = list(headers.items()) if isinstance(headers, dict) else headers
        async with self.http() as client:
            return await client.post(SERVER_A, json=payload, headers=[*accept, *pairs])


@contextlib.asynccontextmanager
async def _dpop_world(authz: AuthzServer, spire: LocalSvidIssuer, path: Path) -> AsyncIterator[Any]:
    audit = AuditLog(path=path)
    app = create_app(
        name="a",
        resource=SERVER_A,
        issuer=ISSUER,
        jwks=authz.jwks,
        audit=audit,
        dpop_required=True,
    )
    router = HostRouter({AUTHZ_TEST: authz.app(), "notes-a.test": app})
    async with _running([app]):
        yield DPoPWorld(authz, spire, router)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
class TestResourceServer:
    async def test_bound_token_with_fresh_proofs_calls_tools(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key)
            result = await call_tool(
                SERVER_A,
                token,
                "notes.search",
                {"query": "welcome"},
                http=world.http,
                url_policy=DEV_URLS,
                dpop=key,
            )
            assert "welcome" in result.lower()
            assert not result.startswith("HTTP")

    async def test_stolen_token_without_the_key_is_denied(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            token = await world.token(DPoPKey())
            result = await call_tool(
                SERVER_A,
                token,
                "notes.search",
                {"query": "x"},
                http=world.http,
                url_policy=DEV_URLS,
                dpop=DPoPKey(),
            )
            assert result.startswith('HTTP 401: DPoP error="invalid_token"')

    async def test_bound_token_sent_as_bearer_is_denied(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key)
            response = await world.post(
                {
                    "Authorization": f"Bearer {token}",
                    "DPoP": key.proof("POST", SERVER_A, token),
                }
            )
            assert response.status_code == 401
            assert response.headers["www-authenticate"].startswith("DPoP ")

    @pytest.mark.parametrize(
        "case", ["missing", "duplicate", "wrong_ath", "wrong_htm", "wrong_htu"]
    )
    async def test_bad_proof_is_denied(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path, case: str
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key)
            auth = ("Authorization", f"DPoP {token}")
            good = key.proof("POST", SERVER_A, token)
            headers = {
                "missing": [auth],
                "duplicate": [auth, ("DPoP", good), ("DPoP", key.proof("POST", SERVER_A, token))],
                "wrong_ath": [auth, ("DPoP", key.proof("POST", SERVER_A, "other.token"))],
                "wrong_htm": [auth, ("DPoP", key.proof("GET", SERVER_A, token))],
                "wrong_htu": [auth, ("DPoP", key.proof("POST", "http://other.test/mcp", token))],
            }[case]
            assert (await world.post(headers)).status_code == 401

    async def test_valid_proof_is_accepted_once_even_concurrently(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key)
            headers = {
                "Authorization": f"DPoP {token}",
                "DPoP": key.proof("POST", SERVER_A, token),
            }
            responses = await asyncio.gather(*(world.post(headers) for _ in range(5)))
            statuses = sorted(r.status_code for r in responses)
            assert statuses.count(401) == 4
            assert statuses[0] != 401

    async def test_forged_forwarding_headers_do_not_change_the_target(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key)
            response = await world.post(
                {
                    "Authorization": f"DPoP {token}",
                    "DPoP": key.proof("POST", "http://attacker.test/mcp", token),
                    "X-Forwarded-Host": "attacker.test",
                    "Forwarded": "host=attacker.test",
                }
            )
            assert response.status_code == 401

    async def test_scope_denial_still_applies_and_uses_the_dpop_scheme(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            key = DPoPKey()
            token = await world.token(key, scope="notes:read")
            result = await call_tool(
                SERVER_A,
                token,
                "notes.write",
                {"text": "x"},
                http=world.http,
                url_policy=DEV_URLS,
                dpop=key,
            )
            assert result.startswith('HTTP 403: DPoP error="insufficient_scope"')

    async def test_unbound_token_is_denied_in_dpop_mode(
        self, spire: LocalSvidIssuer, dpop_authz: AuthzServer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world:
            dpop_authz.dpop_required = False
            plain = dpop_authz.issue(_token_form(spire))["access_token"]
            dpop_authz.dpop_required = True
            key = DPoPKey()
            response = await world.post(
                {"Authorization": f"DPoP {plain}", "DPoP": key.proof("POST", SERVER_A, plain)}
            )
            assert response.status_code == 401

    async def test_metadata_stays_public_and_declares_the_requirement(
        self, dpop_authz: AuthzServer, spire: LocalSvidIssuer, tmp_path: Path
    ) -> None:
        async with _dpop_world(dpop_authz, spire, tmp_path / "a.jsonl") as world, world.http() as c:
            response = await c.get("http://notes-a.test/.well-known/oauth-protected-resource/mcp")
            assert response.status_code == 200
            assert response.json()["dpop_bound_access_tokens_required"] is True


@pytest.mark.anyio
class TestCompatibility:
    async def test_bearer_mode_rejects_a_bound_token(self, world_factory: Any) -> None:
        async with world_factory() as world:
            # Signed by the same keys the Bearer servers trust, but sender-constrained.
            world.authz.dpop_required = True
            key = DPoPKey()
            token = world.authz.issue(_token_form(world.spire), [key.proof("POST", TOKEN_URL)])[
                "access_token"
            ]
            world.authz.dpop_required = False
            result = await call_tool(
                SERVER_A,
                token,
                "notes.search",
                {"query": "x"},
                http=world.http,
                url_policy=DEV_URLS,
            )
            assert result.startswith("HTTP 401")

    async def test_client_requiring_dpop_refuses_a_bearer_response(
        self, world_factory: Any
    ) -> None:
        async with world_factory() as world:
            with pytest.raises(TokenRequestError, match="not sender-constrained"):
                await fetch_access_token(
                    SERVER_A,
                    world.spire.source_for(RESEARCH),
                    scope="notes:read",
                    http=world.http,
                    url_policy=DEV_URLS,
                    trusted_issuers=[ISSUER],
                    dpop=DPoPKey(),
                )

    async def test_client_without_a_key_refuses_a_bound_token(self, world_factory: Any) -> None:
        async with world_factory() as world:
            world.authz.dpop_required = True
            original = world.authz.issue

            def forced(form: dict[str, str], proofs: list[str] | None = None) -> dict[str, Any]:
                body: dict[str, Any] = original(form, [DPoPKey().proof("POST", TOKEN_URL)])
                return body

            world.authz.issue = forced
            with pytest.raises(TokenRequestError, match="lacks"):
                await fetch_access_token(
                    SERVER_A,
                    world.spire.source_for(RESEARCH),
                    scope="notes:read",
                    http=world.http,
                    url_policy=DEV_URLS,
                    trusted_issuers=[ISSUER],
                )

    async def test_client_sends_a_new_proof_on_every_request(self) -> None:
        seen: list[str] = []
        key = DPoPKey()

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(request.headers["dpop"])
            assert request.headers["authorization"] == "DPoP synthetic.token"
            return httpx2.Response(200)

        from mcp_svid_auth.dpop import DPoPAuth  # noqa: PLC0415

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), auth=DPoPAuth("synthetic.token", key)
        ) as client:
            await client.post(SERVER_A)
            await client.post(SERVER_A)
        assert len(set(seen)) == 2
        for proof in seen:
            claims = jwt.decode(proof, options={"verify_signature": False})
            assert claims["ath"] == access_token_hash("synthetic.token")
