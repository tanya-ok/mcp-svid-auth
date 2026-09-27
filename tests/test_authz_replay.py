"""JWT-SVID jti replay tracking at the token endpoint."""

from __future__ import annotations

import jwt
import pytest

from mcp_svid_auth.authz import AuthzServer, ReplayCache
from mcp_svid_auth.errors import AuthError
from mcp_svid_auth.policy import Policy
from mcp_svid_auth.spiffe_keys import LocalSvidIssuer
from tests.conftest import ISSUER, POLICY, READER, RESEARCH, SERVER_B
from tests.test_authz import _form, _post
from tests.test_authz_hardening import _audit_reasons


def test_replayed_svid_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    svid = spire.mint(RESEARCH, ISSUER)
    assert _post(authz, _form(svid))[0] == 200
    status, body = _post(authz, _form(svid, resource=SERVER_B, scope="notes:read"))
    assert (status, body["error"]) == (401, "invalid_client")
    assert body["error_description"] == "client assertion replayed"
    assert "client assertion replayed (jti=" in _audit_reasons(authz)[1]


def test_distinct_jti_accepted(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    for _ in range(3):
        assert _post(authz, _form(spire.mint(RESEARCH, ISSUER)))[0] == 200


def test_same_jti_for_different_sub_accepted(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    assert _post(authz, _form(spire.mint(RESEARCH, ISSUER, jti="shared")))[0] == 200
    form = _form(spire.mint(READER, ISSUER, jti="shared"), scope="notes:read")
    assert _post(authz, form)[0] == 200


def test_missing_jti_rejected(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER, jti=None)))
    assert (status, body["error"]) == (401, "invalid_client")
    assert body["error_description"] == "client assertion invalid"
    assert '"jti"' in _audit_reasons(authz)[0]
    assert len(authz.replay_cache) == 0


@pytest.mark.parametrize("jti", ["", 7, "x" * 257])
def test_malformed_jti_rejected(authz: AuthzServer, spire: LocalSvidIssuer, jti: object) -> None:
    status, body = _post(authz, _form(spire.mint(RESEARCH, ISSUER, jti=jti)))
    assert (status, body["error"]) == (401, "invalid_client")
    assert len(authz.replay_cache) == 0


def test_invalid_assertion_not_recorded(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    status, _ = _post(authz, _form(spire.mint(RESEARCH, ISSUER, ttl=3600)))
    assert status == 401
    assert len(authz.replay_cache) == 0


def test_expired_entries_evicted() -> None:
    cache = ReplayCache()
    cache.add("sub", "a", expires_at=100, now=0)
    cache.add("sub", "b", expires_at=200, now=0)
    cache.evict_expired(now=150)
    assert len(cache) == 1
    # After expiry the pair is forgotten; the signature check rejects the expired SVID anyway.
    cache.add("sub", "a", expires_at=300, now=150)
    with pytest.raises(AuthError, match="replayed"):
        cache.add("sub", "b", expires_at=300, now=150)


def test_expiry_includes_clock_skew(authz: AuthzServer, spire: LocalSvidIssuer) -> None:
    svid = spire.mint(RESEARCH, ISSUER, ttl=60)
    assert _post(authz, _form(svid))[0] == 200
    ((expires_at, _),) = authz.replay_cache._heap
    exp = jwt.decode(svid, options={"verify_signature": False})["exp"]
    assert expires_at == exp + 30


def test_full_cache_fails_closed(spire: LocalSvidIssuer) -> None:
    server = AuthzServer(
        issuer=ISSUER,
        policy=Policy.from_dict(POLICY),
        resolver=spire.resolver(),
        replay_cache=ReplayCache(max_entries=1),
    )
    assert _post(server, _form(spire.mint(RESEARCH, ISSUER)))[0] == 200
    status, body = _post(server, _form(spire.mint(RESEARCH, ISSUER)))
    assert (status, body["error"]) == (503, "temporarily_unavailable")
    assert len(server.replay_cache) == 1
