"""Real Workload API probes. Never print assertions, access tokens or exception text."""

from __future__ import annotations

import asyncio
import json
import sys
import time

import httpx2
import jwt
from spiffe import WorkloadApiClient

from mcp_svid_auth.agent_client import UrlPolicy, call_tool
from mcp_svid_auth.authz import CLIENT_ASSERTION_TYPE

ISSUER = "http://authz:8100"
RESOURCE = "http://notes-a:8101/mcp"


def svid(issuer: str) -> str:
    with WorkloadApiClient() as client:
        return str(client.fetch_jwt_svid(audience={issuer}).token)


def post(assertion: str, issuer: str) -> httpx2.Response:
    return httpx2.post(
        issuer + "/token",
        timeout=10,
        trust_env=False,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
            "resource": RESOURCE,
            "scope": "notes:read",
        },
    )


def ready() -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            svid(ISSUER)
            for url in [
                ISSUER + "/.well-known/oauth-authorization-server",
                "http://notes-a:8101/.well-known/oauth-protected-resource/mcp",
                "http://notes-b:8102/.well-known/oauth-protected-resource/mcp",
                "http://notes-rogue:8103/.well-known/oauth-protected-resource/mcp",
                "http://authz-strict:8104/.well-known/oauth-authorization-server",
            ]:
                httpx2.get(url, timeout=3, trust_env=False).raise_for_status()
            print(json.dumps({"event": "ready", "ok": True}))
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError("readiness timeout")


def replay(strict: bool) -> None:
    issuer = "http://authz-strict:8104" if strict else ISSUER
    assertion = svid(issuer)
    results = [post(assertion, issuer) for _ in range(2)]
    print(
        json.dumps(
            {
                "event": "strict_replay" if strict else "svid_replay",
                "statuses": [r.status_code for r in results],
                "issued": ["access_token" in r.json() for r in results],
                "second_error": results[1].json().get("error"),
            }
        )
    )


def issuance() -> None:
    assertions = [svid(ISSUER) for _ in range(3)]
    claims = [jwt.decode(value, options={"verify_signature": False}) for value in assertions]
    identifiers = [claim.get("jti") for claim in claims]
    result = post(assertions[-1], ISSUER)
    print(
        json.dumps(
            {
                "event": "issuer_observation",
                "fetches": len(assertions),
                "distinct_assertions": len(set(assertions)),
                "all_have_jti": all(
                    isinstance(value, str) and bool(value) for value in identifiers
                ),
                "distinct_jti": len({value for value in identifiers if isinstance(value, str)}),
                "accepted": result.status_code == 200,
            }
        )
    )


def rotation() -> None:
    initial = post(svid(ISSUER), ISSUER)
    initial.raise_for_status()
    old = initial.json()["access_token"]
    old_kid = jwt.get_unverified_header(old)["kid"]
    deadline = time.monotonic() + 200
    prepublished = False
    public_only = True
    while time.monotonic() < deadline:
        keys = httpx2.get(ISSUER + "/jwks.json", timeout=5, trust_env=False).json()["keys"]
        public_only = public_only and all(not {"d", "p", "q"}.intersection(key) for key in keys)
        current = post(svid(ISSUER), ISSUER)
        current.raise_for_status()
        new = current.json()["access_token"]
        new_kid = jwt.get_unverified_header(new)["kid"]
        if new_kid == old_kid:
            prepublished = prepublished or any(key["kid"] != old_kid for key in keys)
        else:
            outcomes = [
                asyncio.run(
                    call_tool(
                        RESOURCE,
                        token,
                        "notes.search",
                        {"query": "welcome"},
                        url_policy=UrlPolicy(allow_http=True, allow_private=True),
                    )
                )
                for token in (old, new)
            ]
            print(
                json.dumps(
                    {
                        "event": "planned_rotation",
                        "prepublished": prepublished,
                        "public_only": public_only,
                        "old_and_new_keys_present": {old_kid, new_kid}.issubset(
                            {key["kid"] for key in keys}
                        ),
                        "old_token_accepted": "welcome" in outcomes[0],
                        "new_token_accepted": "welcome" in outcomes[1],
                    }
                )
            )
            return
        time.sleep(2)
    raise RuntimeError("planned rotation timeout")


def lifecycle() -> None:
    original = svid(ISSUER)
    expires = int(jwt.decode(original, options={"verify_signature": False})["exp"])
    if not time.time() < expires <= time.time() + 300:
        raise RuntimeError("unexpected SVID lifetime")
    successful = 0
    renewed = False
    outcome = ""
    while time.time() <= expires + 35:
        current = svid(ISSUER)
        result = post(current, ISSUER)
        if result.status_code != 200:
            raise RuntimeError("renewed credential refused")
        successful += 1
        if time.time() > expires:
            claims = jwt.decode(current, options={"verify_signature": False})
            renewed = current != original and int(claims["exp"]) > time.time()
            outcome = asyncio.run(
                call_tool(
                    RESOURCE,
                    result.json()["access_token"],
                    "notes.search",
                    {"query": "welcome"},
                    url_policy=UrlPolicy(allow_http=True, allow_private=True),
                )
            )
        if time.time() > expires + 30:
            old = post(original, ISSUER)
            print(
                json.dumps(
                    {
                        "event": "svid_lifecycle",
                        "successful_requests": successful,
                        "renewed_after_expiry": renewed,
                        "tool_after_expiry": "welcome" in outcome,
                        "old_status": old.status_code,
                        "old_error": old.json().get("error"),
                    }
                )
            )
            return
        time.sleep(5)
    raise RuntimeError("expiry probe timeout")


def main() -> None:
    try:
        mode = sys.argv[1]
        if mode == "ready":
            ready()
        elif mode in ("replay", "strict"):
            replay(mode == "strict")
        elif mode == "issuance":
            issuance()
        elif mode == "rotation":
            rotation()
        elif mode == "lifecycle":
            lifecycle()
        else:
            raise RuntimeError("unknown probe")
    except Exception:
        print(json.dumps({"event": "probe_failed"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
