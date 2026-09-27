# Demo scenarios

`make demo` runs four scenarios against a real SPIRE 1.15.3 stack. Policy for all of them is `deploy/policy.yaml`.

## Workloads

| SPIFFE ID | Container label `org.example.svid.workload` | In policy |
|---|---|---|
| `spiffe://example.org/authz` | `authz` | n/a |
| `spiffe://example.org/mcp/notes-a` | `notes-a` | n/a |
| `spiffe://example.org/mcp/notes-b` | `notes-b` | n/a |
| `spiffe://example.org/agent/research` | `agent-research` | notes-a: `notes:read notes:write`; notes-b: `notes:read` |
| `spiffe://example.org/agent/intruder` | `agent-intruder` | No |

Registration entries use `docker:label:org.example.svid.workload:<name>` selectors, a JWT-SVID TTL of 300s and `-jwtSVIDIncludeJTI`, so each SVID carries a `jti`. authz runs with `--svid-replay=allow-reuse-within-lifetime`: the SPIRE 1.15.3 agent re-serves one cached SVID per audience, so scenarios 2 and 4 present the same SVID and `jti` as scenario 1. See [JWT-SVID replay tracking](security.md#jwt-svid-replay-tracking). The SPIRE agent reads labels through the Docker socket; see [Docker socket exposure](security.md#docker-socket-exposure). Workloads still run as distinct non-root UIDs, but the UID no longer decides the identity.

## Scenarios

| # | Caller | Target | Expected |
|---|---|---|---|
| 1 | `agent/research` | notes-a | token with `notes:read notes:write`, both tools allowed |
| 2 | `agent/research` | notes-b | token with `notes:read`, `notes.write` gets 403 `insufficient_scope` |
| 3 | `agent/intruder` | notes-a | valid SVID, not in `policy.yaml`, token request fails with `unauthorized_client` |
| 4 | `agent/research` | token for notes-a sent to notes-b | 401 `invalid_token`, audit reason `InvalidAudienceError` |

Commands, as run by `deploy/demo.sh`. Each run also passes `--trusted-issuer http://authz:8100`, omitted below:

```sh
# 1
mcp-svid-agent --resource http://notes-a:8101/mcp --scope "notes:read notes:write" \
  --spiffe-id spiffe://example.org/agent/research
# 2
mcp-svid-agent --resource http://notes-b:8102/mcp --scope notes:read
# 3 (in the agent-intruder container)
mcp-svid-agent --resource http://notes-a:8101/mcp --scope notes:read
# 4
mcp-svid-agent --resource http://notes-a:8101/mcp --scope "notes:read notes:write" \
  --steal-token http://notes-b:8102/mcp
```

In each run the agent calls `notes.search` and then `notes.write`, and prints one JSON event per step (`token`, `replay`, `call`, `token_denied`, or `issuer_refused`).

## Result

| Item | State |
|---|---|
| `make demo` against SPIRE 1.15.3 | Pass on 2026-09-27, Docker Desktop 29.6.1 on macOS, docker attestor, `--trusted-issuer`, `--svid-replay=allow-reuse-within-lifetime`. All four scenarios behave as in the table above. The three authz allow lines carry the same `svid_jti`, which shows the agent SVID cache. |
| `make demo` with `--svid-replay reject` | Fails as expected on 2026-09-27: scenario 1 passes, scenarios 2 and 4 get `401 invalid_client: client assertion replayed`. Without `-jwtSVIDIncludeJTI` every request gets `401 invalid_client` (no `jti`). |
| Offline tests | Pass (`make check`) |

Audit line format:

```json
{"timestamp":"2026-09-26T18:07:11.742+00:00","component":"mcp_server:notes-b","spiffe_id":"spiffe://example.org/agent/research","tool":"notes.write","decision":"deny","reason":"insufficient_scope: needs notes:write"}
```

## Offline equivalents

The same behaviour is covered without SPIRE in `tests/`, using `LocalSvidIssuer`:

| Test file | Covers |
|---|---|
| `test_end_to_end.py` | Scenarios 1 to 4, Protected Resource Metadata, missing-token challenge |
| `test_authz.py` | SVID validation, policy grants, trust domain, `client_id` match, metadata, audit |
| `test_authz_hardening.py` | `iat` and SVID lifetime, fixed error strings, 503 on bundle failure, scope parsing, repeated parameters |
| `test_resource_server.py` | Expiry, issuer, `typ`, ES256 pin, unknown tool, bad and oversized bodies, every tool declares a scope |
| `test_stdio_wrapper.py` | Token file mode, refresh, fail closed, env export opt-in, cleanup |
| `test_jwks_fetcher.py` | Async JWKS fetch, one refetch on unknown `kid` at most every 10s, fail closed when the fetch fails |
| `test_authz_replay.py` | `--svid-replay` modes: `jti` required and single use in `reject`, reuse and missing `jti` accepted in `allow-reuse-within-lifetime`, malformed `jti` refused in both, full cache fails closed, demo sets the mode explicitly |
| `test_issuer_allowlist.py` | Trusted issuer allowlist: unknown and lookalike issuers refused before any SVID fetch, refusal event |
| `test_no_identifiers.py` | Optional anonymization denylist |
