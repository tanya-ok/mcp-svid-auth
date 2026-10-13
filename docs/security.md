# Security model

!!! warning
    This is a proof of concept. Do not deploy it to protect real data. Report vulnerabilities privately through GitHub private vulnerability reporting, not in a public issue.

## Threat model

The table below is the short view. [Threat model (STPA-Sec)](threat-model.md) derives these threats from the control structure, maps unsafe control actions to MCP 2026-07-28 clauses, and lists the ones not mitigated.

| Threat | Mitigation here | Gap |
|---|---|---|
| Static key leak | No static keys. Access tokens live 5 min; SVID maximum is 5 min, with 60s SVIDs in the demo. | A stolen access token works until expiry. |
| Token replay to another server | `aud` bound to one resource. Each server checks `aud` equals its own URI. | None within one issuer. |
| JWT-SVID replay to authz | SVID `aud` must be the issuer only. Maximum SVID lifetime 5 min; demo TTL 60s. Default `--svid-replay reject`: `jti` required, each `(sub, jti)` accepted once. | The container demo runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent re-serves cached SVIDs; there a stolen SVID mints tokens until it expires. In `reject` mode the seen-set is in memory and per process, and a stolen, unused SVID still works once. |
| SVID harvesting by a malicious resource | The agent mints SVIDs only for issuers on its `--trusted-issuer` allowlist. An issuer named in Protected Resource Metadata that is not on the list is refused, and logged as `issuer_refused`, before any request to it and before any SVID fetch. Exact match after scheme, host and default port normalization; no prefix match. | The allowlist is per process, not per resource. |
| Discovery SSRF | Every URL the agent fetches or sends a credential to (resource, issuer, `token_endpoint`, tool call) must be `https` and resolve only to public addresses. The default transport connects to a checked address with the original TLS identity and ignores proxy environment variables. Refused URLs get no request. | `--allow-http` and `--allow-private-network` relax these checks for dev and log `url_policy_relaxed` on stderr at startup; the container demo needs both. Injected HTTP factories must enforce equivalent address checks. |
| Workload impersonation | SPIRE Kubernetes namespace/ServiceAccount selectors; copied labels are denied. | Cluster operators and those allowed to use an authorized ServiceAccount can assume its identity. |
| Over-broad access | Allowlist per SPIFFE ID, resource and scope. Per-tool scope check. Policy reloaded on SIGHUP or file change. | Policy is a local file. No versioning or review flow. Issued tokens outlive a revoked grant by up to 300s. |
| Confused deputy | Server never forwards the incoming token. An upstream call uses the server's own SVID-based token (`notes.search_upstream`), tested in `test_no_passthrough.py`. | No delegation chain: the upstream sees the relay, not the original caller. |
| Algorithm confusion | SVIDs: asymmetric algorithms only, `alg=none` rejected. Access tokens: ES256 only, `typ` `at+jwt`. Key selected by `kid` from a trusted key set. | None known. |
| Stale token in a stdio child | Token passed by 0600 file, refreshed. Wrapper deletes it and stops the child on expiry. With `--export-token-env` the child is stopped when the exported token expires. | `--export-token-env` values are visible in the process environment to the same UID. |
| Supply chain | Dependency majors bounded, images pinned by digest, `uv.lock` committed. | `httpx2` is a transitive dependency of `mcp` 2.x. On PyPI it is owned by Pydantic Services Inc., source github.com/pydantic/httpx2, uploaded via Trusted Publishing (checked 2026-09-26). |

## What each check proves

### Token endpoint (`authz.py`)

| Check | Failure | Proves |
|---|---|---|
| `grant_type` is `client_credentials` | 400 `unsupported_grant_type` | Only the machine-to-machine grant is accepted |
| `client_assertion_type` is `...:jwt-spiffe` | 401 `invalid_client` | The caller uses SPIFFE client authentication |
| No repeated form parameter | 400 `invalid_request` | No parameter smuggling (RFC 6749 section 3.2) |
| `resource` present | 400 `invalid_target` | Every token names exactly one target server |
| SVID `alg` in RS256/384/512, ES256/384/512, PS256/384 | 401 `invalid_client` | No `none`, no HMAC |
| `sub` is a valid SPIFFE ID in the policy trust domain | 401 `invalid_client` | Caller identity comes from the expected trust domain |
| Signature against the SPIRE JWT bundle, key by `kid` | 401 `invalid_client` | The SVID was issued by SPIRE for this trust domain |
| `sub`, `aud`, `exp`, `iat` present, and `jti` in `reject` mode; `exp` not past (30s leeway) | 401 `invalid_client` | The SVID is current and, in `reject` mode, individually identifiable |
| `aud` is the issuer and nothing else | 401 `invalid_client` | The SVID was minted for this authorization server only |
| `exp - iat` at most `--max-svid-lifetime` (300s) | 401 `invalid_client` | Long-lived SVIDs cannot be used as credentials |
| `jti`, if present, a UTF-8 string of 1 to 256 characters | 401 `invalid_client` | No oversized, non-string or unencodable identifiers reach the cache or the audit log |
| `reject` mode: `(sub, jti)` not seen before | 401 `invalid_client` | Each SVID is used once (RFC 7523 section 3) |
| `reject` mode: replay cache has room | 503 `temporarily_unavailable` | Memory is bounded and a full cache fails closed |
| `client_id`, if sent, equals `sub` | 401 `invalid_client` | No identity mismatch between parameters |
| SPIFFE ID in policy | 400 `unauthorized_client` | Only allowlisted workloads get tokens |
| Resource allowed for that SPIFFE ID | 400 `invalid_target` | Per-server allowlist |
| `scope` present, well formed, subset of grant | 400 `invalid_scope` | Least privilege, no implicit default scope |
| Trust bundle fetch fails | 503 `temporarily_unavailable` | Fails closed without leaking details |

Error descriptions returned to the client are fixed strings. Audit diagnostics use exception class names, never exception text; unverified subjects and SVID IDs are hashed.

### JWT-SVID replay tracking

`--svid-replay` selects the mode. The default is `reject`.

| Mode | `jti` | Reuse of one SVID | Use when |
|---|---|---|---|
| `reject` (default) | Required | 401 `invalid_client` on the second use | The SVID source mints a fresh `jti` per fetch and never re-serves an SVID |
| `allow-reuse-within-lifetime` | Optional, validated if present | Accepted until `exp` | The SVID source caches SVIDs, as the SPIRE 1.15.3 agent does. Explicit opt-out |

In `reject` mode:

- The token endpoint records each accepted `(sub, jti)` pair after signature, audience, lifetime, client ID, policy and subject budget checks pass. Invalid or unauthorized requests are not recorded.
- An entry lives until the assertion `exp` plus the 30s clock leeway, the same window in which the SVID would still validate. Expired entries are evicted on every insert.
- A second request with the same pair gets 401 `invalid_client` (`client assertion replayed`, RFC 7523 section 3.2). The audit line identifies a digest prefix of the `jti`.
- The cache defaults to 10,000 live entries globally and 1,000 per verified subject. Both limits are configurable. Exhaustion gets 503 `temporarily_unavailable`; live entries are never evicted to admit another assertion. Quotas reduce one caller's impact but do not guarantee availability against several authorized callers.
- The seen-set is in memory and per process. Several authz replicas, or a restart, each start with their own empty set.

SPIRE 1.15.3, tested 2026-09-27:

- JWT-SVIDs carry no `jti` by default. With `-jwtSVIDIncludeJTI` on the registration entry, the server adds a random `jti` to each SVID it mints (`pkg/server/credtemplate/builder.go`).
- The entry flag is documented to also bypass the agent JWT-SVID cache. In 1.15.3 it does not: the agent drops the attribute when it syncs entries (`additionalAttributesFromProto` in `pkg/agent/client/util.go` copies only `DisableX509SvidPrefetch`). Three fetches in a row from one workload returned the same token and the same `jti`.
- So under `reject`, the first token request from a workload succeeds and every later one within the cached SVID lifetime gets `client assertion replayed`. The demo therefore sets `--svid-replay=allow-reuse-within-lifetime` in `deploy/kubernetes/services.yaml` and keeps `-jwtSVIDIncludeJTI` in `scripts/kubernetes_demo.py`.

Residual risk in `allow-reuse-within-lifetime`: a JWT-SVID stolen from the agent, the workload or the wire mints access tokens at authz until it expires, up to `--max-svid-lifetime` (300s). Each allow audit line carries `svid_jti_sha256=<digest prefix>`, so reuse of one SVID is visible in the audit trail, but it is not blocked. Switch back to `reject` once the SVID source yields a fresh `jti` per fetch.

### Policy reload and grant revocation

| Trigger | Effect |
|---|---|
| SIGHUP | Reload now, even if the content is unchanged |
| File content changes (SHA-256), checked every `--policy-poll-seconds` (default 5s, 0 disables) | Reload |
| Reloaded file is unreadable or invalid | Fail closed: every token request gets `unauthorized_client` until a valid file loads |

Each reload writes an audit line with `decision` `policy_reload`, the first 16 hex characters of the file hash and the client count, or the exception type on failure.

Time to denial after a grant is removed:

| Credential | Denied after |
|---|---|
| New token request | The next reload: immediately on SIGHUP, at most one poll interval (5s) otherwise |
| Access token issued before the reload | Its `exp`, at most 300s (`DEFAULT_TOKEN_TTL`). Servers validate tokens locally; there is no revocation list or introspection |

### MCP server (`mcp_server.py`)

| Check | Failure | Proves |
|---|---|---|
| Bearer token present | 401 with `resource_metadata` challenge | Unauthenticated calls are refused and told where to authenticate |
| Header `typ` is `at+jwt` | 401 `invalid_token` | Only RFC 9068 access tokens, not SVIDs or ID tokens |
| `kid` found in the authz JWKS | 401 `invalid_token` | Token signed by the configured authorization server |
| Unknown `kid` triggers one JWKS refetch, at most every 10s | 401 `invalid_token` | A rotated authz key is picked up; random `kid` values cannot cause a fetch storm |
| JWKS fetched only from `--jwks-uri`, never from `jku` or `x5u` | not applicable | A token cannot choose its own verification key |
| JWKS fetch fails | 401 `invalid_token`, audit `jwks_unavailable` | Fails closed |
| JWKS has no usable key or a malformed key | 401 `invalid_token`, audit `jwks_invalid` | Fails closed, no 500 and no exception text |
| `alg` ES256, signature valid | 401 `invalid_token` | No algorithm confusion |
| `iss` equals configured issuer | 401 `invalid_token` | No tokens from another issuer |
| `aud` equals own resource URI | 401 `invalid_token` | A token for another server is useless here |
| `iss`, `sub`, `aud`, `exp`, `iat`, `scope` present, `exp` not past | 401 `invalid_token` | Complete, current token |
| Body at most 1 MiB | 413 `invalid_request` | Bounded request parsing |
| Body is valid JSON-RPC, each `tools/call` names a tool | 400 `invalid_request` | The scope guard cannot be bypassed with a malformed body |
| Tool has a declared scope | 400 `invalid_request` | Deny by default for unknown tools |
| Granted scopes include the tool scope | 403 `insufficient_scope` with `WWW-Authenticate` | Per-tool least privilege |
| `tools/list` shows only tools whose scope was granted | tool omitted | A read-only token does not see `notes.write` |
| A `tools/call` still running at the token `exp` | 401 `invalid_token`, audit `token_expired_during_call` | No tool result is returned on an expired token |
| `notes.write` re-checks the token `exp` just before it stores | Tool error `access token expired`, nothing stored | `notes.write` does not store after the token expired, apart from the short window between the check and the write. Other async tools may keep running after the 401, since the server is stateless and does not cancel them |

`build_mcp` also refuses to start if any registered tool has no declared scope.

## Non-goals

- Not production software. No HA or distributed rate limits; planned in-process key rotation and local cost budgets only. Plain HTTP inside the demo network.
- Not a replacement for an MCP gateway such as agentgateway. It shows the token flow a gateway could implement.
- No user delegation. The agent acts as itself (`client_credentials`). No token exchange or `act` claim chain yet.
- No X.509-SVID or WIT-SVID client authentication. JWT-SVID only.

## Known gaps

| Gap | Effect | Where |
|---|---|---|
| No access token `jti` tracking | A stolen access token is usable until it expires (5 min). | `mcp_server.py` |
| JWT-SVID reuse allowed in the demo | `allow-reuse-within-lifetime`: a stolen SVID mints tokens until it expires (max 300s). Needed because the SPIRE 1.15.3 agent re-serves cached SVIDs. | `deploy/kubernetes/services.yaml` |
| JWT-SVID seen-set per process | `reject` mode only. Replicas or a restart forget seen `jti` values. | `ReplayCache` |
| Signing keys in memory | Planned rotation preserves public-key overlap; an abrupt restart still loses old keys. | `AuthzServer.signing_key` |
| Checkpoint storage trust | Links detect internal edits but not tail truncation. A separately trusted terminal checkpoint detects suffix deletion and chain replacement; an attacker who can replace both defeats that protection. No signatures or managed external storage. See [Audit integrity](audit.md). | `audit.py` |
| Upstream widens read access | `notes.search_upstream` on notes-a lets any caller with `notes:read` on notes-a read notes-b under notes-a's own grant, even without a notes-b grant (confused deputy widening). Fix pending a delegation chain. | `mcp_server.Upstream` |
| Plain HTTP | No TLS inside the demo network. The demo agents run with `--allow-http --allow-private-network`. | `deploy/kubernetes/services.yaml`, `scripts/run_demo.py` |
| Custom transports and dev URL flags | The default client binds the actual connection to a policy-checked IP with original TLS hostname verification. Injected HTTP factories must enforce equivalent checks; dev flags deliberately allow private addresses and HTTP. | `agent_client.UrlPolicy`, `pinned_transport.py` |

## Runtime socket exposure

The default [Kubernetes lab](kubernetes-lab.md) does not mount a containerd or
Podman API socket. SPIRE verifies projected ServiceAccount tokens and uses the
Kubernetes workload attestor with namespace/ServiceAccount selectors. Application
pods receive only the Workload API socket, not Kubernetes API tokens. The agent
has root and host PID access inside the VM. Operators who may start workloads with
an authorized ServiceAccount can assume its identity; copied labels alone are
insufficient. The previous Podman label-attestation path was retired on
2026-10-13. Its dated reports remain historical evidence, not active runtime
instructions. See [Runtime](runtime.md).

## Compatibility boundary

The JWT-SVID exchange is a supported subset of draft -02. The local Workload API bundle lookup is a deliberate alternative the draft does not recommend for general interoperability. Generic MCP Client Credentials authentication and native gateway SPIFFE support do not imply support for this exchange. See [Compatibility](compatibility.md).

## Cost and planned rotation

[Cost budgets and signing-key overlap](auth-cost-rotation.md) specifies token form,
verification and JWKS response limits; negative fetch caching; per-subject replay
quotas; and public-key prepublication/retirement. These are per-process prototype
bounds, not an external denial-of-service protection or restart-safe key store.
