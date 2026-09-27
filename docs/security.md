# Security model

!!! warning
    This is a proof of concept. Do not deploy it to protect real data. Report vulnerabilities privately through GitHub private vulnerability reporting, not in a public issue.

## Threat model

The table below is the short view. [Threat model (STPA-Sec)](threat-model.md) derives these threats from the control structure, maps unsafe control actions to MCP 2026-07-28 clauses, and lists the ones not mitigated.

| Threat | Mitigation here | Gap |
|---|---|---|
| Static key leak | No static keys. SVID and access token both live 5 min. | A stolen access token works until expiry. |
| Token replay to another server | `aud` bound to one resource. Each server checks `aud` equals its own URI. | None within one issuer. |
| JWT-SVID replay to authz | SVID `aud` must be the issuer only. 5 min TTL. Default `--svid-replay reject`: `jti` required, each `(sub, jti)` accepted once. | The compose demo runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent re-serves cached SVIDs; there a stolen SVID mints tokens until it expires. In `reject` mode the seen-set is in memory and per process, and a stolen, unused SVID still works once. |
| SVID harvesting by a malicious resource | The agent mints SVIDs only for issuers on its `--trusted-issuer` allowlist. An issuer named in Protected Resource Metadata that is not on the list is refused, and logged as `issuer_refused`, before any request to it and before any SVID fetch. Exact match after scheme, host and default port normalization; no prefix match. | The allowlist is per process, not per resource. |
| Discovery SSRF | Every URL the agent fetches or sends a credential to (resource, issuer, `token_endpoint`, tool call) must be `https` and resolve only to public addresses. Refused URLs are logged as `url_refused` and get no request. | `--allow-http` and `--allow-private-network` turn the checks off for dev; the compose demo needs both. The check resolves the host itself and the HTTP client resolves it again, so DNS rebinding between the two lookups is not covered. |
| Workload impersonation | SPIRE docker attestor. Identity is bound to a container label, not a UID. | Anyone who can start a container with a registered label on that host gets that identity. |
| Over-broad access | Allowlist per SPIFFE ID, resource and scope. Per-tool scope check. Policy reloaded on SIGHUP or file change. | Policy is a local file. No versioning or review flow. Issued tokens outlive a revoked grant by up to 300s. |
| Confused deputy | Server never forwards the incoming token. | No delegation chain for downstream calls. |
| Algorithm confusion | SVIDs: asymmetric algorithms only, `alg=none` rejected. Access tokens: ES256 only, `typ` `at+jwt`. Key selected by `kid` from a trusted key set. | None known. |
| Stale token in a stdio child | Token passed by 0600 file, refreshed. Wrapper deletes it and stops the child on expiry. | `--export-token-env` values are visible in the process environment and never refreshed. |
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
| `jti`, if present, a string of 1 to 256 characters | 401 `invalid_client` | No oversized or non-string identifiers reach the cache or the audit log |
| `reject` mode: `(sub, jti)` not seen before | 401 `invalid_client` | Each SVID is used once (RFC 7523 section 3) |
| `reject` mode: replay cache has room | 503 `temporarily_unavailable` | Memory is bounded and a full cache fails closed |
| `client_id`, if sent, equals `sub` | 401 `invalid_client` | No identity mismatch between parameters |
| SPIFFE ID in policy | 400 `unauthorized_client` | Only allowlisted workloads get tokens |
| Resource allowed for that SPIFFE ID | 400 `invalid_target` | Per-server allowlist |
| `scope` present, well formed, subset of grant | 400 `invalid_scope` | Least privilege, no implicit default scope |
| Trust bundle fetch fails | 503 `temporarily_unavailable` | Fails closed without leaking details |

Error descriptions returned to the client are fixed strings. Exception details go only to the audit log.

### JWT-SVID replay tracking

`--svid-replay` selects the mode. The default is `reject`.

| Mode | `jti` | Reuse of one SVID | Use when |
|---|---|---|---|
| `reject` (default) | Required | 401 `invalid_client` on the second use | The SVID source mints a fresh `jti` per fetch and never re-serves an SVID |
| `allow-reuse-within-lifetime` | Optional, validated if present | Accepted until `exp` | The SVID source caches SVIDs, as the SPIRE 1.15.3 agent does. Explicit opt-out |

In `reject` mode:

- The token endpoint records each accepted `(sub, jti)` pair after the signature, audience and lifetime checks pass. Invalid assertions are not recorded.
- An entry lives until the assertion `exp` plus the 30s clock leeway, the same window in which the SVID would still validate. Expired entries are evicted on every insert.
- A second request with the same pair gets 401 `invalid_client` (`client assertion replayed`, RFC 7523 section 3.2). The audit line names the `jti`.
- The cache holds at most 10,000 live entries. When full, new assertions get 503 `temporarily_unavailable` instead of evicting live entries.
- The seen-set is in memory and per process. Several authz replicas, or a restart, each start with their own empty set.

SPIRE 1.15.3, tested 2026-09-27:

- JWT-SVIDs carry no `jti` by default. With `-jwtSVIDIncludeJTI` on the registration entry, the server adds a random `jti` to each SVID it mints (`pkg/server/credtemplate/builder.go`).
- The entry flag is documented to also bypass the agent JWT-SVID cache. In 1.15.3 it does not: the agent drops the attribute when it syncs entries (`additionalAttributesFromProto` in `pkg/agent/client/util.go` copies only `DisableX509SvidPrefetch`). Three fetches in a row from one workload returned the same token and the same `jti`.
- So under `reject`, the first token request from a workload succeeds and every later one within the cached SVID lifetime gets `client assertion replayed`. The demo therefore sets `--svid-replay=allow-reuse-within-lifetime` in `deploy/docker-compose.yml` and keeps `-jwtSVIDIncludeJTI` in `deploy/register.sh`.

Residual risk in `allow-reuse-within-lifetime`: a JWT-SVID stolen from the agent, the workload or the wire mints access tokens at authz until it expires, up to `--max-svid-lifetime` (300s). Each allow audit line carries `svid_jti=<jti>`, so reuse of one SVID is visible in the audit trail, but it is not blocked. Switch back to `reject` once the SVID source yields a fresh `jti` per fetch.

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
| `notes.write` re-checks the token `exp` just before it stores | Tool error `access token expired`, nothing stored | A state change never happens after the token expired, even if the call started before |

`build_mcp` also refuses to start if any registered tool has no declared scope.

## Non-goals

- Not production software. No HA, no rotation of the authz signing key, no rate limits, plain HTTP inside the compose network.
- Not a replacement for an MCP gateway such as agentgateway. It shows the token flow a gateway could implement.
- No user delegation. The agent acts as itself (`client_credentials`). No token exchange or `act` claim chain yet.
- No X.509-SVID or WIT-SVID client authentication. JWT-SVID only.

## Known gaps

| Gap | Effect | Where |
|---|---|---|
| Docker socket in the SPIRE agent | Full Docker API access for the agent container. See [Docker socket exposure](#docker-socket-exposure). | `deploy/docker-compose.yml` |
| Label selectors | Anyone who can start a container with a registered label on the host gets that identity. Fits a single-host demo only. | `deploy/register.sh` |
| No access token `jti` tracking | A stolen access token is usable until it expires (5 min). | `mcp_server.py` |
| JWT-SVID reuse allowed in the demo | `allow-reuse-within-lifetime`: a stolen SVID mints tokens until it expires (max 300s). Needed because the SPIRE 1.15.3 agent re-serves cached SVIDs. | `deploy/docker-compose.yml` |
| JWT-SVID seen-set per process | `reject` mode only. Replicas or a restart forget seen `jti` values. | `ReplayCache` |
| Signing key in memory | Rotates only on restart. | `AuthzServer.signing_key` |
| Audit chain not anchored | Edits, deletions and reordering are detected, but a writer with file access can rebuild the chain after an edit. No signing or external anchor. | `audit.py` |
| Plain HTTP | No TLS inside the compose network. The demo agents run with `--allow-http --allow-private-network`. | `deploy/docker-compose.yml`, `deploy/demo.sh` |
| DNS rebinding | The URL check and the HTTP client resolve the host separately. A name that changes answer between the two lookups can still reach a private address. | `agent_client.UrlPolicy` |

## Docker socket exposure

The SPIRE agent uses the `docker` workload attestor. For each Workload API call it maps the caller PID to a container ID through `/proc`, then inspects that container over the Docker API to read its labels. Registration entries select on `docker:label:org.example.svid.workload:<name>`.

What this needs, and nothing more:

| Requirement | Why | Trade-off |
|---|---|---|
| `/var/run/docker.sock` mounted into `spire-agent` | Container inspect to read labels | The Docker API has no read-only mode. `:ro` on the mount only stops the socket file being replaced. A process that controls the agent container controls the Docker daemon, which is root on the host (or on the Docker Desktop VM). |
| Workloads join the agent PID namespace (`pid: service:spire-agent`) | The agent must see the caller PID in `/proc` | Workloads can see each other's processes. |
| Agent runs as root | Read the socket and `/proc` of workloads under other UIDs | Root inside the agent container. |

Not needed: `cgroup: host`. With cgroup v2 on Docker Desktop, the default container locator resolves container IDs without it (tested 2026-09-27).

Compared with the unix attestor used before: a process running under a registered UID no longer gets an identity. The identity now follows the container label. The cost is the Docker socket in the agent. Anyone who can already start containers on the host can still claim any label, so the host Docker daemon is the trust boundary.

Options to narrow the exposure, not implemented here:

- A socket proxy in front of the daemon that allows only `GET /containers/{id}/json`.
- `docker:image_config_digest` selectors next to the label, so a label alone is not enough.
- The Kubernetes (`k8s`) attestor on a real cluster, where the kubelet API replaces the Docker socket.
