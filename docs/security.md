# Security model

!!! warning
    This is a proof of concept. Do not deploy it to protect real data. Report vulnerabilities privately through GitHub private vulnerability reporting, not in a public issue.

## Threat model

| Threat | Mitigation here | Gap |
|---|---|---|
| Static key leak | No static keys. SVID and access token both live 5 min. | A stolen access token works until expiry. |
| Token replay to another server | `aud` bound to one resource. Each server checks `aud` equals its own URI. | None within one issuer. |
| JWT-SVID replay to authz | SVID `aud` must be the issuer only. 5 min TTL. | No `jti` tracking. A stolen SVID can mint tokens for its whole lifetime. |
| Workload impersonation | SPIRE docker attestor. Identity is bound to a container label, not a UID. | Anyone who can start a container with a registered label on that host gets that identity. |
| Over-broad access | Allowlist per SPIFFE ID, resource and scope. Per-tool scope check. | Policy is a local file. No versioning or review flow. |
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
| `sub`, `aud`, `exp`, `iat` present; `exp` not past (30s leeway) | 401 `invalid_client` | The SVID is current |
| `aud` is the issuer and nothing else | 401 `invalid_client` | The SVID was minted for this authorization server only |
| `exp - iat` at most `--max-svid-lifetime` (300s) | 401 `invalid_client` | Long-lived SVIDs cannot be used as credentials |
| `client_id`, if sent, equals `sub` | 401 `invalid_client` | No identity mismatch between parameters |
| SPIFFE ID in policy | 400 `unauthorized_client` | Only allowlisted workloads get tokens |
| Resource allowed for that SPIFFE ID | 400 `invalid_target` | Per-server allowlist |
| `scope` present, well formed, subset of grant | 400 `invalid_scope` | Least privilege, no implicit default scope |
| Trust bundle fetch fails | 503 `temporarily_unavailable` | Fails closed without leaking details |

Error descriptions returned to the client are fixed strings. Exception details go only to the audit log.

### MCP server (`mcp_server.py`)

| Check | Failure | Proves |
|---|---|---|
| Bearer token present | 401 with `resource_metadata` challenge | Unauthenticated calls are refused and told where to authenticate |
| Header `typ` is `at+jwt` | 401 `invalid_token` | Only RFC 9068 access tokens, not SVIDs or ID tokens |
| `kid` found in the authz JWKS | 401 `invalid_token` | Token signed by the configured authorization server |
| `alg` ES256, signature valid | 401 `invalid_token` | No algorithm confusion |
| `iss` equals configured issuer | 401 `invalid_token` | No tokens from another issuer |
| `aud` equals own resource URI | 401 `invalid_token` | A token for another server is useless here |
| `iss`, `sub`, `aud`, `exp`, `iat`, `scope` present, `exp` not past | 401 `invalid_token` | Complete, current token |
| Body at most 1 MiB | 413 `invalid_request` | Bounded request parsing |
| Body is valid JSON-RPC, each `tools/call` names a tool | 400 `invalid_request` | The scope guard cannot be bypassed with a malformed body |
| Tool has a declared scope | 400 `invalid_request` | Deny by default for unknown tools |
| Granted scopes include the tool scope | 403 `insufficient_scope` with `WWW-Authenticate` | Per-tool least privilege |

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
| No `jti` replay tracking | A stolen JWT-SVID or access token is usable until it expires (5 min). | `authz.py`, `mcp_server.py` |
| No JWKS refetch on unknown `kid` | The MCP server caches the authz JWKS for 60s with a blocking fetch. A restarted authz is unknown for up to 60s. | `JwksFetcher` |
| No client-side issuer allowlist | The agent trusts the authorization server named in Protected Resource Metadata. A malicious server could point it at another issuer; the SVID `aud` then names that issuer. | `agent_client.discover` |
| No `tools/list` filtering | Every caller sees all tools. The scope check applies at `tools/call`. | `ToolScopeGuard` |
| Signing key in memory | Rotates only on restart. | `AuthzServer.signing_key` |
| Plain HTTP | No TLS inside the compose network. | `deploy/docker-compose.yml` |

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
