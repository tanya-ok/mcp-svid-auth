# Production readiness

Status on 2026-11-26: the code paths below are implemented and covered by offline tests. The project is **not yet production-ready**: the remaining items in the second table need infrastructure, accounts or decisions from the operator, and no production deployment has been run.

Type legend: **Code** can be finished in this repository. **Infra** needs infrastructure the operator provides. **Decision** needs an owner decision or an external party.

## Closed in code

| Gap | Severity | Type | What exists now | Tests |
|---|---|---|---|---|
| Plain HTTP listeners | High | Code | `--tls-cert`, `--tls-key` on `mcp-svid-authz` and `mcp-svid-notes`; TLS 1.2 minimum, forward-secret TLS 1.2 suites; the public URL must be `https`; a plain listener off loopback is announced as `plaintext_listener` on stderr | `test_tls_listeners.py` |
| No client certificate check on listeners | Medium | Code | `--tls-client-ca` requires a client certificate signed by that CA (mTLS) | `test_tls_listeners.py` |
| Outbound trust limited to the system store | Medium | Code | `--ca-file` for the agent, stdio wrapper and MCP server (JWKS, upstream). Verification and hostname checks stay on | `test_tls_listeners.py`, `test_https_end_to_end.py` |
| DPoP not verified over HTTPS | Medium | Code | Discovery, JWT-SVID exchange and a DPoP-bound tool call over real TLS sockets; Bearer use and a foreign proof key refused | `test_https_end_to_end.py` |
| In-cluster names need the blanket dev flag | Medium | Code | `--allow-private-host HOST`: exact names may resolve to private addresses; https and all other checks stay on | `test_private_hosts.py` |
| No access token revocation | High | Code | `--revocation-file` on both servers: revoked `jti` and blocked SPIFFE IDs (subject, client or actor) are refused within `--revocation-poll-seconds` (default 5 s). Blocked IDs get no new token or exchange. Unreadable or invalid state fails closed and fails readiness | `test_revocation.py` |
| No access token `jti` tracking | Medium | Code | Opt-in `--max-calls-per-token N` counts tool calls per `jti` until expiry, bounded by `--token-use-cache-size`, refusing new tokens when full | `test_revocation.py` |
| Signing keys lost on restart | High | Code | `--signing-key-file` loads an owner-only P-256 key with a stable RFC 7638 `kid`; replicas sharing the file publish one key. `--verification-key-file` publishes previous public keys for rotation overlap | `test_signing_key_file.py` |
| Audit checkpoint replaceable by the writer | High | Code | Ed25519 signed checkpoints (`--signing-key`, `--checkpoint-public-key`); a rebuilt, edited or re-signed checkpoint fails | `test_audit_checkpoint_signing.py` |
| No health or readiness endpoints | Medium | Code | `/healthz` (liveness) and `/readyz`: authz not ready after a failed policy load or unreadable revocation state; MCP server not ready while the JWKS or revocation state is unavailable | `test_tls_listeners.py`, `test_revocation.py` |
| Source archive picked up local directories | Low | Code | Explicit sdist allowlist; `make package` validates contents, license and checksums | `make package` |

## Remaining before production deployment

| Gap | Severity | Type | Why it is open | Plan |
|---|---|---|---|---|
| Replay caches and rate budgets are per process | High | Infra | SVID `jti`, DPoP proof `jti`, token call counts and request budgets live in memory. Replicas or a restart do not share them, so a replay can succeed on another replica within the credential lifetime | Operator selects a shared store (for example a replicated key-value service). Then add a store interface with fail-closed semantics and run a multi-replica test. Until then run one authz replica, or accept the stated replay window |
| Workload admission is not constrained | High | Infra | Anyone allowed to start a pod with an authorized ServiceAccount obtains its SPIFFE ID | Add an admission policy that restricts which principals may use each authorized ServiceAccount, keep the copied-label denial, and prove one denied and one allowed launch in the lab. Needs a lab run by the owner |
| Lab still runs plain HTTP and `allow-reuse-within-lifetime` | High | Infra | TLS flags exist, but `deploy/` is unchanged and the lab was not run in this session. The SPIRE 1.15.3 agent re-serves cached SVIDs, so strict replay mode breaks normal fetches there | Issue lab certificates, switch `deploy/` to `--tls-cert` and `https` URLs, rerun all lab scenarios. Strict replay needs an upstream SPIRE fix or a non-caching SVID source |
| Signing key custody | High | Infra | `--signing-key-file` reads a local file. No KMS or HSM signer | Operator chooses a KMS or HSM. Add a signer interface for it; key never leaves the device |
| Checkpoint key custody and retained audit storage | High | Infra | Signing proves who made a checkpoint, not that logs reached durable storage. Logs are local files or stderr | Operator provides append-only log shipping and an offline checkpoint signing key with a capture schedule |
| Revocation file distribution | Medium | Infra | Each replica reads its own file path. Propagation is bounded only after the file changes on every replica | Mount one source (for example a config map or shared volume) and alert on `/readyz` failures |
| Grant policy has no review flow | Medium | Decision | `policy.yaml` is a local file reloaded on change. No versioning, approval or signature | Owner decides the change process (for example reviewed Git changes with a signed bundle). Code can then verify a signature before reload |
| Human user delegation | Medium | Decision | Token exchange accepts only tokens this server issued. No human identity provider token is accepted as `subject_token` | Requires a design decision on the identity provider and consent model |
| Release, package and supply-chain attestation | Medium | Decision | Local wheel and source archive build and validate. Nothing is published, signed or tagged. Version stays 0.1.0 | Owner decides the version, PyPI trusted publishing, artifact signing and SBOM. CI publishing changes need the owner's accounts |
| Metrics | Low | Code | Decisions are in JSON audit lines only. No metrics endpoint | Derive metrics from audit lines in the log pipeline, or add a bounded metrics endpoint |
| Agent client for single-call tokens | Low | Code | The bundled agent reuses one token for all its calls, so `--max-calls-per-token 1` refuses its second call | Fetch a new token per call when the server sets a call limit |
| Independent security review | High | Decision | All checks are self-run. No external review or penetration test | Owner commissions a review against this table and `docs/threat-model.md` |
| Deployment outside the local lab | High | Infra | Only the single-node local lab and offline tests were run | Owner deploys to a non-lab environment with TLS, a shared store and log shipping, then records the results here |

## Operating notes

| Task | Command or setting |
|---|---|
| Serve HTTPS | `--tls-cert server.pem --tls-key server.key`; add `--tls-client-ca clients-ca.pem` for mTLS |
| Trust a private CA outbound | `--ca-file ca.pem` |
| Revoke a token or block a workload | Add the `jti` to `revoked_jti` or the SPIFFE ID to `blocked_spiffe_ids` in the revocation file; it applies within `--revocation-poll-seconds` |
| Rotate a persistent signing key | Start with the new `--signing-key-file` and the old public key as `--verification-key-file`; remove the old key after the access token lifetime plus clock skew |
| Capture a signed checkpoint | `mcp-svid-audit-verify log.jsonl --write-checkpoint cp.json --signing-key checkpoint.key` |
| Verify against it | `mcp-svid-audit-verify log.jsonl --checkpoint cp.json --checkpoint-public-key checkpoint.pub` |
| Probes | Liveness `GET /healthz`, readiness `GET /readyz` |

Flag defaults and the revocation file schema are in the generated [configuration reference](configuration.md).
