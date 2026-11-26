# Production readiness

Status on 2026-11-26: **production deployment is not claimed**. The items in the first table are implemented and covered by offline tests, some against real local servers; the lab rows were also run in the local lab on 2026-11-26. The second table lists what is still open. No production deployment has been run.

Type legend: **Code** can be finished in this repository. **Lab** needs a run of the repository's Kubernetes lab. **Infra** needs infrastructure the operator provides. **Decision** needs an owner decision, account or external party.

## Closed

| Gap | Severity | What exists now | Tests |
|---|---|---|---|
| Plain HTTP listeners | High | `--tls-cert`, `--tls-key` on both servers; TLS 1.2 minimum; the public URL must be `https`; a plain listener off loopback prints `plaintext_listener` | `test_tls_listeners.py` |
| No client certificate check on listeners | Medium | `--tls-client-ca` requires a client certificate from that CA | `test_tls_listeners.py` |
| Outbound trust limited to the system store | Medium | `--ca-file` for the agent, stdio wrapper and MCP server, verification kept on | `test_tls_listeners.py`, `test_https_end_to_end.py` |
| DPoP not verified over HTTPS | Medium | Full DPoP flow over real TLS sockets | `test_https_end_to_end.py` |
| Workload admission is not constrained | High | Two ValidatingAdmissionPolicies in the lab namespaces: a ServiceAccount must be on the allow list, and only the lab operator and the Deployment and DaemonSet controllers may launch workloads with it. Job, CronJob and StatefulSet controllers cannot. Evaluated for cluster administrators too | `test_lab_admission.py`; lab scenarios 19-22 on 2026-11-26, including a run with the bindings removed that failed three of four checks. The cluster operator can still change the policy |
| Lab runs plain HTTP | High | Per-run CA and server certificates, `--tls-cert`, `--ca-file`, `NODE_EXTRA_CA_CERTS`; `--allow-http` and `--allow-private-network` removed from the lab, exact names use `--allow-private-host`. Verification is never disabled | `test_lab_tls.py`; all 22 lab scenarios over TLS on 2026-11-26; a plain HTTP request to the issuer failed and system trust alone refused its certificate |
| The lab VM name is fixed | Low | `LAB_VM` selects the Lima instance (default `security-lab`); `SVID_LAB_REPO_<NAME>` selects each repository checkout | `test_lab_parameters.py`; the lab ran in `svid-prod-lab` |
| In-cluster names need the blanket dev flag | Medium | `--allow-private-host` for exact names | `test_private_hosts.py` |
| Per-process replay caches and rate budgets | High | `--state-store-url`: Valkey or Redis shared by replicas, atomic, TLS and password file, refuses evicting stores, fails closed. In-process state stays the default | `test_shared_state.py` (two authz instances on one real server, outage, eviction policy, TLS); skipped without a server binary |
| Ephemeral signing key by default | High | Authz requires `--signing-key-file`, a transit signer, or the explicit `--dev-ephemeral-signing-key` | `test_transit_signer.py`, `test_signing_key_file.py` |
| Signing key lost on restart, no remote signer | High | Persistent key file with stable `kid` and published previous keys; OpenBao or Vault transit signer behind a `Signer` seam (`sign`, `public_jwks`), rotation keeps old tokens valid, outages fail closed | `test_signing_key_file.py`, `test_transit_signer.py` (real Vault 2.1.1 dev server; OpenBao not run); skipped without a binary |
| No access token revocation | High | `--revocation-file` on both servers: revoked `jti` and blocked SPIFFE IDs refused within `--revocation-poll-seconds` (0.5 to 300). Bounded no-follow reads, strict format, optional Ed25519 signature, fails closed | `test_revocation.py`, `test_revocation_files.py` |
| Issued token not findable for revocation | High | Authz allow records include `jti`, audience, expiry, actor and a DPoP key hash | `test_issuance_audit.py` |
| No access token `jti` tracking | Medium | `--max-calls-per-token` with a per-subject quota in memory or the shared store; `mcp-svid-agent --token-per-call` | `test_revocation*.py`, `test_shared_state.py`, `test_agent_token_per_call.py` |
| Audit checkpoint replaceable or stale | High | Ed25519 signed checkpoints with sequence, time and previous hash; `--min-sequence`, `--min-records`, `--max-age` high-water checks | `test_audit_checkpoint_signing.py`, `test_audit_freshness.py` |
| Audit chain with replicas and rotation | High | `replica_id` and `schema_version` in records, fsync per record, one writer per file (lock), bounded tail on resume, rotation verified with `--continues-from` | `test_audit_freshness.py` |
| Key and secret files read unsafely | Medium | One descriptor, no symlinks, regular file, size cap, owner-only private files | `test_signing_key_file.py`, `test_revocation_files.py`, `test_shared_state.py` |
| No health, readiness or metrics | Medium | `/healthz`, `/readyz` (policy, trust bundle, revocation, signer, store, JWKS with a `degraded` state), `--metrics` with bounded labels | `test_tls_listeners.py`, `test_degraded_readiness.py`, `test_metrics.py` |
| JWKS outage fails every token at cache expiry | Medium | Last good JWKS served for the token lifetime plus skew, readiness `degraded` | `test_degraded_readiness.py` |
| A replayed DPoP proof burns the SVID | Low | The proof is recorded before the SVID `jti` | `test_issuance_audit.py` |
| Source archive picked up local directories | Low | Explicit sdist allowlist | `make package` |

## Remaining before production deployment

| Gap | Severity | Type | Why it is open | Plan |
|---|---|---|---|---|
| Lab accepts SVID reuse | Medium | Lab | The main lab authz instance runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent returns one cached SVID with one `jti`; the strict instance denies the second use (scenario 13) | Needs an upstream SPIRE fix or a non-caching SVID source |
| Lab rerun is a single pass | Medium | Lab | One full pass on 2026-11-26 (22 of 22). The Headlamp viewer and the ZITADEL profile were not rerun, and the FHIR gateway and probe still pin a plain HTTP issuer in their own repository: the lab edits the staged copy | Make the issuer configurable in `hipaa-fhir-mcp`, then drop the staging edits; rerun the viewer and identity checks |
| Lab cluster operator is trusted | Medium | Lab | The admission policy names the k3s administrator and built-in controllers as allowed creators; whoever controls the cluster can edit or delete the policy. Audit checkpoints are stored beside the logs | Separate operator duties, protect the policy objects with RBAC and keep checkpoints on separately controlled storage (beads svid-e13 still covers the checkpoint half) |
| Cloud KMS signer | Medium | Decision | The transit signer is implemented and tested; a cloud KMS adapter needs an account | Implement `sign` and `public_jwks` for the chosen KMS and test against the account |
| Durable audit storage and checkpoint key custody | High | Infra | Records are fsynced locally and checkpoints are signed, but log shipping to append-only storage and an offline checkpoint signing job are operator systems | Operator provides log shipping, the checkpoint key host and a capture schedule; see [operations](operations.md) |
| Store and transit high availability | High | Infra | The code uses one store URL and one transit address. Replication, persistence and failover are the operator's | Operator runs a replicated Valkey with persistence and an HA OpenBao or Vault |
| Revocation file distribution | Medium | Infra | Each replica polls its own path | Operator mounts one source on every replica and alerts on readiness failures |
| Grant policy has no review flow | Medium | Decision | `policy.yaml` is a local file reloaded on change | Owner decides the change process; code can then verify a signed policy bundle |
| Human user delegation | Medium | Decision | Token exchange accepts only tokens this server issued | Needs an identity provider and consent design |
| Release, package and supply-chain attestation | Medium | Decision | Local wheel and source archive build and validate. Nothing is published, signed or tagged; version stays 0.1.0 | Owner decides the version, PyPI trusted publishing, artifact signing and SBOM |
| Independent security review | High | Decision | All checks are self-run | Owner commissions a review against this table and the threat model |
| Deployment outside the local lab | High | Infra | Only the local lab and offline tests were run | Owner deploys with TLS, a shared store, a signer and log shipping, then records the result |
| CI does not run the transit tests | Low | Code | CI installs Valkey or Redis but no OpenBao or Vault binary, so those tests skip there | Add a pinned OpenBao binary to CI |

Operating instructions are in [operations](operations.md); flag defaults in the generated [configuration reference](configuration.md).
