# Operations

How to run `mcp-svid-authz` and `mcp-svid-notes` with the production features. Flag defaults are in the generated [configuration reference](configuration.md). Remaining gaps are in [production readiness](production-readiness.md).

All key, password and token files are read once through one descriptor without following symlinks. Private files (keys, passwords, tokens) must be regular files owned by the service user with mode `0600` or stricter; anything else stops startup.

## TLS

| Task | Setting |
|---|---|
| Serve HTTPS | `--tls-cert server.pem --tls-key server.key`; `--issuer` or `--resource` must then be `https` |
| Require client certificates | add `--tls-client-ca clients-ca.pem` |
| Trust a private CA for outbound calls | `--ca-file ca.pem` on the agent, stdio wrapper and MCP server (JWKS and upstream) |
| In-cluster service names | `--allow-private-host notes-b.example.org` per name; keep `--allow-private-network` for development only |

TLS 1.2 is the minimum. A listener without TLS that is not on loopback prints a `plaintext_listener` event on stderr.

## Access token signing key

`mcp-svid-authz` needs exactly one key source.

| Source | Flags | Use |
|---|---|---|
| Key file | `--signing-key-file key.pem --signing-rotation-seconds 0` | P-256 key in a mounted secret. Every replica uses the same file and publishes the same `kid` (RFC 7638 thumbprint) |
| Transit signer | `--transit-address https://bao.example.org:8200 --transit-key access-tokens --transit-token-file token --signing-rotation-seconds 0` | OpenBao or Vault transit key of type `ecdsa-p256`; the private key stays in the engine. Optional `--transit-mount`, `--transit-ca-file`, `--transit-namespace` |
| Development | `--dev-ephemeral-signing-key` | In-memory key per process with planned rotation. Replicas disagree and a restart invalidates tokens. Lab and tests only |

Key file rotation: start the replicas with the new `--signing-key-file` and the old public key as `--verification-key-file`. Remove the old public key after the access token lifetime (300 s) plus 30 s skew.

Transit rotation: rotate the transit key (`POST /v1/transit/keys/<name>/rotate`). Replicas pick up the new version within 60 s and publish the four newest versions, so tokens signed by the previous version stay verifiable. Keep `min_decryption_version` low enough that published versions remain readable.

Minimum transit policy for the authz token:

```hcl
path "transit/sign/access-tokens/sha2-256" { capabilities = ["update"] }
path "transit/keys/access-tokens" { capabilities = ["read"] }
```

A cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault) needs an adapter with the same two methods, `sign(claims)` and `public_jwks()`, in `src/mcp_svid_auth/signers.py`, and an account to test it against. None is included.

If the transit engine is unreachable, token requests get 503 `temporarily_unavailable`, `/jwks.json` returns 503 and `/readyz` reports `signer_unavailable`. A token request that fails at signing has already consumed its JWT-SVID `jti`; the client fetches a new SVID.

## Shared replay and rate-limit store

Without a store, SVID `jti` values, DPoP proof `jti` values, per-token call counts and authz request budgets are per process. With several replicas, give all of them the same store:

```sh
uv sync --locked --extra valkey   # installs the redis-py client
mcp-svid-authz ... --state-store-url rediss://valkey.example.org:6380/0 \
  --state-store-password-file /run/secrets/valkey-password \
  --state-store-ca-file /etc/ssl/valkey-ca.pem --state-store-prefix prod-authz
```

| Rule | Reason |
|---|---|
| `maxmemory-policy noeviction` | An evicted replay entry would let a credential pass twice. Startup refuses any other policy it can read; when `CONFIG GET` is not allowed it prints `store_policy_unknown` and continues, so confirm the policy yourself |
| Same `--state-store-prefix` for every replica of one deployment | Keys are `<prefix>:<namespace>:<sha256>`; different prefixes do not share state |
| Password in a file, never in the URL | URLs with user information are refused |
| `rediss://` with `--state-store-ca-file`, optional `--state-store-cert` and `--state-store-key` | Certificate and hostname checks stay on |
| Persistence (AOF) and a replica | A store restart without persistence forgets replay entries; the replay window is then up to the SVID lifetime (300 s) |

Any store error denies: token requests get 503, DPoP proofs and token call counts are refused, budgets refuse. `/readyz` reports `state_store_unavailable`. The MCP server verification budget stays per process on purpose: it bounds CPU per replica.

## Revocation file

Both servers accept `--revocation-file`. Format (YAML or JSON, both keys required, empty lists allowed):

```yaml
revoked_jti: [4f0c...]
blocked_spiffe_ids: ["spiffe://example.org/agent/compromised"]
```

Find a token's `jti` in the authz allow record (`jti=` in `reason`).

| Rule | Detail |
|---|---|
| Atomic replace | Write a temporary file in the same directory, then `rename` it over the old one. An empty, partial or invalid file fails closed (every request denied, readiness fails) |
| Propagation bound | `--revocation-poll-seconds`, 0.5 to 300, default 5 |
| Distribution | Mount one source on every replica, for example a ConfigMap or a shared volume. Each replica applies a change within its poll interval after the file changes on that replica |
| Signature (optional) | `--revocation-public-key revocation.pub`. Then `<file>.sig` must hold the base64 Ed25519 signature of the exact file bytes, for example `openssl pkeyutl -sign -rawin -inkey revocation.key -in revocations.yaml \| base64`. Replace the file and signature together; a mismatch fails closed until both match |

## Audit logs and checkpoints

| Task | Setting or command |
|---|---|
| One file per replica | `--audit-log /var/log/mcp-svid/authz-0.jsonl --audit-replica-id authz-0`. A second writer on one file is refused |
| Ship logs | Ship each file, or stderr when `--audit-log` is not set, to append-only storage you operate. The application does not provide durable storage |
| Rotate | Rename the file; the writer continues in a new file linked to the old one. Then checkpoint the old file |
| Sign a checkpoint | `mcp-svid-audit-verify old.jsonl --write-checkpoint old.cp --signing-key checkpoint.key --previous-checkpoint last.cp` |
| Verify | `mcp-svid-audit-verify old.jsonl --checkpoint old.cp --checkpoint-public-key checkpoint.pub --min-sequence <n>` |
| Verify the continuing file | `mcp-svid-audit-verify current.jsonl --continues-from old.cp --checkpoint-public-key checkpoint.pub` |

Keep the checkpoint signing key away from the hosts that write logs, for example on an offline host or in a separate signing job. Record the latest sequence number and record count outside the log host and pass them as `--min-sequence` or `--min-records`, so an older genuine checkpoint presented with a truncated log is detected. `--max-age SECONDS` refuses old checkpoints. The audit record format is the [audit event contract](architecture/contracts/audit-event.md).

## Probes and metrics

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Process is serving |
| `GET /readyz` on authz | 503 with `policy_unavailable`, `revocation_unavailable`, `trust_bundle_unavailable`, `signer_unavailable` or `state_store_unavailable` |
| `GET /readyz` on the MCP server | 503 when the JWKS, revocation state or store is unavailable; 200 with `degraded` while it serves the last good JWKS during an issuer outage (at most 330 s after the cache expired) |
| `GET /metrics` with `--metrics` | `mcp_svid_decisions_total{component,decision,reason}` and `mcp_svid_dependency_up{dependency}` |

Alert on `mcp_svid_dependency_up == 0`, on readiness `degraded`, and on rising `reason="replay"`, `"rate_limited"`, `"revoked"`, `"store_unavailable"` or `"jwks_unavailable"`. Metrics carry no identifiers; still expose `/metrics` only to the monitoring network.
