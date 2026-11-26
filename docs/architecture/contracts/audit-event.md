# Audit event contract

Status: schema version `2`, written by `mcp-svid-authz` and `mcp-svid-notes` from 2026-11-26. Readers must also accept version 1 records (the same fields without `schema_version` and `replica_id`). Source: `src/mcp_svid_auth/audit.py`. Other components that want to share a verifier or pipeline, such as `mcp-spiffe-bridge`, can align to this page.

## Record

One JSON object per line, UTF-8, `\n` terminated. One chain per file and one writer per file.

| Field | Type | Rule |
|---|---|---|
| `schema_version` | string | `"2"`. Absent in version 1 records |
| `record_id` | string | Random UUIDv4, unique within the file |
| `parent_record_id` | string or null | `record_id` of the previous record; null only for the first record of a chain |
| `prev_hash` | string or null | Lowercase hex SHA-256 of the previous record in RFC 8785 (JCS) form; null with `parent_record_id` |
| `timestamp` | string | ISO 8601 with offset, millisecond precision, UTC; never earlier than the previous record |
| `component` | string | `authz` or `mcp_server:<name>` |
| `replica_id` | string | Writer instance name (`--audit-replica-id`, default `HOSTNAME`). Absent in version 1 |
| `spiffe_id` | string or null | Verified SPIFFE ID, a hashed unverified identifier, or null |
| `tool` | string or null | Tool name for tool decisions, comma separated for a batch; never an unknown tool name |
| `decision` | string | `allow`, `deny` or `policy_reload` |
| `reason` | string | Fixed vocabulary below, never exception text, tokens or keys |

Exactly these fields. A record with any other field set is invalid.

## Reason vocabulary

A reason starts with a fixed code. Some codes carry a bounded suffix after `: ` or a space.

| Component | Decision | Reason prefix | Suffix |
|---|---|---|---|
| authz | allow | `issued for <aud> scope=<scopes> jti=<jti> exp=<unix> cnf_jkt_sha256=<16 hex or none>` | optional ` act=<SPIFFE ID>`, then ` svid_jti_sha256=<16 hex or none>` |
| authz | deny | an OAuth error code: `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `invalid_target`, `unauthorized_client`, `unsupported_grant_type`, `temporarily_unavailable`, `invalid_dpop_proof` | `: <fixed description>` and an optional ` (<detail>)` with an exception class name or a hash |
| authz | policy_reload | `loaded sha256=<16 hex> clients=<n>` or `failed: <exception class>; denying all token requests` | none |
| mcp_server | allow | `scope <scope>` | none |
| mcp_server | deny | `missing_token`, `invalid_token: <exception class>`, `invalid_token_size_or_encoding`, `jwks_unavailable`, `jwks_invalid`, `verification_budget_exceeded`, `revoked_token`, `blocked_spiffe_id`, `revocation_unavailable`, `insufficient_scope: needs <scope>`, `unknown tool`, `unparseable request body`, `request body too large`, `token_expired_during_call`, `token_call_limit_reached`, `token_use_store_full`, `token_use_store_unavailable`, `token_use_subject_limit_reached`, `dpop_scheme_required`, `invalid_dpop_proof: <code>` | as shown |

The metrics endpoint maps these reasons to the bounded labels in `src/mcp_svid_auth/metrics.py` (`classify`).

## Identifier rules

| Value | Written as |
|---|---|
| Verified SPIFFE ID (allow, and denials after verification) | The SPIFFE ID as is |
| Subject before verification | `unverified:sha256:` + first 16 hex characters of SHA-256 of the claimed `sub` |
| JWT-SVID `jti` | `svid_jti_sha256=` or `jti_sha256=` + 16 hex characters of SHA-256 |
| DPoP key thumbprint | `cnf_jkt_sha256=` + 16 hex characters of SHA-256 of the RFC 7638 thumbprint |
| Issued access token `jti` | In clear, so it can be revoked. It is an identifier, not a credential |
| Access tokens, assertions, proofs, keys, exception messages | Never written |

## Chain, files and checkpoints

- Each replica writes its own file. A second writer on the same file is refused through an exclusive lock on `<file>.lock`.
- Each record is fsynced before the decision completes.
- Rotation: rename the file, let the writer continue in a new file whose first record links to the last record of the old file, and verify the new file with `--continues-from <old checkpoint>`. See [audit integrity](../../audit.md).
- Checkpoint versions: 1 (unsigned terminal state) and 2 (Ed25519 signed, with `sequence`, `created_at` and `previous`).

## Compatibility

Adding a field, a decision value or a reason prefix is a schema version change. Readers reject unknown versions. Within a schema version the field set and the meaning of each prefix do not change.
