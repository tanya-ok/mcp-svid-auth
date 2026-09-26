# Configuration reference

All commands are installed by `uv sync` as console scripts. `--socket` defaults to the `SPIFFE_ENDPOINT_SOCKET` environment variable.

## `mcp-svid-authz`

Token endpoint.

| Flag | Default | Meaning |
|---|---|---|
| `--issuer` | required | Public base URL. Used as `iss` and as the required SVID `aud`. Trailing slash removed. |
| `--policy` | required | Path to the policy YAML file |
| `--host` | `127.0.0.1` | Listen address |
| `--port` | `8100` | Listen port |
| `--static-jwks` | none | Test mode: JWT-SVID bundle as a JWKS file instead of the Workload API |
| `--socket` | `SPIFFE_ENDPOINT_SOCKET` | Workload API socket for JWT bundles |
| `--audit-log` | stderr | Audit log file (JSON lines, appended) |
| `--max-svid-lifetime` | `300` | Reject JWT-SVIDs whose `exp - iat` exceeds this many seconds |

Fixed values: access token TTL 300s, SVID clock leeway 30s, trust bundle cache 30s.

## `mcp-svid-notes`

Demo MCP server with `notes.search` (`notes:read`) and `notes.write` (`notes:write`).

| Flag | Default | Meaning |
|---|---|---|
| `--name` | `notes` | Server name, also used in the audit `component` (`mcp_server:<name>`) |
| `--resource` | required | Canonical URI, e.g. `http://host:8101/mcp`. Must equal the token `aud`. |
| `--issuer` | required | Authorization server issuer URL |
| `--jwks-uri` | `<issuer>/jwks.json` | JWKS location |
| `--host` | `127.0.0.1` | Listen address |
| `--port` | `8101` | Listen port |
| `--audit-log` | stderr | Audit log file |

Fixed values: JWKS cache 60s, request body limit 1 MiB, access token algorithm ES256.

## `mcp-svid-agent`

Demo agent. Calls `notes.search` then `notes.write`.

| Flag | Default | Meaning |
|---|---|---|
| `--resource` | required | MCP server canonical URI |
| `--scope` | required | Space separated scopes, e.g. `'notes:read notes:write'` |
| `--spiffe-id` | none | Sent as `client_id` |
| `--socket` | `SPIFFE_ENDPOINT_SOCKET` | Workload API socket |
| `--steal-token` | none | Demo: send the token issued for `--resource` to this other resource |

Exit code 2 and a `token_denied` event when the token request fails.

## `mcp-svid-stdio`

See [stdio wrapper](stdio-wrapper.md).

| Flag | Default | Meaning |
|---|---|---|
| `--resource` | required | Upstream resource the child calls |
| `--scope` | required | Space separated scopes |
| `--socket` | `SPIFFE_ENDPOINT_SOCKET` | Workload API socket |
| `--refresh-margin` | `60` | Seconds before expiry to refresh |
| `--export-token-env` | off | Also set `MCP_ACCESS_TOKEN` (weaker) |
| `-- command [args...]` | required | Child command |

## Policy file

Allowlist of which SPIFFE IDs may get access tokens for which MCP servers, with which scopes. Anything not listed is denied.

```yaml
trust_domain: example.org
clients:
  - spiffe_id: spiffe://example.org/agent/research
    resources:
      http://notes-a:8101/mcp: [notes:read, notes:write]
      http://notes-b:8102/mcp: [notes:read]
```

| Key | Type | Meaning |
|---|---|---|
| `trust_domain` | string, required | Only SVIDs from this trust domain are accepted |
| `clients` | list | One entry per SPIFFE ID |
| `clients[].spiffe_id` | string | Exact SPIFFE ID (SVID `sub`) |
| `clients[].resources` | map | Resource URI to list of allowed scopes. Trailing slashes are ignored when matching. |

Decision order:

| Condition | Error |
|---|---|
| SPIFFE ID not listed | `unauthorized_client` |
| Resource not listed for that ID | `invalid_target` |
| Requested scopes not a subset of the listed scopes | `invalid_scope` |

The token carries exactly the requested scopes, not the full grant.
