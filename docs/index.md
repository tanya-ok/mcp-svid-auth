# mcp-svid-auth

Proof of concept. An AI agent authenticates to MCP servers with its SPIFFE workload identity instead of a static API key.

!!! warning "Proof of concept"
    Not production software. Do not deploy it to protect real data. See [Security model](security.md).

## Problem

MCP client configs often hold long-lived static keys:

```json
{ "env": { "NOTES_API_KEY": "sk-live-..." } }
```

| Issue with static keys | Effect |
|---|---|
| Long-lived | A leaked key works until someone rotates it by hand |
| Not bound to a workload | Any process that reads the file can use it |
| Not bound to a server | One key often opens several servers |
| No per-caller identity | Audit logs cannot say which agent acted |

## What this POC proves

| Claim | Where |
|---|---|
| An agent gets a short-lived access token using only its JWT-SVID | `authz.py`, draft-ietf-oauth-spiffe-client-auth |
| Tokens are bound to one MCP server via the RFC 8707 `resource` parameter | `authz.py`, `policy.py` |
| A token issued for server A is rejected by server B | `mcp_server.py`, `test_token_for_a_is_rejected_by_b` |
| Scopes are enforced per tool, with a 403 `insufficient_scope` challenge. Tools without a declared scope are denied. | `ToolScopeGuard`, `build_mcp` |
| Every decision is written as one JSON audit line with the SPIFFE ID | `audit.py` |
| The MCP server never forwards the incoming token | `mcp_server.py` makes no outbound call with it |
| A stdio MCP server can start with a refreshed short-lived token instead of a static key | `stdio_wrapper.py` |

## Standards targeted

- [MCP authorization spec, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization): Protected Resource Metadata (RFC 9728), resource indicators (RFC 8707), audience validation, no token passthrough.
- [draft-ietf-oauth-spiffe-client-auth-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/): assertion type `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`, advertised as `spiffe_jwt` in `token_endpoint_auth_methods_supported`.
- RFC 9068 JWT profile for the access tokens (`typ` `at+jwt`).

Full list: [References](references.md).

## Where to go next

| Page | Content |
|---|---|
| [Quickstart](quickstart.md) | Install, offline checks, the SPIRE demo |
| [Architecture](architecture.md) | Components and the token flow |
| [Demo scenarios](demo.md) | The ten scenarios and their results |
| [Security model](security.md) | Threat model, checks, non-goals, known gaps |
| [stdio wrapper](stdio-wrapper.md) | Short-lived tokens for local stdio MCP servers |
| [Configuration](configuration.md) | CLI flags and the policy file |

## License

Apache-2.0. Copyright 2026 Tanya Babitskaya. See [LICENSE](https://github.com/tanya-ok/mcp-svid-auth/blob/main/LICENSE) and [NOTICE](https://github.com/tanya-ok/mcp-svid-auth/blob/main/NOTICE).
