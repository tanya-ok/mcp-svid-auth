# References

| Reference | Used for |
|---|---|
| [MCP authorization spec, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Protected Resource Metadata, resource indicators, audience validation, no token passthrough. Current revision as of 2026-09-26. |
| [draft-ietf-oauth-spiffe-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) | JWT-SVID as OAuth client assertion. Checked against -02: assertion type `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`, metadata value `spiffe_jwt`, issuer as sole SVID audience. |
| [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707) | `resource` parameter, audience-bound tokens |
| [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728) | `/.well-known/oauth-protected-resource` on the MCP server |
| [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068) | Access token format, `typ` `at+jwt` |
| [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) | `/.well-known/oauth-authorization-server` on authz |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) | `client_credentials`, error codes, scope syntax, no repeated parameters |
| [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) | `WWW-Authenticate` challenges, `insufficient_scope` |
| [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/) | Workload identity, SPIFFE ID, JWT-SVID, Workload API |
| [SPIRE](https://spiffe.io/docs/latest/spire-about/) | SPIFFE implementation used by the demo (1.15.3) |
| [py-spiffe](https://github.com/HewlettPackard/py-spiffe) | Python Workload API client (`spiffe` package) |
| [Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk) | MCP server and client (`mcp` 2.x) |
| [draft-sharif-agent-audit-trail](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/) | Audit hash chain construction (`prev_hash`, `parent_record_id`, JCS plus SHA-256). Checked against -05. |
| [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) | Canonical form hashed in the audit chain |
