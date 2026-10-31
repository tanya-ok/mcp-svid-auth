# Compatibility and integration boundaries

This is a reproducible reference flow for JWT-SVID client authentication and MCP resource protection. It is a proof of concept, with the following deliberately bounded support.

## Profiles

| Surface | Supported here | Boundary |
|---|---|---|
| [MCP authorization, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Protected Resource Metadata, RFC 8707 resource parameter, audience and tool-scope checks, no token passthrough | Machine credentials only; no user authorization flow or delegation |
| [OAuth SPIFFE Client Authentication, draft -02](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) | JWT-SVID assertion type `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`, method `spiffe_jwt`, issuer-only SVID audience, trust-domain validation | Draft, not an RFC; no X.509-SVID, WIT-SVID, URL client identifiers or federation discovery |
| Draft -02 section 6.2.1 | The authorization server itself is a workload and uses the local Workload API to fetch trusted JWT bundles | The draft does not recommend this alternative for general interoperability. Trust is configured out of band for one `example.org` domain; this is a deliberate local-demo limitation, not full draft conformity |
| [MCP Client Credentials extension, draft](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/draft/oauth-client-credentials.mdx) | Uses the `client_credentials` grant | The extension's generic `private_key_jwt` / client-secret profile is separate. A JWT-SVID has a distinct assertion type and trust model. This server does not advertise generic methods it does not implement |
| RFC 9068 access token | ES256, `typ: at+jwt`, required issuer, audience, expiry and issue time; one resource audience | Locally verified bearer tokens, no introspection or immediate revocation |

Do not rename `spiffe_jwt` to `private_key_jwt` to make an SDK accept it. The latter authenticates a registered client key; this flow validates a workload assertion against a separately trusted SPIFFE bundle.

## Independently exercised client

`examples/typescript-client/client.mjs` uses the public TypeScript MCP SDK **1.32.2**. Its explicit JWT-SVID adapter performs discovery and the token exchange; the SDK then negotiates MCP, lists scoped tools, calls `notes.search` and verifies that `notes.write` receives 403. The local harness creates runtime test keys, sends the assertion through stdin and keeps credentials out of output.

```sh
cd examples/typescript-client
npm ci --ignore-scripts --no-audit --no-fund
cd ../..
make interop
```

The test proves interoperability with this adapter, not built-in SPIFFE support in generic OAuth SDKs. The harness uses `LocalSvidIssuer`, not SPIRE. `make demo` independently exercises the real Workload API source. The example is a local compatibility fixture, not a hardened general network client; use the Python client's address-bound transport when evaluating its URL security controls.

The Python client uses `mcp==2.2.0` and `httpx2==2.13.1` from `uv.lock`; the live demo pins SPIRE server and agent **1.15.3** by digest. Consult the lock files for all transitive versions. Supported Python minimum is 3.12; the publication validation ran on Python 3.13, not every supported interpreter.

## Where a gateway fits

[agentgateway documents native SPIFFE integration](https://agentgateway.dev/docs/kubernetes/latest/reference/api/). This project adds a small, inspectable OAuth exchange and failure demonstrations; it does not replace a gateway.

| Owner | Responsibility |
|---|---|
| SPIRE / platform operator | Attest workloads, issue short-lived SVIDs and protect the Workload API socket |
| Authorization server | Establish bundle trust out of band; map workload, resource and requested scopes to a grant |
| MCP resource server or gateway | Validate its own audience, issuer, token type and expiry; enforce every tool's scope |
| Upstream caller | Obtain its own upstream credential; never forward a received access token |
| Audit operator | Preserve a terminal checkpoint in storage the log writer cannot change |

A real gateway integration must verify which component accepts JWT-SVID assertions and which component verifies the resulting access token. Gateway SPIFFE transport support alone does not establish compatibility with this OAuth profile. No deployed agentgateway integration is claimed here.

## CNCF runtime compatibility

The macOS integration demo uses Lima, k3s Kubernetes and containerd. SPIRE's
Kubernetes attestor verifies namespace and ServiceAccount identity without a
container runtime API socket. The old Podman backend was retired on 2026-10-13;
its earlier validation is historical evidence. See [Runtime](runtime.md).
