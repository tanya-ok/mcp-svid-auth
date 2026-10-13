# Local publication validation

Updated on **2026-10-13**. The repository is public on GitHub and its
documentation is built for GitHub Pages. No release, package upload or remote
service deployment was performed. This is a checked proof of concept and makes
no production-readiness claim.

## Current state on 2026-10-13

- `make check` passes with 537 tests, lint, formatting, strict types and generated
  configuration checks on Python 3.12 and 3.13.
- The lab runs on k3s Kubernetes with containerd in a dedicated Lima VM. The
  Podman runtime path, its compose services and `test_podman_backend.py` were
  retired on 2026-10-13.
- `make interop` passes with TypeScript MCP SDK 1.32.1 on Node 26.
- The full lab needs `mcp-spiffe-bridge`, which is not yet published. The
  single-repository [quickstart](quickstart.md) path does not.

The sections below are dated records. Where they mention test counts, Podman,
compose services or SDK 1.30.1, they describe the state on their date.

## Package revalidation on 2026-10-07

Historical, superseded by [Current state on 2026-10-13](#current-state-on-2026-10-13).

The final local gate passed 535 tests, lint, format, strict types and generated
configuration checks. Packaging commit `4f69e2a` excludes local tracker/state
and generated site directories from the source distribution. Negative archive
checks refuse private paths; no authentication behavior changed in this fix.

A clean committed checkout installed its locked dependencies and built the wheel
through the source distribution. Archive contents, Apache-2.0 metadata, license,
runtime module, private-identifier scan and checksums passed. All five installed
console scripts started from a separate Python 3.12.12 environment. The installed
audit verifier accepted a complete synthetic chain and refused tail deletion
against its checkpoint. This is packaging and verifier evidence, not a fresh
SPIRE integration run. The [portfolio readiness page](portfolio-publication-readiness.md)
records current demo evidence and publication scope.

## Shared-lab increment on 2026-10-06

Historical, superseded by [Current state on 2026-10-13](#current-state-on-2026-10-13).

- Fresh recovery-cycle rebuild: eighteen scenarios passed between 15:25 and
  15:31 UTC on 2026-10-06; a prior enabled main identity repeat passed eighteen
  at 15:02 UTC.
- Main synthetic identity: eleven real WebAuthn/OIDC checks, four closed Google
  setup checks with fake inputs, five protected desktop views, mobile layout
  and browser logout passed. Actual Google and physical enrollment remain unverified.
- Initial and final scoped teardown, viewer restart/idempotence and
  identity-backend-loss recovery passed while preserving CISO's namespace UID
  and the shared VM. Final cleanup removed all three owned namespaces, private
  identity records and five viewer listeners.
- Sixty-four five-second samples across that cycle including native startup
  observed at most 1858.1 MiB guest use, with no measurement errors. Host memory
  and the optional host model are outside that measurement.
- The final root offline gate passed 467 tests, lint, formatting, strict types,
  generated configuration, strict docs and source/history secret scans.
- Real Google OAuth configuration, constrained HTTPS egress and physical
  passkey enrollment remain operator gates. User-to-agent delegation and
  record authorization remain subsequent implementation work.

For current evidence and boundaries, see [shared lab](kubernetes-lab.md),
[passwordless identity](passwordless-identity.md) and
[portfolio development plan](portfolio-development-plan.md).

## Earlier recorded checks on 2026-10-05

Historical, superseded by [Current state on 2026-10-13](#current-state-on-2026-10-13).
The Podman 5.4.2 runtime and compose services in this record are retired.

| Check | Result |
|---|---|
| `make check` | Pass: 236 tests, lint, format, strict mypy and generated configuration check; malformed Unicode subjects and identifiers are denied and audited without a server error |
| Independent TypeScript SDK 1.30.1 | Pass: discovery, JWT-SVID adapter, initialization, scoped listing, allowed read and 403 write denial |
| Real SPIRE 1.15.3 / CNCF Lima 2.2.1 / Podman 5.4.2 | Pass: all fourteen real Workload API scenario assertions, including cached reuse, strict rejection, renewal, expiry and audit tail-deletion detection |
| CNCF runtime lifecycle | Pass: existing VM restart, fresh stack, all fourteen assertions, ownership-scoped resource teardown and VM stop. 2 CPUs, 2 GiB guest memory, 8 GiB sparse disk capacity; no automatic startup |
| Local wheel and source archive | Pass: contents, runtime module, lock file, license and checksums; five console scripts start from an isolated wheel installation |
| Secrets scan | `gitleaks detect`: 65 existing commits scanned, no leaks. Separate non-ignored working tree snapshot: no leaks |
| Privacy | Working tree, full history and local denylist checks passed |
| Documentation | Pass: strict clean Zensical build, no issues found |
| Teardown | Pass: demo containers, network and both runtime volumes removed. Lima reports `Stopped`; reusable VM disk and images remain |

The previous Docker-based attempt was blocked by filesystem I/O errors after host disk exhaustion. The final validation uses the CNCF runtime instead. Podman setup and dependency-order cleanup issues were fixed and the complete lifecycle rerun passed. Other projects' Docker containers were not migrated or removed. See [Runtime](runtime.md).

## Security invariant review

| Invariant | Change and evidence |
|---|---|
| Deny by default | Unknown tool names no longer echo untrusted input into audit. Existing malformed/oversized-body and undeclared-tool tests retained; `test_unverified_subject_and_unknown_tool_cannot_echo_a_token` adds privacy evidence |
| One resource audience | Explicitly reject a validly signed token carrying additional audiences; `test_token_with_additional_audience_is_rejected` |
| No token passthrough | Default outbound transport now binds addresses. Existing `test_no_passthrough.py` still captures all outgoing credentials; real scenario 8 verifies downstream workload identity |
| Strict token checks | ES256 and `at+jwt`, required claims and SVID lifetime checks retained. Strict-mode live scenario 13 proves second-use refusal; scenario 12 proves renewal and expired-assertion refusal |
| No secrets in output | Removed exception text; hash unverified subjects and SVID IDs, including malformed Unicode input; redact URL userinfo and query; sanitize remote challenges. Fixed-error, reflection and privacy tests cover these paths |
| Fail closed | Shared client transport changes apply to stdio acquisition. Existing refresh, expiry, file deletion, child termination and cleanup tests retained |
| Runtime keys | SPIRE server state uses a UID-1000 memory-backed volume; no key fixtures added. TLS test and independent-client harness generate keys at runtime; source/wheel contents and privacy/secret checks verify publication inputs; `test_kubernetes_backend.py` covers unmounted workload tokens, loopback-pinned cluster access and teardown restricted to owned namespaces. The Podman socket path and its tests were retired on 2026-10-13 |

Audit checkpoints additionally detect terminal edits, suffix deletion and complete chain rewrite against a separately trusted baseline. A colocated checkpoint remains a demonstration, not independent archival trust.

## Deliverables and reproduction

- `make check`: local code and invariant tests.
- `make runtime-up`, `make demo`, `make down`, `make runtime-stop`: real Workload API, expected denials, lifetime behavior, clean teardown and resource release. Requires the unpublished `mcp-spiffe-bridge` sibling checkout.
- `make interop`: separately implemented JWT-SVID adapter using the public TypeScript SDK.
- `make package`: local `dist/mcp_svid_auth-0.1.0-py3-none-any.whl`, source archive and `SHA256SUMS`.
- `uv run --locked --only-group docs zensical build --strict --clean`: local documentation site.

The console scripts are also smoke-tested from a locally installed wheel. Generated reports, bundles, runtime credentials, private denylist and dependency directories stay outside commits and source archives.

## Remaining limits to publish with the project

This is a JWT-SVID-only, single-trust-domain reference. The draft is not an RFC and the generic MCP Client Credentials profile differs. The TypeScript adapter is a local compatibility fixture. Explicit cached-SVID reuse is a demonstrated risk, and anyone permitted to start a workload with an authorized ServiceAccount can assume its identity. Existing access tokens survive grant revocation until expiry. Planned signing key rotation with overlap and request budgets are implemented; a restart still loses old signing keys. No HA, user delegation or managed audit archive is implemented. These are separate future milestones in the [development plan](development-plan.md).

## Revision references

Revision hashes in dated records that do not resolve in this repository identify
development commits. They were squashed into the 2026-10-13 release commit and are
archived locally. The release tree was checked again after the squash.
