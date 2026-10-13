# Portfolio checkpoint - 2026-10-07

Local checkout review and task reconciliation. No application tests, live demo, remote CI or release checks were rerun for this checkpoint. Validation counts below are recorded evidence from the cited project documents, not fresh results. All five checkouts were clean before this tracking update.

The `ciso-assistance` project was later renamed IT GRC.

## Where work stopped

| Project | Inspected HEAD | Recorded baseline | Remaining boundary |
|---|---|---|---|
| mcp-svid-auth | dbc5736 | 2026-10-06: 467 offline tests, 18 integrated scenarios, 11 synthetic WebAuthn/OIDC checks and scoped lifecycle | Real Google and physical passkey enrollment; user delegation; admission, independent checkpoints and key overlap |
| hipaa-fhir-mcp | 13e05de | 2026-10-06: 10 tests and local quality gates; shared mTLS/OAuth gateway | Real HTTP response validation/projection, bounded results, rejected stdio audit and record authorization |
| mcp-spiffe-bridge | 44536a4 | 2026-10-06: 56 tests, typecheck/build/lint with 9 warnings; real TLS consumer | In-process reconnect, root rotation/removal and long-lived connection policy |
| ecs-contract | 52397b9 | 2026-10-04: 131 tests and static checks; historical single-service live smoke | Synthesis/deploy race, writer coordination, compact ownership demo, rotation/rollback |
| ciso-assistance | c34d513 | 2026-10-06: v0.1.1, 27 tests, 6 fixture outcomes, integrated assessments/model drafts, responsive UI and verified archive | Optional dedicated sign-in boundary; ephemeral review-state retention/recovery |

Sources: each project's README and docs/development-plan.md; root docs/portfolio-development-plan.md and docs/passwordless-identity.md; CISO docs/evaluation.md. These remain prototypes with bounded evidence, not production or compliance certification.

## Sequence and ownership

1. FHIR: complete real response validation and actual stdio denial audit first. These are independently actionable and do not require personal identity setup.
2. Operator gate: complete real Google and physical passkey enrollment when the operator is available. Keep it blocked in beads; synthetic login success does not satisfy it.
3. Define delegation in mcp-svid-auth, then record authorization in FHIR. Keep verified human, acting workload and backend credential separate. Cross-repository dependency: fhir-z9s needs the approved svid-dtw contract in addition to its local blockers. This dependency is documented here, not automatically enforced across databases.
4. Harden bridge lifecycle, workload admission and independently retained checkpoints in bounded increments. Preserve the current fail-closed restart behavior until reconnect is proven.
5. ECS follows a separate lane: prove stale infrastructure plan rejection and shared writer coordination, then the minimal offline board demo and rotation/rollback. Live AWS work and publication are separate authorizations.
6. CISO already has a complete local presentation baseline. Treat shared sign-in and persistence as separate extensions; do not expand its authority to clinical tools or automatic remediation.

The shared VM also serves CISO. Coordinate full VM shutdown or restart across consumers; project teardown must retain sibling namespaces.

## Beads reconciliation

Beads now exists in all five repositories. Created 16 scoped follow-up tasks with acceptance criteria. Existing ecsc-slz remains the demo task. Closed ecsc-frc for completed local implementation only, with a new release-state verification task because local tags do not establish a 0.3.0 publication. Closed svid-jtu as superseded by Lima/k3s, not as proof of a kind backend. Delegation design is a child of svid-lp6. Personal writing tasks remain local and excluded from exports.

The coordinator uses each repository's local database as its task source. Run bd --sandbox ready before work, mark the selected task in_progress, and close it only with validation evidence. Export after mutations, excluding personal labels and removing owner fields. Keep .beads/issues.jsonl as the reviewable snapshot. Do not commit database files, credentials or private notes. Cross-project dependencies must be recorded with repository and task ID; do not assume an ID in another database is a local dependency.

Both no-git-ops and dolt.auto-push are explicitly disabled for remote operations (no-git-ops: true; dolt.auto-push: false). Use --sandbox as an additional sync guard. During reconciliation, the pre-existing ECS Dolt configuration attempted auto-push despite no-git-ops; it failed resolving GitHub. No successful remote write was observed. The separate auto-push setting was then disabled in all five repositories.

No Git commits, remote publication, AWS changes or runtime changes were made in this checkpoint. Tracking files remain local for review.

## Active task index


### mcp-svid-auth

- `svid-9xg` P1 (blocked): Complete real Google and physical passkey operator gates
- `svid-e13` P1 (open): Constrain ServiceAccount admission and protect audit checkpoints
- `svid-a66` P2 (open): Report SPIRE agent jwtSVIDIncludeJTI cache bug upstream
- `svid-dtw` P2 (open): Specify bounded human-to-workload delegation
- `svid-lp6` P2 (open): Delegation chain with Transaction Tokens
- `svid-xoz` P2 (open): Test signing-key overlap and bound request cost
- `svid-e3d` P4 (open): Bump cryptography and zensical bounds when needed

### hipaa-fhir-mcp

- `fhir-rhq` P0 (open): Audit rejected requests through the actual stdio transport
- `fhir-tfz` P0 (open): Validate and minimize real HTTP FHIR responses
- `fhir-z9s` P1 (open): Define record authorization and separate backend credentials
- `fhir-6p1` P2 (open): Repair standalone setup and metadata documentation

### mcp-spiffe-bridge

- `bridge-2v9` P1 (open): Specify and test bounded credential-stream reconnect
- `bridge-sgs` P1 (open): Prove trust-root rotation and connection revocation boundaries
- `bridge-uiq` P2 (open): Bound SDK support and clean library documentation

### ecs-contract

- `ecsc-hlg` P0 (open): Prevent stale infrastructure deployment across competing writers
- `ecsc-1te` P1 (open): Demonstrate secret rotation and rollback safely
- `ecsc-slz` P1 (open): smallest-board demo, service and infrastructure
- `ecsc-4dc` P2 (open): Reconcile local release metadata with verified distribution state

### ciso-assistance

- `ciso-dxv` P1 (open): Define review-state retention and recovery evidence
- `ciso-857` P2 (open): Specify optional shared sign-in boundary for CISO
