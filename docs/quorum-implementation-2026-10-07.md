# Portfolio quorum implementation

User-authorized scope: implement the recommendations in the six-project quorum,
resolve disputed decisions with evidence and use additional provider review when
needed. The original review remains an immutable historical record. This ledger
tracks implementation and does not substitute passing local checks for live gates.

| Work | Beads | Status and required evidence |
|---|---|---|
| FHIR response validation, projection, bounded pagination | fhir-tfz | Implemented: FHIR commits 91aa759/e9dad1b; 51 tests, types, build, Biome and PHI sweep passed |
| Stdio denial audit | fhir-rhq | Implemented: actual child process proves seven invocations and seven safe records, no protocol errors |
| Explicit production endpoint | fhir-lx6 | Implemented: explicit HTTPS production/unspecified-mode destination; token cannot use implicit sandbox; negative tests passed |
| ECS read-error classification | ecsc-b2m | Implemented: ECS b94b9e9; 140 tests, types, lint and format passed; failed reads block render, explicit denied-read mode stays visibly unverified |
| ECS competing writers | ecsc-hlg | Implemented: ECS e1a664c/89e572b; cooperative DynamoDB mutex, stale-plan refusal, uncertain-completion retention; 156 full tests and 19 targeted follow-up checks passed |
| Bridge reconnect | bridge-2v9 | Implemented: bridge cdb488a; real spiffe gRPC reconnect, bounded backoff, cancellation and invalid-update refusal; 79 tests, types, lint and build passed |
| Bridge trust-root and connection lifecycle | bridge-sgs | Implemented: TLS 1.2/1.3 root overlap/removal, session refusal, stream loss, certificate expiry, five-minute cap and dispatch-race checks |
| Auth signing-key overlap and request budgets | svid-xoz | Implemented: 525 tests, strict docs and secret scans passed; fresh 18-scenario shared lab verifies key overlap, real SPIRE issuance, FHIR and scoped teardown |
| Portable tracker identities and adapters | eos-nmy.1 | Implemented: EOS 7555469/dfaca64; portable identities, beads/JSON/GitHub snapshots, cross-repository and unresolved edges; 63 dashboard tests, types, lint and build passed |
| Context isolation and reproducible setup | eos-nmy.3 | Implemented: scoped index startup, content/deletion freshness, Node >=26 and frozen bootstrap; 46 RAG unit tests and three real-model E2E checks passed |
| Review evidence in Engineering OS | eos-nmy.2 | Implemented: ReviewEvidence/v1 and Reviews view retain incomplete/disputed findings, independent provider votes, revisions and explicit task links; no automatic approval or task mutation |
| CISO digest semantics | ciso-lwa | Implemented: CISO c2d7ce3/3242b17; raw artifact bytes versus versioned canonical record; actual HTTP/CLI equivalence and one bounded file read verified |
| CISO retention and recovery | ciso-dxv | Implemented: CISO b654995/3242b17; bounded atomic state, refusal instead of silent eviction, checksummed export/restore into an empty directory; 36 tests and repository validation passed |

Related corrections in the touched boundaries include FHIR clean startup,
metadata and accurate documentation. No unsafe historical model remedy is an
acceptance criterion: bridge failure must deny access, ECS unknown state must
not become a silent deployment success, and FHIR does not require a static token
or file sink merely because one reviewer suggested them.

Each completed row must name its code, checks and remaining limitations here or
in its repository documentation. Local commits only; publication and remote CI
are not authorized by this implementation request. Physical-device enrollment
and real clinical/AWS deployments are separate operator gates, not simulated
success criteria.

## Current evidence

FHIR implementation: `hipaa-fhir-mcp/docs/quorum-hardening-2026-10-07.md`.
ECS implementation: `ecs-contract/docs/permissions.md`.
Bridge implementation: `mcp-spiffe-bridge/docs/credential-lifecycle.md`.
The shared SPIRE lab passed all 18 scenarios after auth, bridge and FHIR changes;
scoped teardown preserved CISO and the shared VM.
These are local changes and synthetic checks; native Desktop and remote CI were
not executed. Prior unrelated working-tree edits remain separate.

Additional FHIR configuration review `20261007T152309485403Z` completed Claude
research, then the Codex stage was refused by the existing privacy filter. It is
an incomplete quorum, not an approval. Claude's implicit-mode/token-destination
finding was reproduced by negative configuration tests and corrected in e9dad1b.
The earlier eight-file attempt timed out; targeted HTTP/stdio source selections
were excluded by privacy screening before dispatch. No filter was weakened.

Additional ECS quorum `20261007T160024574521Z` completed Claude/Codex/Claude
and independent Kimi (7216 tokens) after one strict citation rejection. All
supported the unreachable nonzero-exit diagnostic finding. Commit 89e572b
separates execution, nonzero-exit and stability-wait diagnostics; lock retention
and suppression of raw exception text remain unchanged. This is a cooperative
protocol requiring all writers to use the same mutex, not an ECS fencing API.


Additional Engineering OS quorum `20261007T163527732434Z` completed
Claude/Codex/Claude and independent Kimi (7286 tokens). F1 stayed `needs_test`
because the selected source packet omitted parser and graph consequences.
Actual parser/graph tests now prove explicit cross-repository references and
missing-dependency blocking; unresolved graph edges are marked and counted.
The historical report stays unchanged in `docs/quorum-eos-portable/`.

Engineering OS implementation: `engineering-os/docs/portable-portfolio.md`.
CISO contracts: `ciso-assistance/docs/evidence-digests.md` and
`ciso-assistance/docs/review-recovery.md`. Recovery checks preserve human
review decisions while leaving missing evidence `not_verified`. Checksums
provide corruption detection, not authenticity. State storage assumes one
writer; this does not claim high availability or power-loss durability.
RAG filters are not authorization, search is an operator-refreshed snapshot,
and private vaults are excluded from cloud review packets. Trackers remain
read-only adapters; Linear is optional. Clean bootstrap used Node 26.10.0 and
pnpm 10.33.2 with frozen lockfiles, not the exact declared pnpm 10.34.5.

All 13 implementation tasks are closed in their own repository's beads.
Remaining operator gates include real AWS execution, native Desktop enrollment,
remote CI and deployment-specific recovery exercises. None are reported as
executed here. The original quorum findings remain historical observations;
closed implementation tasks are evidenced by the checks above, not by rewriting
provider votes into approvals.

The final local dashboard check loaded 59 issues from six live beads exports,
with no source errors or unresolved dependency edges. The Reviews view preserves
all seven imported reviews and opens the explicitly linked, closed investigation
task. Screenshot and source freshness were checked in the in-app browser.
