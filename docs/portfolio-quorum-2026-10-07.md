# Six-project quorum - 2026-10-07

Focused run: `20261007T123322520415Z`. Status: complete for the declared focused source selections.
The preceding broad run `20261007T122242280168Z` timed out on the first
research stage and was cancelled before repeating the same failure elsewhere.

The review uses saved working-tree packets with per-file hashes. A source quote
is checked mechanically; agreement is not proof of a defect. Claude researches,
Codex challenges, Claude responds and Kimi casts an independent vote. A project
is complete only after all required stages return validated results. This is a
bounded portfolio review, not a full security audit or deployment qualification.

## Fresh local validation

| Project | Result | Boundary |
|---|---|---|
| mcp-svid-auth | 505 tests, lint, types and generated docs passed | No fresh VM, physical passkey or Google enrollment test |
| hipaa-fhir-mcp | 10 tests and TypeScript check passed | Synthetic tests; focused model packet contains only config and two security stubs |
| mcp-spiffe-bridge | 56 tests and TypeScript check passed | First sandbox run lacked socket permission; unrestricted local rerun passed |
| ecs-contract | 131 tests passed | First sandbox run lacked jsii cache permission; local rerun passed; no AWS deployment |
| ciso-assistance | 27 tests and repository validation passed | Synthetic evidence and local HTTP, not compliance certification |
| engineering-os | Dashboard: 53 tests and types passed; RAG not run | RAG dependencies absent; frozen-lockfile restoration was interrupted after a prolonged final-package download, before tests started |

Successful tests establish the tested baseline, not the absence of gaps identified
by reviewers. No application behavior was modified in this review.

## Current public references

Checked directly on 2026-10-07 by the coordinating agent, independently of the
model reviews. These references inform the development priorities; they do not
prove the local implementation meets the referenced requirements.

- [MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices):
  audience validation, no incoming token passthrough, scoped access and proxy
  boundaries remain central to the authorization and transport projects.
- [SPIFFE SVID operations](https://spiffe.io/docs/latest/deploying/svids/):
  credential and trust-bundle lifecycle must be assessed together. Reconnect,
  rotation and already-established connections deserve explicit scenarios.
- [FHIR R4 security](https://hl7.org/fhir/R4/security.html):
  the FHIR format alone is not an authorization or privacy boundary. Keep
  synthetic examples distinct from deployment controls and data access policy.
- [Amazon ECS service updates](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service-parameters.html):
  deployment settings and task-definition changes motivate testing the
  infrastructure/application ownership boundary across updates and rollback.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework):
  a voluntary risk-management framework supports explicit evidence, evaluation
  and human review. The NIST page says AI RMF 1.0 is being revised; do not present
  work in progress as a newly finalized requirement.

## Reconciliation

Existing project tasks were reused when model findings described the same work.
Consensus findings remain investigation proposals until behavior is reproduced.
Unresolved votes, omitted coverage and failed stages remain visible in the final
record. Runtime databases stay private; only filtered issue exports are saved.

## Coordinator reproduction checks

These checks were performed separately from the model votes. They do not rewrite
the historical votes or imply the reviewers observed these executions.

- FHIR configuration: executed `loadConfig` with synthetic environment values
  and `NODE_ENV=production`. With no FHIR URL it returned the HTTPS SMART sandbox
  default; with `http://example.org/fhir` it accepted HTTP. Both had no configured
  bearer token or audit file. This is a reproduced configuration gap, not a
  demonstrated PHI disclosure.
- FHIR audit correction: `src/audit/logger.ts` writes to stderr in production
  regardless of a file path. Therefore requiring an audit file is not the correct
  fix, and the original model claim of no audit sink is rejected by this review.
  A production policy must specify its intended identity and log collection
  mechanisms instead of forcing a static backend token or local file sink.
- Authorization cache: with a two-entry ReplayCache, subject A filled both live
  slots, subject B was refused, and B was accepted after expiry. This confirms
  shared-capacity contention and preserves fail-closed expiry behavior. It does
  not establish that a deployed workload can obtain enough distinct signed SVIDs
  to exhaust the real default cache. Measure the issuer behavior before calling
  this an exploitable denial of service.
- ECS secret-key probe: injected synthetic botocore ClientError instances into a
  mock client. AccessDeniedException returned unknown (`None`), while
  ThrottlingException and DecryptionFailure returned absence (`False`). The
  inspected caller converts `False` into a missing-key diagnostic. This semantic
  misclassification is reproduced without AWS access. Fixing it does not require
  allowing deployment after an unreadable secret; define the refusal policy
  separately from accurate diagnostics.
- Bridge recovery: the existing passing fetcher tests explicitly refuse cached
  credentials after stream termination and require a fresh instance after
  startup failure. Reconnect is an availability extension. Serving cached
  credentials during failure or ignoring invalid updates is not accepted by this
  coordinator review; preserve denial until fresh, validated state is available.
- CISO import digest: passed two equivalent synthetic lab-shaped dictionaries
  with reversed top-level key order through `import_lab` using the HTTP handler's
  serialization. Both were accepted and their digests differed. No lab was run.
  This confirms representation-sensitive hashes, not tampering or broken SHA-256.
  Task `ciso-lwa` must choose raw-file versus canonical-record identity and align
  HTTP/CLI behavior and export labels with that choice.

## Proposed development order

1. Preserve the existing high-priority FHIR response validation/minimization and
   actual stdio-denial audit work (`fhir-tfz`, `fhir-rhq`). Add the reproduced
   production endpoint guard (`fhir-lx6`) without forcing static credentials.
2. In the independent ECS lane, retain stale-plan/writer coordination
   (`ecsc-hlg`) and fix error-state misclassification (`ecsc-b2m`). Reproduction
   does not establish that warning-and-continuation is the safe deployment policy.
3. Implement bounded bridge reconnect (`bridge-2v9`) with fresh-valid-credential
   gating, then trust-root/connection lifecycle (`bridge-sgs`). Keep the current
   refusal behavior during invalid or disconnected state.
4. Extend the existing authorization cost/rotation task (`svid-xoz`) with realistic
   SVID issuance and cache fairness scenarios. The replay-cache result does not
   replace the separate human-delegation and operator identity work.
5. Engineering OS: portable task identity and adapters (`eos-nmy.1`), context and
   bootstrap qualification (`eos-nmy.3`), then presentation of these review records
   (`eos-nmy.2`). Keep separate repository authorities and show incomplete checks.
6. CISO: define the imported evidence digest contract (`ciso-lwa`) while preserving
   the existing human-review boundary. Retention/recovery (`ciso-dxv`) remains a
   separate extension, not a claim that no persistence exists.

These are coordinator priorities informed by verified behavior and existing
backlog, not a majority vote or an instruction to implement every model remedy.

## Final model outcomes

| Project | Model outcome | Coordinator disposition / task |
|---|---|---|
| mcp-svid-auth | Unresolved; all three votes needs_test | Cache fairness is reproduced at helper level; realistic issuer load remains untested. Extend svid-xoz |
| hipaa-fhir-mcp | Unresolved; all three votes needs_test | HTTP acceptance is reproduced; reject the no-audit implication. New fhir-lx6 |
| mcp-spiffe-bridge | Consensus proposal | Reconnect extension is useful; reject cached-credential grace during failure. Reuse bridge-2v9 |
| ecs-contract | Consensus proposal | Read-error versus absence misclassification reproduced. New ecsc-b2m; deployment policy remains explicit |
| ciso-assistance | Unresolved | Hash representation is reproducible but its intended contract needs definition. New ciso-lwa |
| engineering-os | Unresolved | Adapter boundary remains design work; behavior requires multi-source tests. Existing eos-nmy tasks |

There are six findings, one per selected project, with separate Codex, Claude
response and Kimi votes. No model proposal was automatically accepted or applied.
The three new tasks and two existing-task clarifications are coordinator-authored
investigations with corrected boundaries, not copies of unsafe model remedies.

Five projects received fresh model chains in isolated per-project MCP runs with
a concurrency limit of two. Engineering OS reused its previously validated
four-stage review after an exact packet-byte equality check; the parent manifest
records that reuse. All parent packet hashes and source quotations were rechecked.

The five fresh accepted Kimi requests reported 54,063 tokens in total.
The reused Engineering OS vote incurred no new request. This count excludes
earlier attempts and does not estimate Claude/Codex usage or currency cost.

[Interactive portfolio report](quorum-portfolio/index.html),
[full votes and evidence](quorum-portfolio/report.json),
[stage events](quorum-portfolio/events.jsonl), and
[run manifest](quorum-portfolio/manifest.json).
Public reports normalize typography to plain hyphens and a model-generated
synthetic hostname to example.org. Source quotations remain unchanged; original
raw run records stay local.

Application behavior was not changed. Deployment, physical identity enrollment,
full RAG qualification and validation of every suggested remedy remain outside
this completed bounded review. RAG dependency installation was interrupted and
must be completed from the unchanged lockfile before its tests can run.
