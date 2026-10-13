# Portfolio review

Mode: live. Complete: True.

Consensus is a proposal, not verified correctness or approval.

## engineering-os

Revision: d7eceececfec5cf1ccfc4c3417ce4b76a2cb4daa. Dirty: True. Files: 4.

### F1: No tracker adapter seam: beads is baked into the domain types, loader, and single-source store

P3 / unresolved

The dashboard has no adapter contract separating tracker access from the work-graph model, so the documented optional Linear adapter has nowhere to plug in, and multi-repository identity is unrepresentable. Three concrete couplings: (1) `Source` enumerates only beads-native shapes (a bd workspace root, a beads JSONL file) and `loadIssues` execs the `bd` binary directly, so a second tracker requires editing the shared loader rather than adding a module; (2) types.ts declares `Issue`/`Dependency` as a reduction of `bd export`, with `Dependency.type` documented as the beads vocabulary, so any other tracker must either fake beads strings or widen the core type; (3) `IssueStore` holds a single `Source` and returns a fixed one-element array with hardcoded id "source-1" and label "Configured tracker", so the status API cannot express more than one repository or tracker at all. Compounding this, `Issue` has no source or repository field and `project` is derived only from the id prefix before the last hyphen, so identical prefixes in two different workspaces merge into one project and ids whose trailing segment contains a hyphen are cut in the wrong place.

Proposal: Introduce an explicit adapter boundary and give issues real identity. (a) Add a module, e.g. dashboard/src/tracker.ts, defining `interface TrackerAdapter { readonly id: string; readonly label: string; readonly kind: string; listIssues(): Promise<Issue[]>; }`, and make the current beads.ts the first implementation (BeadsAdapter over {root}, JsonlAdapter over {path}); keep the `bd` execFile call and the .beads existence check inside that module only. (b) In types.ts, drop the beads-specific framing: add required `source_id: string` and `repo: string` to `Issue`, and split `Dependency.type` into a normalized `kind` union plus a `raw_type` passthrough so non-beads trackers map into the model instead of emitting beads strings. (c) Change `IssueStore` to hold `readonly adapters: TrackerAdapter[]`, keep per-adapter loadedAt/error/snapshot state, and build sourceStatus() by mapping over the adapters using each adapter's own id/label/kind instead of the literals "source-1" and "Configured tracker". (d) Key project identity on source_id plus projectOf(id), or have the adapter supply the project explicitly, so same-prefix ids from different repositories stay distinct.

Acceptance: Accept when all of the following hold in the tracked source: (1) a second adapter, even a stub returning a fixed array, can be added and registered without editing types.ts or store.ts; (2) the `bd` binary name, the .beads path literal, and execFile appear only in the beads adapter module, not in store.ts or types.ts, and types.ts contains no comment describing the model as the bd export shape; (3) `Issue` has required source_id and repo, and two issues with the same id prefix but different source_id produce different project grouping keys; (4) sourceStatus() returns one entry per configured adapter with ids and labels taken from the adapters, and no "source-1" literal remains; (5) existing beads behavior is preserved end to end, verified by the project's own test command run by the operator, including a case where a dependency arrives in bd show --json shape ({id, dependency_type}) and still normalizes correctly.

- `dashboard/src/types.ts:2`: // `bd export` emits (beads JSONL), reduced to the fields the dashboard uses.
- `dashboard/src/beads.ts:14`: export type Source = { kind: "bd"; root: string } | { kind: "jsonl"; path: string };
- `dashboard/src/beads.ts:108`: const { stdout } = await execFileAsync("bd", ["export", "--no-memories"], {
- `dashboard/src/store.ts:38`: id: "source-1",
- `dashboard/src/beads.ts:19`: return cut > 0 ? id.slice(0, cut) : id;

### research

Reviewed the four supplied tracked sources (dashboard/src/beads.ts, dashboard/src/store.ts, dashboard/src/types.ts, standards/canonical/work-tracking.md) at revision d7eceec (snapshot marked dirty). Per the focus instruction this pass returns a single finding and makes no web calls; current-documentation research is supplied separately by the operator.

On the stated focus: the standards document positions Linear as an optional future adapter and beads as the agent source of truth, which is a plan, not coupling. The actual coupling is in the dashboard code. There is no adapter contract: the domain types are declared as a reduction of `bd export` output, `Source` enumerates only two beads-native shapes, `loadIssues` spawns the `bd` binary inline, and `IssueStore` holds exactly one `Source` and emits one hardcoded `source-1` status row. Multi-repository identity is also unresolved at the type level: `Issue` carries no source or repository attribution, and `project` is derived purely from the id prefix before the last hyphen, so two workspaces using the same prefix collapse into one project and ids whose suffix contains hyphens are split at the wrong point.

Context access boundaries are partly handled well: sourceStatus() returns a generic masked error string rather than the raw message. However lastError exposes the raw error text, and the file header comment says that error is surfaced through /api/health; since loadIssues error messages embed resolved filesystem paths and child-process stderr, that endpoint is a plausible local-path disclosure. The HTTP layer is not in this snapshot, so that is recorded as a limitation rather than a finding.


Limitations:

- No web searches or fetches were performed: the focused pass explicitly directs zero web calls and states the operator supplies current-documentation research separately, so no external documentation is cited and no documentation-currency claims are made.
- At most one finding was requested, so secondary observations were not promoted to findings.
- No commands, builds, tests, or type checks were run, and none are reported; all code claims come from reading the four supplied files only.
- The snapshot is marked dirty at revision d7eceec, so the reviewed text may not match any committed tree.
- The HTTP layer (including the /api/health route referenced by the store.ts header comment), source-status.js, dashboard configuration, and the CLI entry point are not in the snapshot, so the suspected raw-error path disclosure through lastError could not be confirmed or ruled out.
- Vaults, private configuration, untracked work, and all other modules are outside the declared coverage of this selection and were not reviewed.
- The packet lists no omitted sources, so the breadth of what exists outside this selection could not be assessed from the packet itself.
- No previous reviews were supplied, so no cross-review votes are returned.

### verify

F1 identifies concrete beads coupling in the supplied loader and store, but overstates tracker incompatibility and unproven multi-repository behavior. Optional Linear plans do not establish an implemented integration requirement.

- F1: needs_test. The supplied Source union and direct bd invocation establish loader coupling, and each IssueStore exposes one source status. However, Dependency.type and issue status are unrestricted strings, so another tracker need not widen those types or fake beads vocabulary. One source per store does not prove that the omitted application cannot aggregate stores. Issue lacks explicit repository attribution, but actual cross-repository merging requires grouping and configuration code absent here. Splitting an ID at its last hyphen is demonstrated; calling that split incorrect requires an identifier contract. Linear is explicitly optional roadmap work. An adapter seam is a reasonable improvement, but the claimed integration failures need a second-adapter exercise and multi-repository tests.

Limitations:

- Reviewed only the four supplied source texts; no commands, tests, web calls, or delegation were performed.
- Application composition, grouping logic, HTTP routes, source-status definitions, configuration, and other modules were omitted from coverage. The packet's omitted list is empty but does not establish complete repository coverage.
- Context access boundaries remain unverified: sourceStatus masks errors, while lastError returns raw error text. Endpoint exposure and authorization cannot be assessed without the HTTP layer.
- Vaults, private configuration, and untracked work are outside coverage. The supplied snapshot is marked dirty.

### rebuttal

Third-pass response to the verifier on F1. No new findings, no web calls, no commands. Independent read of the four supplied files supports F1's structural core: there is no tracker adapter contract in the snapshot. Source is a closed two-branch union of beads-native shapes, loadIssues spawns the bd binary inline, types.ts frames the domain model as a reduction of bd export, and IssueStore carries one Source and emits a single hardcoded status row ("source-1" / "Configured tracker"). Absence of an interface seam is a read-only structural fact and does not require a test to establish, which is where I part from the verifier's blanket needs_test. Two of F1's sub-claims are not established and I record that disagreement: (a) Dependency.type is a bare string, so a non-beads tracker need not widen the core type, only ignore a comment; (b) the claim that splitting an id at its last hyphen is the wrong cut point presumes an identifier contract the snapshot does not contain, and actual cross-repository project merging needs the omitted composition and grouping code to demonstrate. The attribution gap itself is type-level and verifiable: Issue (types.ts lines 13-34) has no source or repository field, so issues from two adapters would be indistinguishable once merged regardless of how the omitted app layer composes stores. Linear remains explicitly optional roadmap text in standards/canonical/work-tracking.md and is correctly not treated as implemented coupling by F1. F1's improvement and acceptance criteria stand as written and are achievable without the omitted modules. Context access boundaries remain unresolved in both prior reviews and cannot be settled from this selection: sourceStatus() masks the error string, lastError returns raw text, and the referenced /api/health route is not supplied.

- F1: support. The load-bearing claim is absence of an adapter seam, which is directly readable in the snapshot rather than a behavioral prediction. Source is a closed union of two beads-native shapes, loadIssues execs the bd binary in the same shared module, types.ts documents the model as the bd export shape, and IssueStore takes one Source and returns a fixed one-element status array with literal id and label, so a second tracker or repository cannot be registered without editing the shared loader and store. I do not adopt the verifier's blanket needs_test: showing that no interface exists needs no second-adapter exercise. I preserve two disagreements with F1 as written. First, Dependency.type is plain string, so another tracker need not emit beads vocabulary or widen the core type; only a comment is beads-specific, which weakens that leg. Second, calling the last-hyphen cut incorrect assumes an id format contract absent here, and cross-repository project collision depends on omitted composition and grouping code, so that consequence is untested. The attribution gap is still real at type level: Issue has no source or repository field (types.ts 13-34), so merged issues from distinct workspaces are indistinguishable however the omitted layer composes stores. Priority 3 fits design debt against the documented optional Linear adapter, not a present functional defect. The improvement and acceptance criteria stand, with item 3 read as requiring explicit attribution rather than proving a current merge bug.

Limitations:

- No web searches or fetches were performed, per the focused pass instruction that the operator supplies current-documentation research separately; no documentation-currency claims are made.
- No commands, builds, tests, or type checks were run; all claims come from reading the four supplied file texts only.
- Per instruction, findings is empty and exactly one vote is returned for the single original finding F1; no new findings were introduced.
- Omitted coverage: the HTTP layer including the /api/health route named in the store.ts header comment, source-status.js (the SourceStatus type), the app composition and CLI entry point, grouping and filtering logic, and dashboard configuration are absent from the snapshot, so context access boundaries and multi-store aggregation behavior could not be assessed.
- Omitted coverage: vaults, private configuration, untracked work, and all other modules are outside the declared selection and were not reviewed.
- The packet's omitted list is empty, which does not establish complete repository coverage, so the breadth of what exists outside this selection is unknown.
- The snapshot is marked dirty at revision d7eceec, so the reviewed text may not match any committed tree.
- Prior reviews were treated as untrusted evidence; agreement between them was not treated as proof, and each cited line was re-read in the supplied text.

### kimi

Independent read of the four supplied files confirms F1's core structural claim: no tracker adapter seam exists in the snapshot. Source is a closed two-branch union of beads-native shapes; loadIssues spawns the bd binary inline; types.ts frames the domain model as a reduction of bd export; IssueStore holds exactly one Source and emits a single hardcoded status row ("source-1"/"Configured tracker"). These are read-only structural facts. However, F1 overstates two consequences: Dependency.type is plain string, so non-beads trackers need not fake beads vocabulary or widen types; and the last-hyphen split for projectOf assumes an identifier contract absent here, making cross-repository collision an unproven behavioral claim without omitted composition code. The type-level attribution gap is verifiable: Issue lacks source/repo fields, so merged issues from distinct adapters would be indistinguishable. Linear remains correctly documented as optional roadmap work. I split the difference: support the adapter-absence claim as directly observable, but mark needs_test for the unproven multi-repository collision and project-split correctness claims that require omitted application logic to demonstrate.

- F1: needs_test. The adapter seam absence is structurally verifiable: Source is a closed union of beads-native shapes, loadIssues execs bd inline, types.ts documents the model as bd export reduction, and IssueStore carries one Source with hardcoded status literals. I support this leg. However, F1 bundles unproven behavioral claims: (1) that last-hyphen splitting is incorrect requires an id format contract not in the snapshot; (2) that identical prefixes across workspaces cause merging requires omitted grouping/composition code to demonstrate; (3) that Dependency.type forces beads vocabulary is overstated since it is plain string. The attribution gap (no source/repo on Issue) is type-level real but its consequences need the omitted application layer. Priority 3 design debt is appropriate. Verdict is needs_test because the improvement criteria require behavioral verification (items 3-5) that cannot be validated from this selection alone.

Limitations:

- No web searches, fetches, commands, builds, tests, or type checks were performed; all claims from reading four supplied files only.
- HTTP layer, /api/health route, source-status.js, app composition, CLI entry point, grouping/filtering logic, and dashboard configuration are absent from snapshot.
- Vaults, private configuration, untracked work, and all other modules outside declared selection were not reviewed.
- Packet omitted list is empty but does not establish complete repository coverage; breadth of outside code unknown.
- Snapshot marked dirty at revision d7eceec; reviewed text may not match any committed tree.
- Prior reviews treated as untrusted evidence; agreement between them was not treated as proof.
