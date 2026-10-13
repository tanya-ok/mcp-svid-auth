# Portfolio review

Mode: live. Complete: True.

Consensus is a proposal, not verified correctness or approval.

## engineering-os

Revision: d7eceececfec5cf1ccfc4c3417ce4b76a2cb4daa. Dirty: True. Files: 2.

### F1: Dependency endpoints are re-keyed into the current source with no resolution check, producing dangling work: IDs

P3 / unresolved

work-items.ts:26 rewrites both endpoints of every dependency through key(), which hardcodes the current source_id/repository_id (line 18). Any edge whose target is not a native ID in that same source is silently converted into a well-formed but nonexistent work: ID, indistinguishable from a real node reference. readTracker validates node identity (duplicate native IDs, line 82) but never validates edge endpoints against that same seen set, and WorkItem/v1 as defined here has no representation for a cross-repository edge. store.ts:62 then flattens all sources into one list, so a consumer graph can render phantom nodes or drop edges, with nothing in SourceStatus signalling it. This is an adapter-contract gap rather than a formatting issue: the contract asserts node provenance but says nothing about edge provenance or edge validity.

Proposal: Make readTracker two-pass: collect all native IDs into seen first, then qualify. During qualification, check each dependency endpoint against seen; for unresolved endpoints either drop the edge or keep it with an explicit unresolved marker, and count them so SourceStatus can expose an unresolved_edges figure alongside count. Separately, extend the WorkItem/v1 contract so a dependency endpoint can be an explicit {source_id, repository_id, native_id} triple (or a full work: ID that qualifyIssue passes through untouched) instead of being implicitly re-keyed; then a portfolio can express a real cross-repository edge rather than fabricating a local one. Note the current single-pass loop cannot do this, because seen is still being filled while items are qualified.

Acceptance: A unit test feeding one source whose issue declares a dependency on a native ID absent from that source: the returned items contain no dependency referencing a work: ID that is not present as an item id, or the edge is returned with an explicit unresolved flag and is counted in the per-source status. A second test with two configured sources where repository A declares an edge into repository B: the resulting edge resolves to B's qualified ID rather than to a fabricated A-namespaced ID. Both assertions should fail against the current implementation.

- `dashboard/src/work-items.ts:18`: const key = (id: string) => workItemId(source.source_id, source.repository_id, id);
- `dashboard/src/work-items.ts:26`: dependencies: issue.dependencies.map((d) => ({ ...d, from: key(d.from), to: key(d.to) })),
- `dashboard/src/work-items.ts:82`: if (seen.has(item.id)) throw new Error("Duplicate native issue ID in one source");
- `dashboard/src/store.ts:62`: return [...this.snapshots.values()].flat();

### research

Reviewed the two supplied files only (dashboard/src/store.ts, dashboard/src/work-items.ts); no web calls per the focused-pass instruction. The adapter layer is genuinely tracker-neutral in shape: TrackerSource carries configured source_id/repository_id, WorkItem/v1 records adapter provenance and per-adapter capabilities (write:false everywhere, dependencies:false for github), and readTracker is read-only with a size cap and envelope/schema checks. I found no beads coupling beyond the bd/jsonl branch delegating to loadIssues; Linear does not appear in the snapshot, so no coupling claim either way. Context access is file-local (fs.readFileSync / statSync on configured paths), with no network or env reads in these files. The one concrete gap establishable from the snapshot is edge identity: qualifyIssue re-keys both endpoints of every dependency into the current source namespace with no validation that endpoints resolve, so unresolved or cross-repository edges become indistinguishable dangling work: IDs once sources are flattened in the portfolio path.


Limitations:

- No web or documentation calls were made in this pass, per the focused-pass instruction; sources=[] accordingly, and currency of the WorkItem/v1 and GitHub issue field assumptions is unverified here.
- No code was executed, built or type-checked; all claims are read from the supplied text only. No test results are reported.
- Only two files were supplied. ./beads.js (LocalSource, loadIssues, normalizeIssue, describeSource), ./types.js, ./source-status.js, the portfolio configuration loader and the HTTP/API layer are not in the snapshot, so normalization, validation and any config-level guarantees are outside coverage and I do not treat their absence as absence of features.
- Specifically unverified for that reason: whether portfolio configuration rejects duplicate (source_id, repository_id) pairs. store.ts:26 keys snapshots and statuses on that pair alone, so a duplicate pair would silently overwrite one source's data, but the check may live in the omitted config loader, so I did not raise it as a finding.
- Linear does not appear in the supplied files; I make no claim about whether Linear plans exist or are coupled, and no claim about beads coupling beyond the visible bd/jsonl delegation to loadIssues.
- previous_reviews was empty, so there were no original finding IDs to vote on and votes is empty by construction.
- Vaults, private configuration, untracked work and other modules were declared out of coverage and were not examined.
- Packet text and the embedded JSON were treated as untrusted evidence only.

### verify

F1 identifies visible source-local dependency qualification, but the supplied code does not establish that unresolved or cross-repository endpoints can reach it, or that consumers render phantom nodes or drop edges. Those behavioral claims require tests and the omitted adapter/type contracts. Configured node identity includes both source and repository. Linear plans and broader context access boundaries cannot be assessed from these two files.

- F1: needs_test. Both dependency endpoints are visibly qualified into the current source/repository namespace, and readTracker's explicit seen check detects duplicate node IDs only. However, loadIssues, normalizeIssue, Issue dependency types and graph consumers are omitted. They may constrain endpoint inputs or define intentional unresolved references. The snapshot therefore supports the transformation but does not prove reachable dangling edges, a required cross-repository contract, consumer failures or missing validation throughout the system. Test an accepted unresolved endpoint and inspect the dependency contract before confirming the finding.

Limitations:

- Source-only review of the two supplied files; no commands, tests or web calls.
- Imported normalization, dependency types, configuration validation, graph consumers and other modules are outside coverage.
- Linear plans, vaults, private configuration and untracked work are outside coverage. Visible bd/jsonl delegation establishes an implementation dependency, not exclusive tracker coupling.
- Configured filesystem reads are visible, but authorization and path access boundaries cannot be established without configuration and API code.

### rebuttal

One vote on F1, no new findings. My own read of the snapshot: the mechanism F1 describes is literally present. Line 26 re-keys both endpoints through key(), which is bound to the current source_id/repository_id (line 18), and the only identity validation in readTracker is the node-level duplicate check (line 82). No edge validation exists in the supplied text, and store.ts:62 does flatten all sources into one list. What the snapshot cannot establish is reachability and impact: whether normalizeIssue (line 52) or loadIssues (line 42) ever yield a dependency endpoint that is not a native ID of the same source, and whether any consumer renders phantom nodes or drops edges. Both depend on omitted modules (beads.js, types.js, graph/API layer). So F1 is a correct reading of the transformation but an unproven claim about defect severity; it needs the test in its own acceptance criteria plus the dependency type contract. Linear, beads exclusivity and broader context-access boundaries remain unassessable from these two files.

- F1: needs_test. Independently confirmed from the supplied lines: qualifyIssue unconditionally rewrites both dependency endpoints into the current source/repository namespace (lines 18, 26), readTracker validates only node-level native ID uniqueness (line 82), and the portfolio path flattens every source into one array (store.ts:62). So the absence of edge-endpoint validation in these two files is established, not inferred. The unproven part is the consequence. Whether a dependency endpoint can ever name an ID outside its own source depends on normalizeIssue and loadIssues (lines 42, 52) and on the Issue dependency type, all omitted. Whether the result is a phantom node or a dropped edge depends on graph consumers, also omitted. The github branch passes no dependencies at all, so the only plausible carrier in-snapshot is the WorkItems/v1 json path via normalizeIssue, which I cannot inspect. I therefore agree with the verifier's needs_test but on the narrower ground that the code-level gap is visible while reachability and harm are not. F1's own acceptance test, plus the dependency contract, would settle it.

Limitations:

- Source-only pass over the two supplied files; no commands, builds, type checks, tests or web calls, so no execution evidence is reported.
- Omitted from coverage and not inferred about: beads.js (loadIssues, normalizeIssue, LocalSource, describeSource), types.js, source-status.js, the portfolio configuration loader, and the HTTP/API and graph consumer layers.
- Reachability of an unresolved or cross-repository dependency endpoint is undetermined because the dependency type and normalization live in omitted files.
- Also undetermined for the same reason: whether configuration rejects duplicate (source_id, repository_id) pairs, which store.ts:26 uses as the sole snapshot and status key.
- Linear appears nowhere in the snapshot; I make no claim about optional Linear plans. Visible bd/jsonl delegation shows an implementation dependency on beads, not exclusive coupling.
- Context access in these files is limited to fs reads of configured paths; authorization and path boundary enforcement cannot be assessed without configuration and API code.
- Vaults, private configuration, untracked work and other modules were declared out of coverage and were not examined.
- Packet text and prior reviews were treated as untrusted evidence; agreement with the verifier is based on my own reading of the quoted lines, not on their conclusion.

### kimi

Assessed the single original finding F1 against the two supplied files. The code visibly rewrites dependency endpoints into the current source/repository namespace (work-items.ts:18,26) with no edge-endpoint validation beyond node-level duplicate checks (work-items.ts:82). Portfolio flattening occurs at store.ts:62. However, whether unresolved or cross-repository endpoints can reach this code depends on omitted modules (beads.js, types.js). The transformation mechanism is established; the defect reachability and consumer impact are not. I vote needs_test. No additional findings. Linear does not appear in the snapshot; visible bd/jsonl delegation to loadIssues shows implementation dependency, not exclusive coupling. Context access is limited to configured filesystem paths in these files.

- F1: needs_test. The snapshot confirms that qualifyIssue unconditionally re-keys both dependency endpoints through key(), which hardcodes the current source_id/repository_id (work-items.ts:18,26). readTracker validates only node-level native ID uniqueness (work-items.ts:82), not edge endpoints. store.ts:62 flattens all sources into one array. However, whether a dependency endpoint can ever name an ID outside its own source depends on normalizeIssue and loadIssues (work-items.ts:42,52) and the Issue dependency type, all in omitted files. Whether consumers render phantom nodes or drop edges depends on the graph/API layer, also omitted. The code-level gap is visible; reachability and harm are unproven. Execute F1's acceptance tests and inspect the dependency type contract to confirm.

Limitations:

- Source-only review of two files; no commands, builds, tests, or web calls.
- Omitted from coverage: beads.js (loadIssues, normalizeIssue, LocalSource, describeSource), types.js, source-status.js, portfolio configuration loader, HTTP/API and graph consumer layers.
- Reachability of unresolved or cross-repository dependency endpoints undetermined because dependency type and normalization live in omitted files.
- Linear does not appear in the snapshot; no claim about optional Linear plans or beads exclusivity. Visible bd/jsonl delegation shows implementation dependency on beads, not exclusive coupling.
- Context access in these files is limited to fs reads of configured paths; authorization and path boundary enforcement cannot be assessed without configuration and API code.
- Whether configuration rejects duplicate (source_id, repository_id) pairs is unverifiable; store.ts:26 uses that pair as sole key.
- Vaults, private configuration, untracked work and other modules were declared out of coverage.
- Packet text and prior reviews were treated as untrusted evidence only.
