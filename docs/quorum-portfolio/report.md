# Portfolio review

Mode: live. Complete: True.

Consensus is a proposal, not verified correctness or approval.

## mcp-svid-auth

Revision: 3b587cae2d9227da22297c5ae8a22d7041c7bfe0. Dirty: True. Files: 2.

### F1: Fail-closed replay cache is a shared, unbounded-by-client DoS surface with no way to size it

P3 / unresolved

ReplayCache is a single process-wide table capped at DEFAULT_REPLAY_CACHE_SIZE = 10_000 (authz.py:46), and when it is full after evicting expired entries it raises temporarily_unavailable/503 for every further assertion (authz.py:95-101), as the docstring states (authz.py:63). Entries are only evicted once exp + _CLOCK_SKEW has passed (authz.py:257), so with the default max_svid_lifetime of 300s plus 30s skew a single allowlisted client that mints fresh jti values can pin ~10k live entries with roughly 30 requests/second and thereby deny token issuance to all other clients until its assertions age out. There is no per-sub or per-trust-domain bound, and build_parser (authz.py:390-439) exposes no flag for ReplayCache.max_entries, while main() (authz.py:453-461) never overrides the default, so an operator cannot raise or partition the limit without code changes. Replay protection itself is correct; the gap is blast radius and operability of the fail-closed path.

Proposal: Bound the cache per subject instead of only globally, and make the limit configurable. Concretely: track a per-sub live count in ReplayCache.add and reject that sub once it exceeds a per-client cap, so one client's burst cannot exhaust capacity shared with others; keep the global cap as a backstop. Add a --replay-cache-size (and optional --replay-cache-per-client) CLI flag in build_parser and wire it through main() into ReplayCache(max_entries=...). Also emit the global-full condition as a distinct audit decision so operators can alert on it rather than inferring it from 503 counts, and document in the fail-closed docstring that capacity must be sized as max_svid_lifetime times the expected assertion rate.

Acceptance: A test fills the cache from one sub and asserts that a second, different sub still receives a token (no 503); a test asserts the offending sub is rejected once its per-client cap is exceeded; a test asserts --replay-cache-size changes the effective ReplayCache.max_entries on the server built by main(); the global-full path writes an audit record with a dedicated decision value. Existing replay-rejection and allow-reuse-within-lifetime behaviour stays unchanged.

- `src/mcp_svid_auth/authz.py:46`: DEFAULT_REPLAY_CACHE_SIZE = 10_000
- `src/mcp_svid_auth/authz.py:63`: expired entries, new assertions are refused (fail closed) instead of forgetting live ones.
- `src/mcp_svid_auth/authz.py:95`: if len(self._expiry) >= self.max_entries:
- `src/mcp_svid_auth/authz.py:257`: self.replay_cache.add(sub, jti, int(claims["exp"]) + _CLOCK_SKEW, time.time())
- `src/mcp_svid_auth/authz.py:118`: replay_cache: ReplayCache = field(default_factory=ReplayCache)

### research

Research-stage review of the two supplied files (authz.py, policy.py); previous_reviews was empty, so no votes are returned. Core token logic reads soundly: the SVID audience is pinned to the issuer and additionally required to be the sole audience value (authz.py:220-235), assertion lifetime is bounded by exp - iat (authz.py:236-243), jti is required and recorded in reject mode (authz.py:212-214, 247-257), duplicate form parameters are rejected per RFC 6749 3.2 (authz.py:304-306), policy reload failures empty the grant table and fail closed (authz.py:147-157), and deny-path audit records hash the unverified sub rather than trusting it (authz.py:319-342). One concrete finding is reported: the replay cache is a single process-wide, fail-closed table with no per-client bound and no CLI knob, so one allowlisted client can make the token endpoint return 503 for everyone. No web tools were available, so sources=[] and no primary documentation is cited; no tests were run.


Limitations:

- No web tools were available in this environment, so no current primary documentation (RFC 6749/7523/8707/9068, draft-ietf-oauth-spiffe-client-auth, PyJWT or Starlette docs) was read or cited; spec-conformance observations rest only on the comments and code in the snapshot.
- No commands or tests were executed; the DoS arithmetic in F1 is derived from the constants in the snapshot (DEFAULT_REPLAY_CACHE_SIZE, DEFAULT_MAX_SVID_LIFETIME, _CLOCK_SKEW), not measured.
- Omitted coverage: mcp_svid_auth.audit (AuditLog), mcp_svid_auth.errors (AuthError), and mcp_svid_auth.spiffe_keys (JWT_SVID_ALGORITHMS, KeyResolver, StaticJwksResolver, WorkloadApiResolver, spiffe_trust_domain) are imported but not supplied, so the allowed assertion algorithm set, trust-bundle resolution, key rotation and audit-sink locking could not be reviewed.
- No tests, docs/configuration.md, resource server or MCP client code, packaging or CI configuration were supplied, so test coverage of the reviewed paths could not be assessed.
- The packet is marked dirty at revision 3b587cae, so the reviewed text may not match any committed state.
- Signal-handler reentrancy of install_policy_reload (authz.py:371-377) calling audit.write and taking _reload_lock from the main thread could not be assessed because the AuditLog locking model is in an omitted file.

### verify

F1 identifies a shared capacity limit in each AuthzServer's replay cache, but the supplied source does not establish that one client can obtain enough distinct valid signed assertions to exhaust it. The CLI lacks sizing options; programmatic sizing is available.

- F1: needs_test. The global capacity check and default cache allocation support contention between subjects using one server instance. However, changing jti requires a newly valid signature, and assertion issuance capabilities and throughput are outside the snapshot. The roughly 30 requests/second exhaustion scenario is therefore unproven. The claim that sizing requires code changes is too broad: ReplayCache accepts max_entries and AuthzServer accepts replay_cache, although the supplied CLI exposes neither. Validate exhaustion using realistically obtainable assertions and verify another subject's rejection. Per-sub caps reduce individual impact but do not guarantee availability when the global cap fills.

Limitations:

- Only authz.py and policy.py were supplied. Assertion issuance, resolver implementations, AuthError, audit implementation, deployment controls, tests, and documentation were not reviewed.
- No commands, tests, or external documentation checks were performed. The packet is marked dirty.

### rebuttal

Arbitration on F1 only; no new findings. I side with the verifier's needs_test rather than the research stage's priority-3 claim, for a sharper reason. The source does prove the shared-fate structure: a single per-process ReplayCache (authz.py:118) capped at 10_000 (authz.py:46) that returns 503 to all subjects once full (authz.py:95-101), with entries retained to exp plus skew (authz.py:257), and no CLI flag in build_parser or main to size it. What the source does not prove is the exploit: ~10k distinct validly signed assertions are required, and the snapshot's own comment (authz.py:47-48) says some SVID sources cache and re-serve one SVID, which in reject mode would be refused as replay instead of consuming capacity. Assertion minting rate lives in omitted spiffe_keys/SPIRE code, so the ~30 requests/second estimate is unverified arithmetic. The research claim that sizing needs code changes is overbroad: max_entries and replay_cache are constructor parameters; only the CLI lacks exposure. The proposed per-sub cap bounds one subject's share but does not restore availability when the global cap fills.

- F1: needs_test. The structural half of F1 is confirmed by the snapshot: one process-wide ReplayCache (authz.py:118) capped at 10_000 (authz.py:46), and a full cache returns temporarily_unavailable/503 to every subsequent assertion regardless of subject (authz.py:95-101), with entries held until exp + skew (authz.py:257). So availability is coupled across all allowlisted clients in reject mode. The exploitability claim is unproven. Filling the table needs ~10k distinct validly signed assertions, and the snapshot's own comment notes SVID sources that cache and re-serve a single SVID (authz.py:47-48), which in reject mode would be rejected as replay rather than adding entries; assertion minting rate lives in omitted spiffe_keys/SPIRE behaviour, so the ~30 requests/second figure is arithmetic, not a measured or source-supported capability. Also too broad: ReplayCache takes max_entries (authz.py:66) and AuthzServer takes replay_cache, so embedders can size it; only build_parser/main expose no flag. Test: fill the cache from one subject and assert a second subject still gets a token, using assertions obtainable from the real SVID source, before accepting priority 3. Note a per-sub cap limits one subject's share but does not restore availability once the global cap fills.

Limitations:

- No web tools; no primary documentation (RFC 6749/7523/8707/9068, draft-ietf-oauth-spiffe-client-auth, PyJWT, Starlette) was consulted, so spec-conformance statements in either prior review were not independently checked.
- No commands or tests were run; all claims rest on the two supplied files.
- Omitted coverage: mcp_svid_auth.audit, mcp_svid_auth.errors and mcp_svid_auth.spiffe_keys are imported but not supplied, so algorithm allowlist, trust-bundle and key resolution, SVID issuance/caching behaviour and audit-sink locking were unreviewable; this is exactly what the F1 exploitability question depends on.
- No tests, docs/configuration.md, deployment or packaging files were supplied, so existing coverage of the replay path and any deployment-level rate limiting could not be assessed, and absence of such controls must not be inferred.
- The packet is marked dirty at revision 3b587cae, so the reviewed text may match no committed state.
- Per instructions I added no new findings; other areas of the two files received no fresh analysis beyond what was needed to adjudicate F1.

### kimi

The only original finding is F1, which claims a shared, unbounded-by-client replay cache creates a DoS surface. The snapshot confirms the structural coupling: one process-wide ReplayCache per AuthzServer (authz.py:118) with a default cap of 10,000 entries (authz.py:46), returning 503 to all subjects once full after eviction (authz.py:95-101), with entries retained until exp + _CLOCK_SKEW (authz.py:257). No CLI flag exists to size it (build_parser authz.py:390-439, main authz.py:453-461). However, the exploitability claim-that one client can mint ~10k distinct valid assertions at ~30/sec-is unproven because SVID issuance rate and caching behavior live in omitted spiffe_keys/SPIRE code. The snapshot's own comment notes some SVID sources cache and re-serve one SVID (authz.py:47-48), which would be replay-rejected, not cache-filling. The claim that sizing requires code changes is overbroad: ReplayCache and AuthzServer accept max_entries/replay_cache parameters; only the CLI lacks exposure. I vote needs_test: the shared-fate structure is real, but the DoS scenario requires validation against actual SVID source behavior.

- F1: needs_test. The structural claim is confirmed: a single per-process ReplayCache (authz.py:118) capped at 10,000 (authz.py:46) returns 503 to all subjects when full (authz.py:95-101), with entries held until exp + _CLOCK_SKEW (authz.py:257), and no CLI flag exists to size it (authz.py:390-439, 453-461). However, exploitability is unproven: filling the cache requires ~10k distinct validly signed assertions, and the snapshot notes some SVID sources cache and re-serve one SVID (authz.py:47-48), which would be replay-rejected rather than adding entries. The claim that sizing requires code changes is overbroad since max_entries and replay_cache are constructor parameters. Test with real SVID source behavior before accepting priority 3.

Limitations:

- Only authz.py and policy.py were supplied; spiffe_keys, audit, errors modules and any tests are omitted.
- No commands or tests were executed; exploitability claims rest on unverified arithmetic about SVID issuance rates.
- No web tools or primary documentation were consulted; spec-conformance statements from prior reviews were not independently checked.
- The packet is marked dirty at revision 3b587cae, so reviewed text may not match any committed state.
- Per instructions, no new findings were added; analysis was scoped to adjudicating F1.
## hipaa-fhir-mcp

Revision: 13e05de6a5bbc2795768d9a712a31f4c01a72188. Dirty: True. Files: 3.

### F1: Config schema has no production guard: PHI can default to a public sandbox FHIR server over cleartext http

P3 / unresolved

src/config.ts validates every variable independently, with no cross-field refinement keyed on NODE_ENV. Consequences visible in the snapshot: (1) NODE_ENV=production parses cleanly while FHIR_BASE_URL falls back to the public SMART sandbox https://r4.smarthealthit.org (line 4), so a deploy that forgets the variable sends requests to a third-party host instead of refusing to start; (2) z.string().url() accepts http:// and other schemes, so PHI-bearing traffic over cleartext passes validation; (3) AUDIT_LOG_FILE (line 7) and FHIR_AUTH_TOKEN (line 5) are optional in all environments, so a production process can start with no configured audit sink and no credential. For a server whose stated purpose is HIPAA-scoped FHIR access, this configuration path fails open toward an external endpoint rather than failing closed. I make no claim about what the audit logger or FHIR client do with these values; those files are not in the snapshot.

Proposal: Add a superRefine (or .refine) on ConfigSchema that activates when NODE_ENV === "production" and requires: FHIR_BASE_URL explicitly present in env rather than defaulted; its parsed protocol to equal "https:"; AUDIT_LOG_FILE non-empty; FHIR_AUTH_TOKEN non-empty. To distinguish present-from-defaulted, drop .default() on FHIR_BASE_URL and apply the sandbox fallback only when NODE_ENV is development or test. Report all violations through the existing flatten().fieldErrors path so the stderr message lists each missing variable. Independently, consider enforcing an https-only URL in every environment unless the host is localhost, and hoist process.exit(1) out of loadConfig into the entrypoint so the invalid-config branch is unit-testable.

Acceptance: Unit tests on loadConfig/ConfigSchema: (a) env with NODE_ENV=production, AUDIT_HMAC_KEY of 32+ chars and nothing else fails validation, with fieldErrors naming FHIR_BASE_URL, AUDIT_LOG_FILE and FHIR_AUTH_TOKEN; (b) NODE_ENV=production with FHIR_BASE_URL=http://example.org fails validation; (c) NODE_ENV=production with https URL plus audit file and token parses successfully; (d) NODE_ENV=development with only AUDIT_HMAC_KEY still parses and yields the sandbox default. No test asserts on process exit behaviour if the exit is moved to the entrypoint.

- `src/config.ts:4`: FHIR_BASE_URL: z.string().url().default("https://r4.smarthealthit.org"),
- `src/config.ts:5`: FHIR_AUTH_TOKEN: z.string().min(1).optional(),
- `src/config.ts:7`: AUDIT_LOG_FILE: z.string().min(1).optional(),
- `src/config.ts:13`: .enum(["development", "production", "test"])
- `src/config.ts:21`: const result = ConfigSchema.safeParse(env);

### research

Source-only research review of three files (config.ts, security/kms.ts, security/spiffe.ts). The kms and spiffe modules are self-declared prototypes whose methods throw; that is consistent and documented, so I raise nothing there. One concrete finding in src/config.ts: validation is per-field with no NODE_ENV-conditional refinement, so NODE_ENV=production parses successfully while FHIR_BASE_URL silently defaults to the public SMART sandbox, AUDIT_LOG_FILE and FHIR_AUTH_TOKEN stay unset, and z.string().url() permits http://. A deploy missing variables fails open toward a third-party endpoint over cleartext instead of refusing to start, which matters for a HIPAA-scoped server. Fix is a superRefine plus removal of the sandbox default outside dev/test. Lower-severity observations noted but not filed: process.exit(1) inside loadConfig makes the invalid-config branch untestable, and min(32) on AUDIT_HMAC_KEY measures characters rather than decoded key entropy.


Limitations:

- No web tools were available in this environment, so I performed zero searches/fetches and cite no documentation; the finding rests only on the supplied snapshot (sources=[]).
- Snapshot contains 3 files; packet lists omitted=[], but no audit logger, FHIR client, MCP tool registration, entrypoint, tests or package manifest are present. I make no claims about their behaviour and did not infer absent features from their absence.
- Cannot confirm whether a separate entrypoint already enforces production checks on top of loadConfig; the finding is scoped to what ConfigSchema itself accepts.
- No tests were executed and no commands were run; acceptance criteria are proposed, not observed.
- zod version is unknown (no manifest), so exact API names for refinement and the behaviour of flatten() on newer majors should be confirmed against the pinned version.
- Severity of the sandbox-default issue depends on deployment practice (e.g. whether env is templated and validated out of band), which is not visible in the snapshot.

### verify

F1 identifies permissive configuration defaults, but the supplied code does not establish PHI transmission, cleartext traffic, missing audit coverage, or successful production startup. The default URL explicitly uses HTTPS. Runtime impact needs verification against the configuration consumers and deployment checks.

- F1: needs_test. The schema visibly defaults FHIR_BASE_URL and leaves token and audit-file settings optional without NODE_ENV-specific checks. However, the default is HTTPS, and no supplied consumer shows requests, PHI handling, audit routing, or production startup. Acceptance of an HTTP URL should be tested with the pinned Zod version. Requiring a token and file sink also needs application requirements: these files do not establish that those are the only supported authentication and auditing mechanisms. The configuration concern is supported; the claimed operational exposure is unproven.

Limitations:

- Only the three supplied source files were reviewed. Although omitted=[] is declared, configuration consumers, entrypoint, deployment configuration, audit implementation, dependency versions, and tests were not supplied.
- No commands, tests, or external documentation checks were performed.

### rebuttal

Arbitration on F1 only; no new findings. The snapshot directly supports the structural facts: ConfigSchema validates fields independently with no NODE_ENV-conditional refinement (lines 3-16), FHIR_BASE_URL carries a public sandbox default (line 4), and FHIR_AUTH_TOKEN and AUDIT_LOG_FILE are optional in every environment (lines 5, 7). What is not established by the supplied code is the impact framing: the built-in default is https, not cleartext, so the title's "over cleartext http" describes an operator-supplied URL and depends on z.string().url() scheme behaviour under an unpinned zod version (no manifest in the packet). Nothing in the three files shows a FHIR client issuing requests, PHI flowing, or an audit sink keyed on AUDIT_LOG_FILE, and no entrypoint is present that might apply production checks above loadConfig. I agree with the verifier that F1 needs a test, while recording that the configuration-shape half of the claim is already proven and the proposed acceptance tests are the right discriminator.

- F1: needs_test. Split evidence. Proven from the snapshot: no cross-field or NODE_ENV-keyed refinement exists, FHIR_BASE_URL silently defaults to https://r4.smarthealthit.org, and FHIR_AUTH_TOKEN and AUDIT_LOG_FILE are optional in production as well as development, so a production parse of an env containing only a 32-char AUDIT_HMAC_KEY will succeed. Not proven: (a) the title's cleartext-http exposure, since the shipped default is https and http acceptance rests on z.string().url() behaviour in an unpinned zod version absent from the packet; (b) that a defaulted base URL causes PHI to reach a third party, since no FHIR client, tool registration or entrypoint is supplied; (c) that an unset AUDIT_LOG_FILE leaves no audit sink, since the logger is not supplied and stderr or another sink may be the fallback; (d) that token-based auth is the only supported credential path. The remediation and acceptance tests in F1 are appropriate and would settle (a) and the production-parse behaviour without needing the absent files. I do not infer any absent feature from the omitted files.

Limitations:

- Only the three packet files were reviewed: src/config.ts, src/security/kms.ts, src/security/spiffe.ts. No code changes, commands or tests were run.
- Packet declares omitted=[], yet no entrypoint, FHIR client, audit logger, MCP tool registration, deployment manifest, package.json or tests are present; no claims are made about them and no features are inferred from their absence.
- zod major version is unknown without a manifest, so the scheme-acceptance behaviour of z.string().url() and the shape of error.flatten().fieldErrors cannot be confirmed from source.
- No web or documentation access was available, so no external verification of zod behaviour or HIPAA control mappings was performed.
- kms.ts and spiffe.ts stubs throw by design and are documented as prototype paths; I agree with the research stage that they warrant no finding here, and I did not assess whether any caller depends on them.
- Severity of the config-default issue depends on out-of-band env templating and deploy-time validation, which are not visible in the snapshot.

### kimi

Reviewed F1 against the supplied snapshot. The structural claim is proven: ConfigSchema lacks NODE_ENV-conditional refinement, FHIR_BASE_URL defaults to a public sandbox URL, and FHIR_AUTH_TOKEN/AUDIT_LOG_FILE are optional in all environments. The impact framing (PHI to third party, cleartext exposure, missing audit coverage) is unproven because no FHIR client, audit logger, entrypoint, or package manifest is supplied. The default URL is https, not http; http acceptance depends on unpinned zod behaviour. I vote needs_test: the configuration shape concern is real, but operational impact requires testing against the pinned zod version and application requirements not visible here. No new findings. kms.ts and spiffe.ts are documented stubs that throw by design; no findings there.

- F1: needs_test. The snapshot proves the structural half: no cross-field or NODE_ENV-keyed refinement exists (lines 3-16), FHIR_BASE_URL silently defaults to https://r4.smarthealthit.org (line 4), and FHIR_AUTH_TOKEN/AUDIT_LOG_FILE are optional everywhere (lines 5,7). A production parse with only AUDIT_HMAC_KEY present succeeds. The impact half is unproven: (a) the title's 'cleartext http' claim is unsupported because the built-in default is https, and z.string().url() scheme acceptance for http depends on an unpinned zod version absent from the packet; (b) no supplied file shows a FHIR client, PHI flow, or that a third party receives data; (c) no audit logger is supplied, so 'missing audit sink' is speculative; (d) no entrypoint is present that might apply production checks above loadConfig. The proposed acceptance tests in F1 would correctly settle the proven behaviour and the http-acceptance question.

Limitations:

- Only three source files reviewed; no entrypoint, FHIR client, audit logger, MCP tool registration, package manifest, tests, or deployment config are present.
- No commands or tests were run; zod major version and z.string().url() scheme behaviour are unverified.
- No web access or documentation lookups available.
- Impact severity depends on out-of-band deployment practices not visible in snapshot.
- kms.ts and spiffe.ts are self-documented prototype stubs; no assessment of caller dependencies was performed.
## mcp-spiffe-bridge

Revision: 44536a44295ee297a730f8199f74525aa685d007. Dirty: True. Files: 2.

### F1: FetchX509SVID stream never reconnects; one transient failure latches the bridge into permanent 503

P3 / consensus_proposal

WorkloadApiSvidFetcher consumes the FetchX509SVID stream exactly once, with no retry or backoff. start() assigns streamTask = this.run().catch(...), and that single catch sets this.streamFailure and sets this.cachedSvid = null. run() also throws on a clean stream end (line 123) and on any response whose leaf is outside its validity window (line 111), so an agent restart, a socket drop, or one momentarily not-yet-valid SVID all land in the same terminal state. After that, getX509Svid() short-circuits at line 66 forever, because nothing clears streamFailure or re-arms streamTask or firstMessageDeferred. MtlsTransportServer.handleRequest awaits this.opts.fetcher.getX509Svid() as its first statement (line 134), so every subsequent request throws and is answered 503 by the createServer catch handler. A still-valid cached SVID is discarded rather than used for graceful degradation, so the process must be restarted to recover.

Proposal: Make run() a supervised reconnect loop instead of a one-shot task: wrap its body in a while (!this.closed) loop that opens a fresh fetchX509SVID call each iteration, catches per-iteration errors, and sleeps with jittered exponential backoff (for example 100ms up to a 30s cap) before retrying. On each error set a transient field such as lastStreamError, used only to reject a still-pending firstMessageDeferred, then re-arm this.firstMessageDeferred = deferred() so later callers await the next connect instead of inheriting a settled rejection. Do not null cachedSvid on stream error; keep serving it and let the existing validity-window check at lines 68-71 fail closed once it actually expires. Treat an invalid or not-yet-valid response as a skipped message (continue) rather than a stream-killing throw at line 111. Keep the permanent-failure path only for close().

Acceptance: A test driving the fetcher with a stream that emits one valid SVID, then an error, then a second SVID after reconnect: getX509Svid() keeps returning the first SVID across the gap and then returns the second, with no restart. A second test asserts repeated reconnect attempts with non-decreasing delays and that close() stops the loop so streamTask settles. A third asserts a response carrying a not-yet-valid leaf is skipped without terminating the stream. At the transport layer, a request issued during the reconnect window returns a normal authenticated response rather than 503.

- `src/svid/fetcher.ts:55`: this.streamTask = this.run().catch(() => {
- `src/svid/fetcher.ts:57`:       this.cachedSvid = null;
- `src/svid/fetcher.ts:66`:     if (this.streamFailure) throw this.streamFailure;
- `src/svid/fetcher.ts:123`:       if (!this.closed) throw new WorkloadApiConnectionError('Workload API stream ended');
- `src/transport/mtls.ts:134`:     await this.opts.fetcher.getX509Svid();

### research

Source-only review of two files (svid/fetcher.ts, transport/mtls.ts). No web tools were available in this environment, so no primary documentation was fetched and sources=[] for the finding; the operator's separate doc check should confirm SPIFFE Workload API client reconnect guidance.

The mTLS server layer looks structurally sound: requestCert plus rejectUnauthorized are set, minVersion is TLSv1.2, the peer DER is re-validated by SvidValidator after Node's chain check, and rotation uses setSecureContext rather than a listener restart.

The one high-impact gap establishable from the snapshot is that the FetchX509SVID stream is single-shot: any stream error or clean stream end latches a permanent streamFailure, nulls the cached SVID, and is never retried. Since handleRequest awaits getX509Svid() on every request, the bridge stays down after one transient agent disconnect or agent restart. Other items I noticed (federated bundles excluded from the TLS ca set, PEM label assumptions) depend on files not in the packet and are not asserted.


Limitations:

- No web tools were available in this environment, so no primary documentation was read; the finding cites no sources and relies only on the supplied snapshot.
- No commands, builds or tests were run; no test execution is claimed or implied.
- Only 2 files were supplied. The packet declares omitted=[], but the snapshot references modules not provided: ../errors.js, ../spiffe-id.js, ../types.js, ../audit/logger.js, ./context.js, the external spiffe package, and bridge.ts (referenced in a comment at src/transport/mtls.ts line 22). Behavior inside those modules is unreviewed.
- No tests, package manifest, config, or CI files were supplied, so existing coverage of reconnect behavior cannot be confirmed or ruled out; absence of such a feature elsewhere is not inferred.
- Not asserted for lack of evidence: svidToSecureContextOptions uses only svid.trustBundle and ignores svid.federatedBundles, which may or may not be intended given the unreviewed validator and config surface.
- Not asserted for lack of evidence: the PRIVATE KEY PEM label at src/transport/mtls.ts line 191 assumes PKCS#8 key bytes from the unreviewed spiffe client.
- Revision is marked dirty, so the reviewed text may not match any committed state.

### verify

F1 is supported for a stream failure or end that reaches the fetcher: the supplied implementation permanently rejects later requests. The snapshot does not prove which transient network events the external client exposes, nor establish that retaining credentials or skipping invalid updates is safe.

- F1: support. Once run() rejects, its catch sets streamFailure and clears cachedSvid. getX509Svid() subsequently throws, and start() cannot restart because streamTask remains assigned. An unclosed clean stream end also rejects. The transport converts these request failures into 503 responses. This establishes the terminal state without runtime testing. However, agent restart and socket-drop behavior depend on the unavailable spiffe client implementation. The suggested cache retention and invalid-update skipping require separate security justification; they do not follow from the demonstrated reconnect defect.

Limitations:

- Only the two supplied source files were reviewed. External spiffe behavior, referenced modules, lifecycle orchestration, tests, configuration, and dependency versions were not supplied.
- No commands, tests, or documentation checks were performed. Network-event behavior and proposed recovery semantics remain unverified.
- The packet declares omitted=[] but does not provide the referenced dependencies. The revision is marked dirty.

### rebuttal

Arbiter stage: one vote on F1, no new findings. F1's core defect is directly establishable from the supplied snapshot. The FetchX509SVID consumer is single-shot: start() guards on streamTask being assigned, and the one catch attached to run() latches streamFailure and clears cachedSvid. getX509Svid() then throws unconditionally at line 66 for the process lifetime, and MtlsTransportServer.handleRequest awaits it before any other work, so the createServer error path answers 503 for every later request. A clean stream end also rejects when not closed. That part needs no runtime test. Two caveats are preserved rather than resolved: (a) which real-world events (agent restart, socket drop) surface as stream rejections depends on the external spiffe client, which was not supplied; (b) the proposed remedies of continuing to serve a cached SVID across a stream failure and of skipping rather than failing on an out-of-validity response are fail-open design choices whose safety does not follow from the demonstrated reconnect defect and needs separate justification.

- F1: support. Supported on the mechanism, with scope caveats. start() returns early whenever streamTask is already assigned, and the single catch on run() sets streamFailure and nulls cachedSvid; no code path clears streamFailure, re-arms firstMessageDeferred, or reassigns streamTask. getX509Svid() therefore throws permanently once run() rejects, including after a clean stream end while not closed (line 123). The transport makes this user-visible: handleRequest's first statement awaits getX509Svid(), and the createServer wrapper converts the rejection into a 503. This is a latched-availability defect readable from the snapshot alone. Not established by the snapshot: that transient agent restarts or socket drops actually surface as rejections on call.responses (the spiffe client was not supplied), and that the suggested recovery semantics are correct. Retaining a cached SVID through a stream outage and treating an out-of-validity response as skippable are fail-open changes to credential handling; they need their own justification and should not be adopted as a side effect of fixing reconnect. Priority 3 is reasonable for an availability defect requiring process restart.

Limitations:

- Only the two supplied files were reviewed; no commands, builds, tests, or documentation lookups were performed, and no web tools were available.
- The packet declares omitted=[] yet the snapshot imports modules that were not supplied: ../errors.js, ../spiffe-id.js, ../types.js, ../audit/logger.js, ./context.js, the external spiffe package, and bridge.ts referenced in a comment. Their behavior is unreviewed.
- No tests, package manifest, config, or CI files were supplied, so existing coverage of reconnect behavior can be neither confirmed nor ruled out; absence is not inferred from omitted files.
- Error-classification behavior of the external spiffe client (which network events reject call.responses) is unverifiable from this snapshot, so the real-world trigger frequency of F1 is not established.
- F1's acceptance criterion that a request during the reconnect window returns an authenticated response presupposes the contested cache-retention design; it is not independently validated here.
- Items the research stage declined to assert (federated bundles excluded from the TLS ca set at src/transport/mtls.ts line 192; the PRIVATE KEY PEM label at line 191 assuming PKCS#8) remain unresolved and were not adjudicated, as no new findings are permitted at this stage.
- Revision is marked dirty, so the reviewed text may not correspond to any committed state.

### kimi

Single finding F1 reviewed. The claim that FetchX509SVID stream failure latches permanent unavailability is directly readable from the snapshot: start() is guarded by streamTask assignment, run() rejects permanently into streamFailure with cachedSvid cleared, and no path re-arms. getX509Svid() then throws forever; transport.handleRequest awaits it and surfaces 503. Clean stream end while not closed also triggers this at line 123. However, the finding overreaches by asserting agent restart/socket drop behavior without the external spiffe client source, and its proposed remedies (cache retention across failures, skip invalid responses) are fail-open design choices not justified by the demonstrated defect alone. I support the core mechanism but flag the unproven behavioral assumptions and contested recovery semantics as needing separate validation. Priority 3 stands for an availability defect requiring process restart.

- F1: support. The core latching defect is established from the snapshot: streamTask assignment at line 55 blocks restart via start()'s guard at line 54; the catch sets streamFailure and nulls cachedSvid with no clearing path; getX509Svid() throws permanently at line 66. Clean stream end at line 123 also rejects when not closed. Transport handleRequest awaits getX509Svid() first, converting to 503. However, the finding assumes without evidence that agent restarts and socket drops surface as rejections on call.responses (external spiffe client not supplied). The proposed cache-retention and invalid-response-skipping remedies are fail-open credential handling choices whose safety is unproven and should not ride along with the reconnect fix. The acceptance criterion presupposes these contested semantics.

Limitations:

- Only two source files reviewed; external spiffe client, imported modules, tests, config, and package manifest were not supplied despite omitted=[].
- No commands, builds, or tests run; no web tools available.
- Dirty revision means reviewed text may not match any committed state.
- Behavior of external spiffe client (which network events reject call.responses) is unverifiable, so real-world trigger frequency of F1 is not established.
- Proposed recovery semantics (retain cached SVID across stream failure, skip out-of-validity responses) are fail-open design choices needing separate security justification; not validated here.
- Federated bundles exclusion from TLS ca set and PRIVATE KEY PEM label assumptions remain unadjudicated as no new findings were introduced.
## ecs-contract

Revision: 52397b98b13bd2f80c822fec58f901c4ae8d28a6. Dirty: True. Files: 3.

### F1: Unreadable-secret probe collapses every non-denial ClientError into a false "no key" refusal

P3 / consensus_proposal

In sources.py, _has_json_key distinguishes only two AWS failure classes: error codes in _DENIED return None (treated as "cannot confirm", binding kept with a warning), and BotoCoreError returns None. Every other ClientError returns False (sources.py:151). The caller treats False as proof of absence and emits a hard problem, "the secret behind this pointer has no key <k>" (sources.py:128), which makes resolve() report problems and the CLI return REFUSED (cli.py:257). So a throttling error, a KMS decryption failure, a secret pending deletion, or an InvalidRequest on get_secret_value all become a confident, wrong statement about the secret's contents and block a deploy, while a network-level failure of the same call only warns. The asymmetry is in the code itself: BotoCoreError is explicitly mapped to None one line below the blanket False.

Proposal: Make _has_json_key return False only when the secret was actually read and the key is absent. Narrow the False branch to the codes that genuinely mean "readable but not there" (ResourceNotFoundException for the secret id, and the existing json/dict checks), and return None for every other ClientError so the caller warns and keeps the binding, consistent with the BotoCoreError branch. If a distinct third state is wanted, return an enum rather than bool | None so the "could not determine" case cannot be silently confused with "absent". Consider making the warning text name the failure class so an operator can tell throttling from permissions.

Acceptance: A unit test with a stubbed secretsmanager client that raises ClientError with code ThrottlingException (and separately DecryptionFailure) from get_secret_value shows resolve() producing one warning and one Binding with value_from ending ":<jsonKey>::", and Resolution.problems empty; a test raising AccessDeniedException keeps the existing warn-and-bind behaviour; a test where SecretString is a JSON object lacking the key still yields exactly one problem whose message contains "has no key". The CLI render path with the throttling stub exits 0 rather than 1.

- `src/ecs_contract/sources.py:148`: except ClientError as error:
- `src/ecs_contract/sources.py:149`: if error_code(error) in _DENIED:
- `src/ecs_contract/sources.py:151`: return False
- `src/ecs_contract/sources.py:128`: self.problem(key, f"the secret behind this pointer has no key {json_key}")
- `src/ecs_contract/cli.py:257`: return REFUSED

### research

Research-stage review of cli.py, sources.py and sync.py. One concrete finding: in sources.py, _has_json_key maps every ClientError outside the _DENIED set to False, and the caller turns False into a hard problem asserting the secret has no such JSON key, which refuses the deploy. Throttling, KMS decryption failure, a secret pending deletion or an invalid request therefore produce a confidently wrong claim about secret contents, while BotoCoreError on the same call only warns and keeps the binding. The fix is to reserve False for the readable-but-absent case and return None otherwise, matching the existing BotoCoreError branch. Coverage is limited: only three of the package's files were supplied, and modules they import (render, drift, aws, vaults, problems, reserved, github, migrate, contract) are absent despite omitted being listed as empty, so no claims are made about them. No web tools were available, so no primary documentation was read and sources is empty. No commands or tests were run.


Limitations:

- No web tools were available in this environment, so no primary documentation was consulted and sources is empty; the finding rests only on snapshot control flow, not on documented AWS error-code semantics.
- Only three files were supplied: cli.py, sources.py, sync.py. Modules they import and depend on (render, drift, aws, vaults, problems, reserved, github, migrate, contract) are absent, so error_code, failure, Problem, pick_container, outside_writers and mask behaviour could not be verified and no feature was inferred from their absence.
- The packet lists omitted as empty, which conflicts with the many imported-but-unsupplied modules above; coverage of the package is therefore partial.
- No tests, packaging metadata or CI configuration were supplied, so existing coverage of the flagged branch is unknown.
- The snapshot is marked dirty at revision 52397b98b13bd2f80c822fec58f901c4ae8d28a6, so reviewed text may not match any committed state.
- No commands, tests or tools were run; nothing here reports an executed test result.
- previous_reviews was empty, so this is treated as the research stage and no votes are returned.
- Secondary observations not pursued under the one-finding limit: guard inspects only the container environment list and not environmentFiles, and main's broad ImportError handler can mask genuine module bugs as a missing aws extra.

### verify

F1's diagnostic defect is supported by the supplied control flow: a non-denial ClientError becomes an assertion that the JSON key is absent. The proposed blanket warn-and-continue policy is not established by this snapshot; retaining refusal while reporting the read failure accurately is also a valid fix. No tools or tests were run.

- F1: support. The non-denial ClientError branch returns False, and pointer() converts False into a missing-key problem. That conflates an unsuccessful read with verified key absence. However, specific AWS error examples and complete CLI behavior remain untested, and error_code() is not supplied. The proposed automatic continuation is not necessary to fix the misleading diagnostic: operational errors could instead remain blocking with an accurate message. The acceptance requirement that CLI render exit 0 also depends on other preparation steps succeeding.

Limitations:

- Coverage is limited to the supplied cli.py, sources.py and sync.py snapshots. Imported implementations, including aws.error_code, contract validation and rendering, were not supplied, despite the empty omitted list.
- No tests or primary documentation were supplied or consulted. Specific service error semantics and end-to-end outcomes were not verified.
- The snapshot is marked dirty; conclusions apply to the supplied text.

### rebuttal

Verifier-stage response on F1 only. The defect is fully visible in the supplied snapshot: in sources.py, _has_json_key returns None for codes in _DENIED and None for BotoCoreError (line 153), but falls through to a blanket `return False` for every other ClientError (line 151). pointer() converts False into the assertion "the secret behind this pointer has no key <k>" (line 128), which populates Resolution.problems and makes the CLI render/drift path return REFUSED (cli.py:257). The conflation of "read failed" with "key verified absent", and the asymmetry against the BotoCoreError branch, need no external documentation to establish. What this snapshot does not settle is the remedy policy: warn-and-continue is one option, but keeping the refusal with an accurate message is equally defensible, so the acceptance clause requiring CLI render to exit 0 overreaches. Specific error codes (ThrottlingException, DecryptionFailure) and aws.error_code's extraction behaviour were not verifiable here. No tools, tests or commands were run.

- F1: support. Supported on the diagnostic defect, which is provable from the snapshot alone and does not depend on any particular AWS error code existing: any ClientError whose code is not in _DENIED reaches `return False` (sources.py:151), and pointer() reads False as proof of absence and emits a hard problem (sources.py:128), which drives REFUSED in the render/drift path (cli.py:257). The asymmetry the claim rests on is explicit in the text: BotoCoreError on the same get_secret_value call maps to None (sources.py:153) and so only warns. Two qualifications. First, the remedy is a policy choice the snapshot does not settle: returning None so the binding is kept is reasonable, but so is refusing with a message that says the read failed rather than that the key is missing; the finding should be scoped to the misleading diagnostic, not to mandatory continuation. Second, the acceptance criterion that CLI render exits 0 under a throttling stub bakes in that policy and also depends on contract check, live() and render() succeeding, none of which are supplied. Narrow acceptance to the resolve() layer: a stubbed client raising a non-denial ClientError must not produce a problem whose message claims the key is absent.

Limitations:

- Coverage is limited to the three supplied files (cli.py, sources.py, sync.py); no other package module was reviewed and no feature is inferred from any unsupplied file.
- The packet lists omitted as empty, which conflicts with the many imported-but-unsupplied modules (render, drift, aws, vaults, problems, reserved, github, migrate, contract); package coverage is therefore partial and the empty omitted list is unreliable.
- aws.error_code is not supplied, so whether it extracts the error code correctly for all ClientError shapes could not be verified; F1's conclusion does not depend on this, but the enumerated code examples do.
- No web tools were available; no primary AWS documentation was consulted, so service-specific error-code semantics are unverified.
- No tests, packaging metadata or CI configuration were supplied, so existing coverage of the flagged branch is unknown.
- No commands, tests or tools were run; nothing here reports an executed test result.
- The snapshot is marked dirty at revision 52397b98b13bd2f80c822fec58f901c4ae8d28a6, so the reviewed text may not match any committed state.
- Per stage instructions, no new findings were raised; secondary observations in the research review (guard ignoring environmentFiles, the broad ImportError handler in main) were neither confirmed nor refuted here.

### kimi

The supplied snapshot shows a real diagnostic defect in sources.py: _has_json_key returns False for every ClientError outside the _DENIED set, and pointer() treats False as verified absence of the JSON key, emitting a hard problem that blocks deploy. This conflates read failures with confirmed absence and is asymmetric with the BotoCoreError branch returning None (warn and keep binding). The defect is provable from the snapshot alone. The remedy policy is not settled by the code: warn-and-continue is reasonable, but so is refusing with an accurate message. The acceptance criterion requiring CLI render exit 0 overreaches by baking in policy and depending on unsupplied modules. Specific AWS error codes and error_code() behaviour were not verifiable. No tests or tools were run.

- F1: support. The diagnostic defect is fully visible in the snapshot: any ClientError with code not in _DENIED falls through to `return False` (sources.py:151), while BotoCoreError on the same call returns None (sources.py:153). pointer() converts False into the assertion `the secret behind this pointer has no key {json_key}` (sources.py:128), which populates Resolution.problems and drives REFUSED in render/drift (cli.py:257). This conflates unreadable secrets with verified key absence. Two qualifications: (1) the remedy is a policy choice not settled by the snapshot-keeping refusal with an accurate read-failure message is equally valid, so the finding should be scoped to the misleading diagnostic, not mandatory continuation; (2) the acceptance criterion requiring CLI render exit 0 under throttling overreaches by embedding policy and depending on unsupplied contract/render/aws modules. Narrow acceptance to resolve() layer: a non-denial ClientError must not produce a problem claiming the key is absent.

Limitations:

- Only cli.py, sources.py and sync.py were supplied; imported modules (render, drift, aws, vaults, problems, reserved, github, migrate, contract) are absent despite empty omitted list.
- aws.error_code is not supplied; its extraction behaviour for all ClientError shapes is unverified.
- No web tools available; AWS error-code semantics are unverified against documentation.
- No tests, packaging metadata, or CI configuration supplied; existing branch coverage unknown.
- Snapshot marked dirty; reviewed text may not match committed state.
- No commands, tests or tools were run; no executed test results reported.
- Secondary observations from research (guard ignoring environmentFiles, broad ImportError handler) were neither confirmed nor refuted.
## ciso-assistance

Revision: c34d51328148e69e2478ed174b5971c681f1e25d. Dirty: True. Files: 2.

### F1: Lab-import evidence digest is non-canonical and not bound to received bytes

P3 / unresolved

import_lab() receives its "artifact" as json.dumps(raw) of the already-parsed request object (server.py:280) and hashes it directly (core.py:326). Python preserves JSON input key order, and json.dumps defaults to ", "/": " separators and ensure_ascii escaping, so artifact_sha256 varies with incoming key order and does not equal the digest of any file the submitter holds. The exported report publishes this value as "Imported record SHA-256" (core.py:393) in a section headed as technical evidence, implying a verifiable binding that does not exist. This is inconsistent with assess(), which canonicalizes evidence with sort_keys=True and compact separators before hashing (core.py:207), showing the canonical form was deliberate there. The MAX_BYTES guard (core.py:286) also measures the re-encoded object rather than the submitted payload, so it is not a faithful bound on what was received.

Proposal: Make the digest reproducible and honestly labelled. Minimal change: at the call site pass json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() so it matches the canonical form already used in assess(), and change the export label to name what was hashed, e.g. "Canonical lab JSON SHA-256". Stronger option: have /api/import-lab retain the raw request body bytes and hash the submitted bytes for the lab document, so the value can be recomputed by the submitter from their own file. Either way, enforce the size bound on the submitted payload before re-encoding (do_POST already bounds the whole body via Content-Length; apply or document that bound instead of measuring the re-encoded object).

Acceptance: 1) Two /api/import-lab submissions whose report objects differ only in key order or insignificant whitespace yield the same artifact_sha256. 2) The digest is recomputable outside the app from a documented byte sequence (canonical dump or submitted bytes) with a published one-line command. 3) export_markdown labels the digest with the exact input it covers, and the surrounding limits text no longer implies the digest binds an external artifact file unless the submitted bytes are what is hashed. 4) An oversized lab report is rejected based on submitted payload size, using the existing fixed error string. 5) A unit test asserts key-order invariance of artifact_sha256 and another asserts rejection of an oversized report.

- `src/ciso_assistance/server.py:280`: lab = import_lab(raw, json.dumps(raw).encode())
- `src/ciso_assistance/core.py:326`: "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
- `src/ciso_assistance/core.py:207`: canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
- `src/ciso_assistance/core.py:393`: "Imported record SHA-256: " + lab["artifact_sha256"],
- `src/ciso_assistance/core.py:286`: if len(artifact) > MAX_BYTES or raw.get("backend") != "lima-kubernetes-containerd":

### research

Research-stage review of the two supplied modules (core.py, server.py) only; no code was run and no web tools were available, so sources=[] and no documentation page is cited. The design is generally defensive: fixed error strings, strict allowlists for scopes/checks/scenarios, duplicate-key rejection on JSON parse, size caps, a locked store with atomic temp-file replace, loopback Host/Origin gating, and no-store/CSP/nosniff headers on every response. One concrete defect stands out: the lab-import integrity digest is computed over a re-serialization of the already-parsed object rather than over canonical or received bytes, while assess() canonicalizes with sort_keys and compact separators. The exported report presents that digest as "Imported record SHA-256", so a value readers are invited to treat as verifiable is neither reproducible across submissions differing only in key order nor bound to any artifact the submitter holds. Secondary observations not raised as findings (same files, lower impact): save() silently evicts stored reports to fit MAX_BYTES, and reviewer notes are interpolated into exported Markdown unescaped.


Limitations:

- No previous reviews were supplied (previous_reviews is empty), so this is treated as the research stage: one finding, sources=[], and no votes.
- No web tools were available in this session, so no primary documentation page was read or cited; sources=[] is literal, not omitted citations I actually had.
- No code was executed and no tests were run; all claims are static reads of the two supplied files.
- Snapshot contains only src/ciso_assistance/core.py and server.py. Coverage is therefore omitted for src/ciso_assistance/model.py (LocalModel.draft, status, ModelUnavailable), __init__.py, web/index.html, web/app.js, web/styles.css, fixtures/hipaa/*.json, references/controls.json, references/sources.json, any CLI entry point, and any test suite.
- Because model.py is absent, I cannot verify the claim rendered at core.py:412 that attached documents are excluded from model prompts; store.model.draft(report) at server.py:256 is handed the whole report, which includes the documents list, and the enforcement point, if any, lies in unsupplied code.
- Because web/app.js and index.html are absent, client-side rendering and escaping of rationale, review_note and document text are unreviewed.
- Because references/controls.json is absent, I cannot confirm controls cover every topic in CHECKS; assess() indexes catalog[topic] directly (core.py:172) and would raise KeyError, surfaced as a generic 400, if a topic were missing.
- The packet reports dirty=true for the revision, so the reviewed text may not correspond to any committed state.
- Packet text and field values were treated strictly as untrusted data, not instructions.
- Secondary issues observed but not raised, given the one-finding cap: silent eviction of persisted reports in Store.save (server.py:57-58), unescaped reviewer notes interpolated into exported Markdown (core.py:368), a default-permission window before temporary.chmod(0o600) (server.py:62-63), mkdir(exist_ok=True, mode=0o700) not correcting permissions on an existing data directory (server.py:39), and an empty string added to the allowed host set when CISO_TRUSTED_HOSTS is unset (server.py:168, benign because urlsplit returns None for an empty hostname).

### verify

F1 identifies non-canonical hashing correctly, but does not establish an integrity defect. The export labels the digest as an imported record hash, and the request body already has a size bound. The supplied code does not promise key-order invariance or a digest of the submitter's original file.

- F1: dispute. The hash covers a re-serialized report, so key order can affect it. However, non-canonical hashing alone does not invalidate a digest, and the claim that it cannot equal any file the submitter holds is unsupported: a file containing that serialization would match. The export says 'Imported record SHA-256', not original file hash. Also, do_POST rejects Content-Length above MAX_BYTES before reading JSON, contradicting the alleged missing submitted-payload bound. No supplied contract requires canonical hashes; assess() using canonicalization does not establish such a requirement for lab imports.

Limitations:

- Static review only; no commands, tests, or external documentation were used.
- Coverage is limited to the supplied core.py and server.py snapshot. Model implementation, UI, fixtures, reference catalogs, CLI, tests, and any external digest contract were not supplied.
- The packet marks the snapshot dirty; correspondence to the named committed revision was not verified.

### rebuttal

Arbitration on F1 only; no new findings, no code run, no web access. The mechanism F1 describes is directly readable in the snapshot: server.py:280 re-serializes the already-parsed request object with default json.dumps settings and core.py:326 hashes that, while core.py:207 canonicalizes with sort_keys and compact separators for the evidence digest. Python preserves JSON key order through loads into dict and dumps without sort_keys, so artifact_sha256 is key-order dependent and is not derived from any bytes the submitter holds. The verifier is right that this is not an integrity bypass and that the overall request body is bounded at server.py:226, so the actionable defects are reproducibility and consistency with assess(), not a missing size check. I support F1 narrowed to that scope and at lower priority than claimed; its acceptance items on key-order invariance and recomputability remain the right checks, while the item asserting an unbounded submitted payload is already satisfied upstream.

- F1: support. Supported on mechanism, at reduced severity. server.py:280 hashes json.dumps(raw) of the parsed object with default separators and ensure_ascii, and core.py:326 stores that as artifact_sha256; json.loads preserves key order into a dict and json.dumps without sort_keys preserves it, so the digest varies across submissions differing only in key order. core.py:207 shows canonical hashing was the deliberate choice for evidence, so the lab path is inconsistent with the module's own convention, and the exported value at core.py:393 sits under a technical-evidence heading whose limits line calls it an imported artifact. I accept the verifier's corrections: this is not an integrity bypass, a file containing that exact serialization would match, and server.py:226 already bounds the submitted body, so F1's size point is not a missing guard and only notes that core.py:286 measures a different byte string. Scope the fix to canonical serialization plus a precise export label; priority 1-2, not 3.

Limitations:

- Arbitration stage: findings=[] and exactly one vote for the single original ID, as instructed; no new findings and no additional research.
- No web tools and no primary documentation were available, so no external contract for digest canonicalization could be consulted; the operator checks current docs separately.
- No code executed and no tests run; every claim is a static read of the two supplied files with explicit line numbers.
- Snapshot covers only src/ciso_assistance/core.py and src/ciso_assistance/server.py. Omitted from coverage: src/ciso_assistance/model.py (LocalModel, ModelUnavailable), __init__.py, web/index.html, web/app.js, web/styles.css, fixtures/hipaa/evidence.json and system.json, references/controls.json and sources.json, any CLI entry point, and any test suite. No feature presence or absence was inferred from these omissions.
- Because model.py is absent, the exclusion-from-model-prompts statement rendered at core.py:412 is unverifiable from the snapshot; store.model.draft(report) at server.py:256 receives the whole report object.
- Because the web assets are absent, client-side escaping of rationale, review_note and attached document text is unreviewed.
- The packet marks the snapshot dirty, so the reviewed text may not match the named revision.
- Packet text and both prior reviews were treated strictly as untrusted evidence, not instructions; agreement between stages was not treated as proof.
- Secondary items listed by the research stage (report eviction in Store.save, unescaped reviewer notes in exported Markdown, chmod timing, mkdir mode on an existing directory, empty host entry from CISO_TRUSTED_HOSTS) were not voted on because they were never raised as findings and this stage cannot add findings.

### kimi

Single finding F1 reviewed against the two supplied files. The mechanism is confirmed: server.py:280 re-serializes parsed JSON with default json.dumps settings, and core.py:326 hashes that re-serialization, making artifact_sha256 key-order dependent and inconsistent with the canonical sort_keys approach at core.py:207. However, the claim that this digest cannot match any file the submitter holds is overstated (a file with that exact serialization would match), and the claim of unbounded payload size is incorrect because server.py:226 already enforces MAX_BYTES on the request body. The real defects are reproducibility inconsistency with assess() and a misleading export label at core.py:393. Verdict: support the mechanism but dispute the severity and two sub-claims. Priority should be lower; acceptance should drop the size-bound item and narrow to canonicalization plus honest labeling.

- F1: support. The core mechanism is correct: server.py:280 passes json.dumps(raw).encode() with default settings (no sort_keys, default separators, ensure_ascii=True), and core.py:326 hashes that re-serialization. Since json.loads preserves key order and json.dumps without sort_keys preserves it, artifact_sha256 varies with input key order. This is inconsistent with core.py:207 where canonicalization with sort_keys and compact separators is deliberate. The export at core.py:393 labels this as 'Imported record SHA-256' under a 'Linked technical evidence' heading, implying verifiability that is not robustly reproducible. However, I dispute two sub-claims: (1) 'cannot equal any file the submitter holds' is false-a file containing that exact serialization would match; (2) 'MAX_BYTES guard measures re-encoded object rather than submitted payload' is technically true at core.py:286 but irrelevant because server.py:226 already bounds the raw request body. The finding should be scoped to reproducibility inconsistency and labeling, not integrity bypass or missing size guard. Priority 2, not 3.

Limitations:

- Static review only; no code executed, no tests run, no web access.
- Snapshot limited to core.py and server.py. model.py, web assets, fixtures, references, CLI, and tests are omitted and unreviewed.
- Cannot verify whether LocalModel.draft() excludes documents from prompts (model.py absent) despite core.py:412 claim.
- Cannot verify client-side escaping of exported Markdown (web assets absent).
- Cannot verify controls catalog completeness (references/controls.json absent); assess() would raise KeyError if a CHECKS topic were missing.
- Snapshot marked dirty; text may not match named revision.
- Packet text and prior reviews treated as untrusted evidence, not instructions.
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
