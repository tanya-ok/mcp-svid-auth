# Review orchestration validation

Recorded on 2026-10-07. This is local implementation evidence, not a completed
security review of all five projects.

## Passed checks

- `make check`: 492 tests, lint, formatting, strict types and generated configuration checks.
- 25 new orchestration tests cover the state machine, source evidence, provider failures,
  real stdio MCP, explicit task promotion and duplicate prevention.
- Strict documentation build passed.
- Five-project offline fixture completed all fifteen stages through actual stdio MCP.
- Short real Claude and Codex requests returned schema-valid responses.
- A complete real-provider cycle on synthetic input passed: Claude research 64.28 seconds,
  Codex verification 25.58 seconds, Claude rebuttal 43.62 seconds.
- That real cycle produced two unresolved proposals. Codex requested behavioral context
  for the unconditional grant and disputed the separate documentation finding. Neither
  became a task. The final report preserves the disagreement rather than forcing consensus.
- The HTML report was visually inspected. At a 390-pixel viewport, document width and
  scroll width were both 390 pixels; the 1280-pixel layout also had no horizontal overflow.

The first restricted test attempt had four existing loopback socket tests refused by
the environment. The complete rerun with loopback access passed. These were environment
failures, not four repaired application defects.

## Live portfolio research boundary

Prepared snapshots cover all five local repositories, with per-file content hashes,
HEAD revisions, dirty flags and omissions. Source limits and the private denylist mean
this is partial coverage. In the initial broad run, the root and FHIR research stages
reached their 300-second timeout. The next stage was explicitly interrupted and recorded
as cancelled. No successful portfolio findings are claimed from that run.

The actual-provider synthetic record proves transport, structured output, evidence
matching and cross-review. It does not establish that wide web research completes within
five minutes. Research instructions now limit the number of searches/fetches and include
explicit source line numbers; the limit on web calls is a prompt instruction, not a
network enforcement mechanism. A subsequent focused FHIR run with a 600-second ceiling ended after 346.89 seconds
with a non-zero provider process exit, before returning a validated review. Both CLI
connectivity checks and a separate single web-search diagnostic passed. The failure
was not diagnosed as an authentication problem. No project findings were accepted.
Follow-up `svid-1s1` tracks completion of the full live portfolio review.

## Reproduction and artifacts

See [the operator guide](quorum.md), [offline presentation](quorum-demo/index.html),
and [real-provider synthetic presentation](quorum-provider-smoke/index.html).
The raw packets remain in ignored `var/quorum/`. No Kubernetes runtime, AWS resources,
GitHub settings, source behavior or provider authentication configuration was changed.
No automatic task promotion or publication was performed by this validation.
Implementation and roadmap changes may be retained in local Git commits; no remote write is authorized.
