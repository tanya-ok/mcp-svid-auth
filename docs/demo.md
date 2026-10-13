# Checked SPIRE demo

```sh
uv sync --locked
make runtime-up
make demo
make down
make runtime-stop
```

Use a fresh demo stack in the dedicated CNCF Lima Kubernetes/containerd VM. The script refuses existing lab namespaces instead of resetting them. `make down` removes only resources with the demo ownership label, including SPIRE runtime volumes. Stop the VM after teardown to release CPU and memory. The generated report and captures remain in ignored `deploy/.data/`.

The demo registers seven workload entries in the `example.org` trust domain using Kubernetes namespace and ServiceAccount selectors. JWT-SVID lifetime is **60 seconds** so renewal and expiry can be observed quickly; the authorization server's maximum remains **300 seconds**, and access tokens last **300 seconds**. The run usually takes a few minutes, including a wait past the initial SVID's expiry plus 30 seconds of validation leeway. No ports are published to the host.

`authz` explicitly accepts cached JWT-SVID reuse. A second issuer, `authz-strict`, keeps the default single-use mode. Both use runtime keys and trusted bundles from the real SPIRE Workload API. The rogue resource names an untrusted issuer.

## Assertions

Every step must have the expected process exit and structured outcome. Missing output, unexpected success and unexpected denial fail the run. The script restores the mounted policy even on failure and writes a safe verdict report. Captured command output and credentials are not copied into it.

| # | Demonstration | Required result |
|---|---|---|
| 1 | Allowlisted research workload on notes-a | Read and write succeed with the requested scopes |
| 2 | Read-only token on notes-b | Read succeeds; write receives 403 `insufficient_scope` |
| 3 | Intruder with a valid SVID | Token endpoint denies `unauthorized_client` |
| 4 | Token for notes-a replayed to notes-b | Both calls receive 401; audit records `InvalidAudienceError` |
| 5 | Another pod copies the research label using its own ServiceAccount | It receives the intruder identity and is denied an OAuth token |
| 6 | Rogue resource names an untrusted issuer | Client emits `issuer_refused`, before fetching an SVID for that issuer |
| 7 | One cached SVID submitted twice to the reuse-mode issuer | Both exchanges succeed; this is an explicit residual risk |
| 8 | notes-a calls notes-b | Downstream audit identifies `mcp/notes-a`. Offline tests additionally capture every outbound credential and prove the incoming token never leaves |
| 9 | Remove the research workload's notes-b grant at runtime | A new token request receives `invalid_target` within the bounded reload wait |
| 10 | Deterministic write request representing an injected instruction | Read-only grant denies it; read-write grant allows it. Identity cannot establish whether a permitted action is intended |
| 11 | Restart authz while notes-a has cached verification keys | New signing key is accepted through unknown-`kid` refetch |
| 12 | Continue exchanges past the first SVID's expiry | A renewed SVID produces a usable token; the original assertion receives 401 after expiry and leeway |
| 13 | One SVID submitted twice to the strict issuer | First exchange succeeds; second receives 401 `invalid_client` and no token |
| 14 | Verify both tool audit chains and test suffix deletion | Complete captures verify; removing the last line fails against the saved terminal checkpoint |

The first eleven numbers preserve the threat-model scenario numbering. Scenario 10 models the authority boundary without an LLM, so its result is deterministic. The last three extend the publication evidence.

## Local evidence

`deploy/.data/demo-report.json` contains timestamp, SPIRE version, configured SVID lifetime, per-scenario verdicts and overall pass/fail. `notes-a.jsonl`, `notes-b.jsonl` and their checkpoint files hold synthetic audit captures. These files are ignored and are never publication inputs. The operator must separately protect checkpoints to establish audit completeness; see [Audit integrity](audit.md).

The published validation summary records actual execution results in [Publication validation](publication.md). The independent TypeScript client uses a local runtime-key harness, separately from this SPIRE demo; see [Compatibility](compatibility.md).

## Offline evidence

| Tests | Boundary |
|---|---|
| `test_end_to_end.py`, `test_resource_server.py` | Discovery, allowlisted access, audience isolation including multiple audiences, per-tool scope, malformed and oversized bodies, undeclared tool startup failure |
| `test_authz.py`, `test_authz_hardening.py`, `test_authz_replay.py` | SVID signature, audience, lifetime, fixed errors, grants and bounded replay cache |
| `test_no_passthrough.py` | Every outbound request captured; caller credential never forwarded |
| `test_policy_reload.py`, `test_jwks_fetcher.py` | Revocation, invalid-policy fail closed, asynchronous key refresh and its request bound |
| `test_stdio_wrapper.py`, `test_token_expiry.py` | Owner-only file, refresh, cleanup, child stop on expiry and recheck before a side effect |
| `test_url_policy.py`, `test_issuer_allowlist.py`, `test_pinned_transport.py` | Issuer trust, SSRF checks, changed DNS answer refused at dispatch, original TLS hostname actually verified, distinct origin pools and proxy bypass prevention |
| `test_audit_chain.py` | Schema, links, broken-chain resume refusal, terminal edits, suffix deletion and complete chain rewrite against a trusted checkpoint |
| `test_demo_contract.py` | Unexpected process exit, missing evidence and wrong outcomes cannot become a passing demo |
| `test_no_identifiers.py` | Working tree and full-history privacy scan |

## Shared FHIR integration

The default lab also asserts scenarios 15-18: three FHIR tools through real SPIRE
mTLS and resource-bound OAuth, malformed/unknown request rejection, denied
intruder identity, rejected missing client certificate and FHIR audit validation.
See [shared Kubernetes lab](kubernetes-lab.md). The Podman compatibility path was retired on 2026-10-13.
