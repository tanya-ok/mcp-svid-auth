# Proposed AI Assurance profile

**Pending maintainer review. No installation or execution evidence is included.**

Scope: Offline OAuth resource/scopes, credential lifecycle and audit regressions; no live identity or deployment attestation.

Prepared base: `89878526aad4dec490b98aaf68d3af17e80a09bd`.
This base revision is not published; verify its remote availability before opening.
Candidate source: AI Assurance 0.2.1, commit
`353d374a00b43479870a6dee300dd200529cc60c`, verified locally against an immutable Git bundle.
This source revision is not published; remote availability must be checked before adoption.
The source checkout and CLI must be trusted separately from a target lock.

| Control | Proposed bounded claim | Existing evidence surface |
|---|---|---|
| access-boundary | Access tokens stay audience-bound and tools enforce declared scopes. | `tests/test_authz.py`, `tests/test_resource_server.py` |
| data-exposure | Credential and token errors do not expose secrets; audit output stays bounded. | `tests/test_authz_hardening.py`, `tests/test_audit_chain.py` |
| untrusted-instructions | Text from a caller cannot add a tool scope or authorize incoming-token forwarding. | `tests/test_no_passthrough.py`, `tests/test_resource_server.py` |
| consequential-actions | An unavailable refresh fails closed and stops the stdio child. | `tests/test_stdio_wrapper.py` |
| evidence-lineage | Audit changes are detected relative to a separately trusted terminal checkpoint. | `tests/test_audit_chain.py` |
| bounded-claims | Publication excludes local assurance state and does not imply live lab or physical-passkey validation. | `tests/test_distribution.py`, `README.md`, `docs/security.md` |

CI workflow: `.github/workflows/ci.yml`. Candidate checks: `check (3.12)`, `check (3.13)`.
These names come from workflow definitions. Before accepting records, match the
actual provider job names, exact project commit, completed job conclusion and
run URL. A CI suite's success is coarse evidence; it cannot establish untested
claims or substitute for review of individual test coverage.

All six controls are proposed for scoped review, with missing proof retained as
`not_verified`. This is not an accepted applicability decision. Only a maintainer
may approve or change applicability. Any future exclusion needs rationale and
`decided_by`. Agents must not manufacture executed records or approve exclusions.

CI has no live shared Kubernetes or physical-passkey proof. Semantic prompt injection and continuous human-session revocation need separate evaluations.

## Adoption gate

1. Review claims and approve the project-specific profile; keep limitations.
2. Use a trusted collector to select real CI evidence for an existing full
   40-hex project commit, a non-future timestamp, and a run URL or artifact hash.
   The current installer also requires publicly verifiable GitHub run/job metadata.
3. Keep records outside this proposal until independently collected. There are
   no empty evidence arrays or fabricated execution outcomes here.
4. Obtain explicit installation approval. Then use the separately reviewed CLI,
   source commit and approved candidate. Do not install by copying this directory.

`proposal.json` is a review envelope, deliberately not an installer input.
No `.ai-assurance/` directory, managed AGENTS block, workflow, dependency, tracker
integration or model call is added. No publication, deployment or certification
is implied. Linear and other trackers remain optional adapters.
