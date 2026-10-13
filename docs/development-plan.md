# Development plan for mcp-svid-auth

The publication milestone makes this project a small, inspectable reference for SPIFFE to OAuth authentication with MCP. Its deliverable is a verified proof of concept, not production deployment.

## Publication milestone

| Requirement from the 2026-10-04 review | Implemented evidence |
|---|---|
| Machine-checked failure demos | All 18 shared Kubernetes scenarios require expected exits and outcomes; safe local verdict report; tests that the checker rejects missing or wrong evidence |
| Profile compatibility | [Compatibility matrix](compatibility.md), draft deviations stated explicitly, independently exercised TypeScript SDK 1.32.1 with a JWT-SVID adapter |
| Cached SVID operation | Live reuse and strict-mode comparison; repeated exchanges through actual SVID expiry, renewed credential and expired-assertion denial |
| Address-bound URL protection | Numeric connection to policy-checked addresses, original Host and TLS server name, separate origin pools, proxy environment disabled; actual TLS test |
| Audit completeness boundary | [Terminal checkpoints](audit.md), suffix deletion and chain replacement tests; protected-storage trust assumption stated explicitly |
| Publication artifact validation | Wheel and source archive checks, license and checksums, installed console-script smoke checks, strict documentation build and privacy/security scans |

[Publication validation](publication.md) records which checks actually ran. The original review snapshot was local commit `ec9ba13`, with 196 tests and a previously recorded September SPIRE run; it is historical evidence, not the result of this milestone.

## Shared CNCF lab, 2026-10-06

The default runtime is a dedicated 2 CPU / 4 GiB Lima VM running k3s Kubernetes and containerd. SPIRE verifies namespace/ServiceAccount identities; the copied-label impostor is denied. The shared FHIR gateway loads `mcp-spiffe-bridge`, requires real mTLS and a matching resource-bound OAuth token, and reuses the synthetic `hipaa-fhir-mcp` tools. All eighteen scenarios and teardown passed. A detached, read-only Headlamp viewer shows nine ready services and recovers through a verified repeated start after a crashed session.

The older 2 CPU / 2 GiB Podman demo and its label-impersonation weakness were retired on 2026-10-13; containerd is the only lab runtime. The selected ZITADEL profile is the approved exception to the CNCF-only platform preference; synthetic passwordless acceptance passed, while real Google and physical passkey enrollment remain operator gates. See the [shared architecture and next increments](portfolio-development-plan.md), [Kubernetes lab](kubernetes-lab.md) and [Headlamp interface](headlamp-ui.md).

## Deliberate remaining limits

The Kubernetes lab denies copied labels, but trusts the cluster operator and anyone permitted to use an authorized ServiceAccount. SPIRE 1.15.3 re-serves cached SVIDs, so the normal demo explicitly permits reuse; the default server mode still rejects repeated assertions. Existing access tokens survive grant removal until expiry. Planned signing key rotation keeps an overlap period, but a restart still loses old keys. Scope checks do not determine human intent or clinical authority.

The authorization server's Workload API bundle lookup is a local-demo alternative discouraged for general interoperability by draft -02. The TypeScript test proves the explicit adapter, not generic SDK support for `spiffe_jwt`. A colocated checkpoint supplies no independent protection. These limits are part of the demonstration, not hidden future completion requirements.

## Separate future milestones

| Priority | Extension | Acceptance criterion |
|---|---|---|
| P1 | Complete real operator enrollment | Synthetic human sign-in passed; independently verify real Google linking and physical passkey enrollment |
| P1 | Stronger Kubernetes admission | The policy restricts who can launch a workload using an authorized ServiceAccount; copied-label denial remains covered |
| P2 | Planned signing key rotation and request budgets | Done on 2026-10-07, see [cost budgets and planned signing rotation](auth-cost-rotation.md). Old public verification keys survive until old tokens expire; invalid-token bursts and token requests have bounded cost |
| P2 | General SPIFFE profile integration | Trusted bundle publication and client registration match a selected draft revision; interoperability exercised against an independently operated implementation |
| P3 | Delegation | A newly issued, bounded upstream credential represents the original subject and acting workload; no incoming token passthrough |

Keep these separate from publication of the reference demo. Existing public backlog entries already cover the SPIRE cache report, delegation and Kubernetes variant. No upstream issue, release or deployment is authorized by this milestone.

## Task tracking checkpoint

The [2026-10-07 portfolio checkpoint](portfolio-checkpoint-2026-10-07.md) reconciles this plan with local beads tasks. Use `bd --sandbox ready` before starting work and update task status and validation evidence as work progresses. Public task snapshots are in `.beads/issues.jsonl`; local databases stay untracked. Remote synchronization is disabled.
