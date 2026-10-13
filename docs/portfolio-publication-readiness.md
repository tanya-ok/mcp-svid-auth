# Portfolio publication and live demonstration

Preparation started on 2026-10-07 after the 13 quorum implementation tasks
completed. This is a separate acceptance gate. A closed implementation issue,
a unit test or a generated website is not proof of publication readiness.
All repository commits and builds remain local.

## Acceptance criteria

Every project needs all of the following:

1. A clean checkout installs with its documented runtime and locked dependencies.
2. The distributable contains the intended source, license and runtime files,
   with no private state, credentials, local tracker database or private notes.
3. A runnable demonstration shows the actual application, its important negative
   case and its cleanup/recovery behavior. Simulation and real execution are
   labelled separately. Retained evidence names revision, environment and date.
4. Repository-specific checks and privacy/secret gates pass for the final tree.
5. Zensical documentation builds strictly, renders correctly and provides a
   complete path from installation to demonstration, architecture and limits.
6. A least-privilege GitHub Pages workflow is prepared. Remote CI and the public
   URL can only be verified after a separately authorized publication.

## Dated project gates

The baseline below was checked on 2026-10-07. The 2026-10-12 follow-up section
records subsequent package and workflow verification; it is not a rerun of every
original acceptance check.

| Project | Beads | Verified locally | Remaining gate |
|---|---|---|---|
| mcp-svid-auth | svid-mng | Clean locked checkout; inspected wheel/sdist; all five installed commands; complete audit accepted and tail deletion refused; 535 offline tests | Optional real Google and physical passkey evidence remains separate |
| hipaa-fhir-mcp | fhir-c90 | Independently installed archive; actual stdio tools against verified synthetic HTTPS; eight invocations and eight minimized audit outcomes; 51 tests, types, build, Biome and PHI sweep | Native Desktop installation is unverified; the retained shared-lab run predates the SDK update; clinical SMART/KMS remain explicit gaps |
| mcp-spiffe-bridge | bridge-l34 | Declared Apache-2.0 license present; 79 tests, real gRPC/TLS lifecycle checks and installed-package TLS demo; retained SPIRE gateway demonstration | Not published yet; publication is a separate maintainer decision |
| ecs-contract | ecsc-4iv | Wheel/sdist inspected and installed independently; valid configuration accepted and invalid configuration refused; 156 tests plus 19 mutex follow-up checks | Actual AWS deployment and teardown require the owner's personal profile and region selection |
| engineering-os | eos-f71 | Clean pnpm 12.10.1 bootstrap; 49 retrieval and 63 dashboard checks; both installed archives demonstrated through actual HTTP and the local embedding model; invalid input refused and owned state cleaned up | Private trust domains must remain isolated; remote CI and publication have not run |
| ciso-assistance | ciso-5fp | Installed package includes the UI and synthetic materials; actual HTTP review/export, two local model drafts and equal restored state; overwrite/tampering refused; 38 tests | Redistribution license needs the owner's selection; review-state recovery is not clinical or cluster recovery |

Every site passed a strict Zensical 0.0.65 build from its selected public
sources. The standalone docs environment was installed freshly with Python
3.12.12. All six concise homepages rendered their architecture diagrams in a
browser, including the dark theme. At 390px, all six pages kept their content
within the viewport and exposed three next-step links. Desktop and mobile
screenshots and local verification manifests were retained outside this
clean-room repository. Detailed reference pages remain available in collapsed
navigation groups. No private vault or local workspace overlay was a docs input.

The root source archive previously included the public beads export and tracker
README. Packaging commit `4f69e2a` excludes the whole tracker directory and local
state, and the archive checker now refuses those paths. Its new negative cases
cover tracker databases, generated sites, runtime state, private denylist files
and invalid paths. A clean committed checkout produced a wheel with 18 entries
and a source archive with 166 entries, both without private-identifier matches
or local metadata. The independently installed verifier accepted a two-record
synthetic audit and rejected deletion against its checkpoint. This packaging
check is separate from the actual SPIRE lab demonstration.

The retained root shared-lab record contains 18 passed scenarios on 2026-10-07
after the auth change, including signing-key overlap and scoped teardown while
preserving the CISO namespace. That record is saved executed evidence, not a new
run against the final documentation or later FHIR SDK. See
[the auth validation record](auth-cost-rotation.md).

A fresh local secret scan of all six reachable histories returned no unresolved
credential findings. Root history uses the existing exact historical exception
for a verified review-packet SHA-256. The root committed-source directory scan
returned one raw finding: the same packet hash. It was independently matched to
the retained packet bytes and classified as a false positive; the raw scanner
exit remained 1 and no scanner rule was weakened. The other five committed-source
scans returned zero findings. These checks are identifier evidence only.

## Follow-up verification - 2026-10-12

- FHIR packaging commits `e89e6cc` and `73c3cb9` stage fresh compiler outputs and
  locked production dependencies. The complete Desktop archive gate refuses
  local pnpm metadata, private paths, symlinks and traversal. Five gate tests and
  the 51 application tests passed. The extracted archive passed eight actual
  stdio/verified synthetic HTTPS invocations, eight audit records, pre-backend
  refusals, recovery and cleanup. Native Desktop installation is still unverified.
- Bridge commits `59f48be` and `01eb152` provide a repeatable installed-library TLS
  demonstration with synthetic runtime certificates. Allowed and denied callers,
  missing certificates, credential loss/recovery and cleanup passed. All 79 tests,
  types, build and lint passed, with nine existing lint warnings. This is not a
  new shared SPIRE run or provenance clearance.
- All six committed Pages workflows passed a local structural review: push
  triggers select only `main`; deployment refuses pull requests and other refs;
  checkout credentials are not persisted; actions use full commit SHA pins;
  uploads select only `site`; Pages/OIDC write permissions exist only in the
  deployment job. This review did not run GitHub Actions, validate remote settings
  or prove that a public site exists.

| Workflow inspected | Revision |
|---|---|
| mcp-svid-auth | `3feda2d` |
| hipaa-fhir-mcp | `73c3cb9` |
| mcp-spiffe-bridge | `01eb152` |
| ecs-contract | `51ee5da` |
| engineering-os | `ce6a1ab` |
| ciso-assistance | `24c62e2` |

## Owner decisions

Updated on 2026-10-13. Publication of the `codex/kubernetes-security-lab` branch
and of the bridge remains a separate maintainer decision. CISO Assistance is
licensed under Apache-2.0. The ECS live deployment and teardown passed on a
personal account. Native Claude Desktop installation of the FHIR bundle was
verified. See each repository's readiness page for the evidence.

## Publication handoff

The owner reviews the exact final changes and chooses when to publish. The
prepared workflows build pull requests and upload `site/`, with Pages deployment
restricted to the main branch and job-scoped permissions. They do not change
repository visibility or Pages settings. No release, package upload, push or
remote deployment has been executed by this preparation.

The [implementation ledger](quorum-implementation-2026-10-07.md) records the prior
13 tasks. The [Zensical documentation](https://zensical.org/docs/create-your-site/)
describes the generator and static hosting contract. Each repository's
`docs/publication-readiness.md` defines its local documentation command and
presentation boundaries; mcp-svid-auth also has [publication evidence](publication.md).

## Publication scope on 2026-10-07

The `codex/kubernetes-security-lab` branch and the bridge repository were kept
unpublished. The svid tracked tree, all reachable history, tracked portfolio
reports and the generated site had no matches against the private local
denylist. This is identifier evidence, not a proof of authorship.

## Unified local runtime - 2026-10-13

The security projects document Lima, Kubernetes and containerd, with Buildah for
OCI builds. ECS Contract uses its own separate Lima/containerd VM and nerdctl,
without a Kubernetes or shared-lab dependency. Host-native Python/Node.js workflows
remain host-native. AWS ECS remains the deployment target for ECS Contract.
Docker/Podman daemon dependencies were removed from active local launch paths;
OCI image formats, registry URLs and dated historical evidence remain intact.
See the [runtime map](runtime.md#portfolio-convention).

The authorization lab passed 531 offline tests and all 18 actual SPIRE/FHIR
scenarios on a fresh image build. Report start: 2026-10-13T06:04:18.370965+00:00.
Final scoped teardown removed lab namespaces/RBAC/socket, preserved the existing
CISO namespace UID and left the shared VM running. The retired Podman VM was not
changed. A restart-readiness race in the demo was fixed by waiting for the
resource server's asynchronous JWKS refresh; cryptographic checks were unchanged.

ECS Contract is a separate project with its own runtime profile, lifecycle
commands and pinned-image local Vault demonstration. It does not start, stop,
mount or depend on the shared security lab. The complete live AWS ECS deployment
remains a separate gate. All six strict Zensical builds passed; the ECS runtime
diagram rendered in the browser.

Publication scope, the CISO license choice and the native FHIR Desktop
installation gate were unchanged at that point. No push, release or external model review
was performed.
