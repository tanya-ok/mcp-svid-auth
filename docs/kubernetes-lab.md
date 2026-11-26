# Shared Kubernetes security lab

This local proof of concept connects `mcp-svid-auth`, `mcp-spiffe-bridge` and
`hipaa-fhir-mcp`. `ecs-contract` is excluded. It does not deploy a cloud cluster.
The [Headlamp interface](headlamp-ui.md) provides a local read-only view.

!!! note "Requires components that are not yet published"
    `mcp-spiffe-bridge` is not yet published, so this lab cannot be reproduced
    from public sources. The [quickstart](quickstart.md) single-repository path
    (tests, local end-to-end demo, packaging and interoperability) needs no lab.
    Results on this page are recorded evidence from the maintainer's environment.

## Components and requests

```mermaid
flowchart LR
  subgraph Lima[Dedicated Lima VM: 2 CPUs, 4 GiB]
    subgraph Kubernetes[k3s Kubernetes with containerd]
      SS[SPIRE server] --> SA[SPIRE agent]
      SA -->|JWT-SVID and X.509-SVID| A[Research workload]
      SA --> AS[mcp-svid-auth authorization server]
      SA --> G[mcp-spiffe-bridge inside FHIR service]
      A -->|JWT-SVID assertion| AS
      AS -->|300 second resource-bound access token| A
      A -->|mTLS and access token| G
      G -->|Verified caller context| F[hipaa-fhir-mcp tools]
      A --> N[Notes MCP services]
    end
  end
```

The bridge is a library loaded by the FHIR gateway, not an extra independently
running daemon. The gateway uses the existing FHIR tools with an explicitly
synthetic, offline FHIR adapter. It does not call the public sandbox or real data.
Its domain schemas, fixture, gateway and audit checker stay in the FHIR repository.
The shared lab receives bounded pass/fail outcomes from that checker.

The FHIR endpoint is `https://fhir.security-lab.svc.cluster.local:8443/mcp`. Its
X.509-SVID includes this DNS name, so clients keep normal CA and hostname checks.
The access token must have exactly this audience, `fhir:read`, the fixed issuer,
and a subject equal to the authenticated mTLS peer. Public verification keys are
fetched from the fixed local issuer without forwarding incoming credentials.
There is no write scope for the FHIR service.

All lab services speak HTTPS. A per-run certificate authority and one server
certificate per service are generated in memory by `scripts/lab_tls.py` and applied
as Secrets; nothing is written to disk and the review preview holds placeholders.
Servers use `--tls-cert` and `--tls-key`, clients use `--ca-file` (Node uses
`NODE_EXTRA_CA_CERTS`) and the agents name each in-cluster host with
`--allow-private-host`. Certificate and hostname verification are never disabled.
The FHIR repository still pins a plain HTTP issuer in its gateway and probe, so the
build edits the staged copy of those two files to `https` and fails if they change;
the checkout is not modified.

Two ValidatingAdmissionPolicies in `scripts/lab_admission.py` limit the lab
namespaces: a pod or workload controller must use a ServiceAccount on the allow
list, and only the lab operator (the k3s administrator) and the Deployment and
DaemonSet controllers may create one with it. Job, CronJob and StatefulSet
controllers are not allowed to. The policies deny for every principal, including
cluster administrators.

SPIRE node attestation uses a projected ServiceAccount token with audience
`spire-server`. Workload registration requires both Kubernetes namespace and
ServiceAccount selectors. Copying a research label onto an intruder workload does
not change its identity. The kubelet's certificate is verified. Neither the
containerd socket nor a Podman socket is mounted into SPIRE or application pods.

## Start, inspect and stop

Check out the three security repositories as siblings; `mcp-spiffe-bridge` is
not yet published, so this step requires maintainer access. Install Lima 2.2.1+ and
the root project's locked Python dependencies. The VM mounts only those three
repositories, read-only, and does not share home directories or SSH credentials.

Two environment variables change where the lab runs. `LAB_VM` is the Lima instance
name (default `security-lab`; it must be lowercase letters, digits and hyphens). The
Kubernetes namespace, node, SPIRE cluster and DNS names stay `security-lab`.
`SVID_LAB_REPO_MCP_SPIFFE_BRIDGE` and `SVID_LAB_REPO_HIPAA_FHIR_MCP` (and
`SVID_LAB_REPO_MCP_SVID_AUTH`) replace the sibling default for a repository. The
build stages files inside the FHIR location, so point it at a copy if the checkout
must stay untouched. Build inputs follow the current sibling revisions (bridge
`tsconfig.build.json`, pnpm 12.14.0, the FHIR `pnpm-workspace.yaml`).

```sh
uv sync --locked
make lab-render   # review generated manifests without starting a VM
make up           # start the VM, build local images and launch the services
limactl shell "${LAB_VM:-security-lab}" sudo k3s kubectl -n security-lab get pods
make down         # remove this lab's namespaces, RBAC and workload socket
make runtime-stop # only when no sibling project needs the shared VM
```

For a fresh full validation, use `make demo` instead of `make up`. It starts the
same stack and asserts all 22 scenarios, including the original OAuth cases,
real SVID renewal, copied-label denial, three FHIR tools, wrong-audience denial,
absent/disallowed client certificates, input rejection, the FHIR audit check and
four ServiceAccount admission checks (scenarios 19-22). `python -m scripts.kubernetes_demo
admission-check` runs only the admission checks.
Existing namespaces cause a refusal; run `make down` before a fresh run.

The review preview contains explicit runtime placeholders for image digests and
the trust bundle. Startup supplies real values; do not apply the preview manually.

The VM uses k3s **v1.37.1+k3s1**, which embeds Kubernetes **1.37.1** and
containerd **2.3.4-k3s1**. Release binaries and Debian base images are pinned by
checksums. SPIRE and application base images are pinned by digest. Locally built
images are imported into containerd and referred to by their resulting digest;
`imagePullPolicy: Never` prevents a registry fallback. Buildah and Skopeo belong
to CNCF Podman Container Tools and are used only for local image construction and
inspection. No container engine API is used for builds, and no image is pushed.

The profile limits guest memory to 4 GiB and disables Traefik, ServiceLB,
metrics-server and local-storage. Every application has CPU/memory limits,
a read-only root filesystem, no Linux capabilities and no mounted Kubernetes
API token. The separate Headlamp viewer uses a short-lived projected API token
and read-only namespace Roles. Runtime keys live in ephemeral volumes or process
memory. Automatic host port forwarding is disabled; the admin kubeconfig stays inside the VM with
mode 0600. The driver always targets the VM's loopback API endpoint.

Stopping releases compute resources. It retains VM disk and image caches.
Building images requires additional disk space and temporarily more CPU than
an idle lab. The 12 GiB sparse guest disk does not limit total host cache usage.

## Validation on 2026-11-26

Run in a new Lima instance, `svid-prod-lab`, created from `deploy/lima-kubernetes.yaml`
with `LAB_VM=svid-prod-lab` (2 CPUs, 4 GiB, k3s v1.37.1+k3s1). No other Lima
instance was started. The bridge (revision `0117062`) and FHIR (revision `d306e8b`)
repositories were copied to a scratch directory and passed through
`SVID_LAB_REPO_*`, so staging wrote nothing into those checkouts. The commands were
the ones behind `make up`, `make demo` and `make down`, run through `uv run`.

| Stage | Result |
|---|---|
| Instance creation, node ready | Passed |
| First image build | Failed: the lab inventory predated the bridge `tsconfig.build.json` and the FHIR pnpm workspace file and pnpm version; corrected |
| First demo run | Scenario 4 failed: the audit filter expected `record_id` first, but schema 2 records start with `schema_version`; corrected |
| Reruns on the same stack | Diagnosed on 2026-11-26, see below |
| `make down`, then fresh `make up` and demo | 22 of 22 scenarios passed; report written 13:09 UTC |
| Admission negative test | With the policy: 4 of 4. With both bindings deleted: the three denial checks failed, the operator launch passed. Bindings restored: 4 of 4 |
| TLS spot check from inside the VM | Plain HTTP to the issuer returned no HTTP response; HTTPS with the lab CA returned 200; HTTPS with system trust only failed certificate verification |
| Teardown | `down` removed the namespaces, RBAC and both policies; the VM was stopped |

### Rerunning the demo on a running stack

The demo is meant for a fresh stack, but it can be rerun without `make down`
since 2026-11-26. Three defects stopped that, found by repeated reruns:

- Scenario 11 restarts authz, which has an ephemeral signing key, so every earlier key
  disappears. notes-a kept its cached upstream token (300 seconds, refreshed 30 seconds
  early) and notes-b rejected it with `invalid_token` until it expired. Reproduced by
  restarting authz alone: 9 of 10 upstream calls over the next minute returned 401, and
  a direct call to notes-b worked. notes-a now replaces a rejected token once with a new
  one fetched under its own SVID (`tests/test_upstream_retry.py`); after the change 10 of
  10 calls passed. This also explains the scenario 8 failures on reruns.
- The wait for the restarted key matched the 401 text exactly, but the agent appends
  `resource_metadata`, so a pending key refresh was reported as a mismatch (scenario 11).
  The resource server refetches keys at most every 10 seconds, so a 401 right after a
  restart is expected and the wait now accepts it.
- The FHIR audit checker needs exactly four records, so the second run saw eight. The demo
  now passes it only the records written since its own start; the checker is unchanged.

Counts on one stack without `down` (all 22 scenarios each time unless noted). Before any
fix: the first run passed, the next failed at scenario 8, and a following partial run
passed 8 to 14. With only the token fix: two reruns reached scenario 17 and failed at
scenario 18 (audit count). With the token and audit fixes: three reruns, two passed and
one failed at scenario 11 (the exact 401 match). With all three fixes: four of four
reruns passed. An earlier scenario 11 failure on 2026-11-26 matches the exact-match
defect but was not captured with its output, so that link is likely, not proven.

Replay protection, single-use assertions and quotas are not relaxed. Admission probes, audit
chains and stored notes carry over between runs, which the checks tolerate.

Not run on 2026-11-26: the Headlamp viewer in a browser (its Deployment was applied
and running), the ZITADEL identity profile, the memory measurement and a repeat of the
full pass. The earlier results below were produced over plain HTTP.

## Validation on 2026-10-06 (plain HTTP)

A fresh rebuild with private umask 077 passed all eighteen scenarios at 14:55
UTC. A repeat with the native ZITADEL profile enabled passed eighteen at 15:02
UTC, using fresh notes-a credential and FHIR audit state. The no-certificate
probe requires an explicit peer TLS alert rather than a generic transport reset.
Public image staging files are readable by the non-root container user without
changing private source files or runtime credential permissions.

The main profile passed eleven synthetic WebAuthn/OIDC checks and four closed
Google provider setup checks with fake inputs. Five protected desktop views,
actual browser logout, detached/idempotent start, shutdown on identity backend
loss and recovery passed. The hosted login form reached passkey authentication
without a password form. These checks do not prove a physical authenticator or
real Google login. See [identity evidence](passwordless-identity.md).

An earlier final cycle failed after macOS disk exhaustion and guest I/O errors.
After the operator-approved VM restart, the complete recovery cycle from 15:25
to 15:31 UTC passed: a fresh eighteen-scenario rebuild, native startup, viewer
stop/restart/idempotence, backend-loss shutdown and recovery, eleven identity
checks, four closed Google setup checks and five desktop views plus mobile.
The final `make down` removed the three owned namespaces, private identity
records and all five viewer listeners while preserving CISO's namespace UID
and the running shared VM. Sixty-four five-second samples including native
startup observed at most 1858.1 MiB guest use, with no measurement errors.
Do not stop the shared VM while a sibling project depends on it without
coordination.

## Earlier validation on 2026-10-05

The final fresh image build and `make demo` run passed all 18 scenarios. Its
report started at 13:58:44 UTC. `make down` removed the owned namespaces, RBAC
and workload socket, then `make runtime-stop` stopped `security-lab`.

| Check | Result |
|---|---|
| Root `make check` | 242 tests; lint, formatting, strict types and generated configuration passed |
| Gateway token verifier | 21 Node crypto and configuration assertions, exercised by the root test suite |
| Bridge | 56 tests including real TLS handshakes, expired credentials, stream loss and failed startup; types and build passed |
| Bridge lint | Passed with nine existing warnings |
| FHIR | 10 tests including independent MCP client calls, concurrent caller isolation and stderr audit; types, formatting and build passed |
| FHIR log scan | Zero sensitive-data findings |
| Integration | All 18 scenarios passed with real SPIRE and Kubernetes ServiceAccount attestation |
| Privacy and secret scans | Root tree and full-history privacy checks passed; all three Git histories and non-ignored source snapshots had zero Gitleaks findings |

The security review covered all seven root invariants:

| Invariant | Evidence |
|---|---|
| Deny by default | Gateway startup refuses undeclared or duplicate tool scopes; crypto/configuration tests and live unknown-tool rejection passed |
| Audience binding | Signed tokens require one exact resource URI; crypto tests and cross-resource live replay denial passed |
| No token passthrough | Existing byte-capture regression checks and the new public-key fetch capture test passed |
| Strict token checks | ES256, `at+jwt`, issuer, audience, caller and lifetime checks passed; live expired assertion and strict replay denials passed |
| No secrets in output | Fixed error strings, bounded outcomes, FHIR audit assertions, privacy checks and secret scans passed |
| Fail closed | Existing stdio expiry/cleanup tests and bridge expiry/stream-loss tests passed; the gateway exits after identity loss |
| Runtime keys | SPIRE state uses ephemeral memory volumes, gateway audit keys are generated in memory and TLS test keys are generated at runtime; source and history scans passed |

At 13:56:17 UTC after the preceding successful run, guest used memory was
**1311.3 MiB**, calculated as `MemTotal - MemAvailable`. Container working sets
totalled **618.0 MiB**, including CoreDNS; the FHIR gateway accounted for
109.5 MiB. This single idle snapshot excludes macOS/Lima overhead and image
build peaks. It is not a Docker comparison or a performance guarantee. The
configured VM cap remains 4 GiB. Safe local results remain under ignored
`deploy/.data/`; no image, commit, package or runtime was published externally.

## Trust boundary and remaining work

This is a single-node lab, without production availability, a managed secrets
store, durable audit retention or a production FHIR backend. All service traffic
uses TLS with a CA that exists only for one run; keys are held in Secrets inside
the cluster, which the operator can read. SMART-on-FHIR and a cloud KMS remain out of
scope for the lab.

The lab authz instances run with `--dev-ephemeral-signing-key`, because
`mcp-svid-authz` requires an explicit key source. The main instance accepts SVID
reuse within the SVID lifetime; the strict instance does not. The lab does not use
the shared state store, the transit signer or the revocation file. See
[production readiness](production-readiness.md).

Anyone who controls the cluster can assume any lab identity: they can edit or delete
the admission policies, read the TLS Secrets or run a pod with host access. The
policy stops other principals, not the operator. The SPIRE agent runs as root with
host PID visibility, and application pods mount the node's Workload API socket.
Namespace/ServiceAccount attestation and the admission policy strengthen the
previous label-only demo, but they do not protect against the VM or cluster operator.

The gateway rejects calls if its credential stream is lost or expired. It exits
after stream loss so Kubernetes replaces the process and obtains fresh identity.
Bridge instances cannot restart after stop or failed startup; create a new one.

Next steps are a SPIFFE CSI socket mount, persistent independently retained audit
checkpoints, a configurable issuer in the FHIR repository so the staging edit can
go, and a rerun of the Headlamp and identity checks.

Primary references: [k3s CNCF project](https://www.cncf.io/projects/k3s/),
[k3s release and embedded versions](https://github.com/k3s-io/k3s/releases/tag/v1.37.1+k3s1),
[SPIRE PSAT attestation](https://github.com/spiffe/spire/blob/v1.15.3/doc/plugin_server_nodeattestor_k8s_psat.md),
[SPIRE Kubernetes workload attestation](https://github.com/spiffe/spire/blob/v1.15.3/doc/plugin_agent_workloadattestor_k8s.md).
