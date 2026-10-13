# CNCF container runtime

Container infrastructure is restricted to CNCF-hosted projects. Appearance in the
broader CNCF Landscape or Linux Foundation membership alone is insufficient.

| Project | Role |
|---|---|
| [Lima](https://www.cncf.io/projects/lima/) | Explicitly started Linux VM on macOS |
| [k3s](https://www.cncf.io/projects/k3s/) / [Kubernetes](https://www.cncf.io/projects/kubernetes/) | Shared local service orchestration |
| [containerd](https://www.cncf.io/projects/containerd/) | Sole running container runtime, managed by k3s |
| [SPIRE](https://www.cncf.io/projects/spire/) | Real workload identity and trust bundles |
| [Podman Container Tools](https://www.cncf.io/projects/podman-container-tools/) | Buildah builds OCI images locally; Skopeo supports image inspection |

The default is the [shared Kubernetes security lab](kubernetes-lab.md), with three
security repositories and no ECS services. The lab requires `mcp-spiffe-bridge`,
which is not yet published; the [quickstart](quickstart.md) offline path does not. The driver reads the existing service
inventory and creates native Kubernetes objects. It uses neither Docker nor a
Compose provider. The historically named OCI build files and image registries do
not select a container runtime.

```sh
make up           # 2 CPU, 4 GiB VM, local image builds, all lab services
make down         # lab-owned namespaces, RBAC and socket only
make runtime-stop # only when no sibling project needs the shared VM
```

For the full fresh integration check, use `make demo` instead of `make up`.
First launch needs free disk for the pinned Debian image, k3s, build dependencies
and container images. The 12 GiB sparse VM disk and caches can consume additional
host disk. Startup is explicit and no login service is installed. Application
images are referred to by digest after local import into containerd.

Only the three security repositories are mounted, read-only. Home directories,
SSH agents and public SSH keys are not shared. The kubeconfig remains inside the
VM. Automatic host port forwarding is disabled. Every driver operation targets
its loopback Kubernetes API and validates ownership before destructive work.

## One active runtime

The Podman compatibility commands and runtime configuration were retired on
2026-10-13. Historical reports remain dated evidence. Existing legacy VMs are
not stopped or deleted by this migration. OCI Containerfiles and `docker.io`
registry references remain valid image formats and locations, not Docker runtime
dependencies.

Integration build staging belongs to the FHIR repository's ignored runtime data,
not the clean-room authorization repository. Only explicit public build inputs
are staged; no Git history, task databases or credentials are copied.

## Portfolio convention

| Project | Local execution | Container path |
|---|---|---|
| mcp-svid-auth | Python checks and CLI | Shared Lima/k3s/containerd lab |
| mcp-spiffe-bridge (not yet published) | Node.js library and TLS demo | Embedded in the shared FHIR gateway |
| hipaa-fhir-mcp | Node.js stdio and Desktop bundle | Shared FHIR namespace |
| it-grc (not yet public) | Python standard-library bridge and CLI | CISO Assistant CE on k3s in its own `it-grc` Lima VM |
| ecs-contract | Independent Python CLI and AWS ECS | Separate `ecs-contract` Lima/containerd VM |
| engineering-os | Node.js retrieval and dashboard, local Beads | No container required |

Host-native workflows stay host-native. ECS Contract has its own VM and lifecycle,
with no Kubernetes or security-lab dependency. IT GRC also has its own VM and
lifecycle; it reads a saved lab demo report and does not use the security-lab VM.
All local application containers use containerd; no Docker or Podman daemon is
required. ECS remains an AWS deployment
target rather than being replaced by Kubernetes. Every teardown targets only
resources owned by its project or run.
