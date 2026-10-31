# Quickstart

The primary path uses this repository only. It runs the tests, a local end-to-end
demo, the packaging checks and the documentation build without SPIRE, a VM or any
unpublished component. The full Kubernetes lab is optional and documented
separately below.

## Requirements

| Need | For |
|---|---|
| Python 3.12+ and [uv](https://docs.astral.sh/uv/) | Package, tests and offline checks |
| Node 26+ and npm | Local end-to-end demo with the independent TypeScript SDK |

## Install and validate

```sh
git clone https://github.com/tanya-ok/mcp-svid-auth.git
cd mcp-svid-auth
uv sync --locked
make check
```

`make check` runs lint, formatting, strict types, generated configuration drift and tests. Tests use runtime local keys instead of SPIRE, and include a loopback TLS server. No external service is contacted by the tests after dependencies are installed.

The optional privacy denylist is `tests/denylist.txt`, ignored by Git. Never include it in a commit or artifact.

## Local end-to-end demo and packages

```sh
cd examples/typescript-client
npm ci --ignore-scripts --no-audit --no-fund
cd ../..
make interop
make package
```

`make interop` starts the authorization server and a Notes MCP server on loopback with runtime keys, then drives them with the official TypeScript SDK 1.32.2 and an explicit JWT-SVID adapter. See the [compatibility check](compatibility.md). The assertion goes through stdin, not arguments or logs. It checks discovery, token exchange, MCP initialization, scoped tool listing, allowed reading and denied writing.

`make package` creates one wheel, one source distribution and `SHA256SUMS` under ignored `dist/`, then checks archive contents and licensing. It does not publish anything. See [Publication validation](publication.md) for the actual checks performed on the prepared version.

## Documentation

```sh
uv run --locked --only-group docs zensical serve
uv run --locked --only-group docs zensical build --strict --clean
```

The site is generated under ignored `site/`. A strict build validates the site; it does not deploy it.

## Full Kubernetes lab (requires unpublished components)

!!! note "Not reproducible from this repository alone"
    The integrated lab needs a sibling checkout of `mcp-spiffe-bridge`, which is
    not yet published, and of
    [`hipaa-fhir-mcp`](https://github.com/tanya-ok/hipaa-fhir-mcp). The recorded
    lab results are evidence from the maintainer's environment.

| Need | For |
|---|---|
| [Lima](https://www.cncf.io/projects/lima/) 2.2.1+ on macOS with free disk space | Dedicated Linux VM for the real SPIRE demo |
| Sibling checkouts of `mcp-spiffe-bridge` and `hipaa-fhir-mcp` | FHIR gateway and SPIFFE bridge in the shared lab |

```sh
make runtime-up
make demo
make down
make runtime-stop
```

The dedicated `security-lab` Lima VM runs k3s Kubernetes with containerd, SPIRE 1.15.3, the two authorization-server modes, Notes MCP services and the FHIR gateway with the SPIFFE bridge. It waits for readiness and asserts all [eighteen scenarios](demo.md). See [shared lab](kubernetes-lab.md).

The expiry scenario uses 60-second SVIDs and waits beyond the 30-second validation leeway. Allow a few minutes. The verdict report and synthetic audit captures remain in ignored `deploy/.data/`. `make down` removes only lab-owned namespaces, RBAC and runtime volumes. `make runtime-stop` stops the VM and releases its CPU and memory; its disk and cached container images remain for the next run.

### CNCF runtime and resource limits

Container infrastructure uses CNCF-hosted projects: Lima, k3s, Kubernetes, containerd, SPIRE and Buildah from [Podman Container Tools](https://www.cncf.io/projects/podman-container-tools/). Install Lima through its [installation guide](https://lima-vm.io/docs/installation/), then use the four commands above. containerd is the only running container runtime; the former Podman runtime path was retired on 2026-10-13. See [Runtime](runtime.md).

The VM has 2 CPUs, 4 GiB guest memory and a 12 GiB disk capacity. Host virtualization adds overhead, and the sparse disk grows as images are built. Keep free host disk space for downloads and builds. Only the three security repositories are mounted read-only; no home directory or SSH agent is shared. Startup is explicit, with no automatic login service.
