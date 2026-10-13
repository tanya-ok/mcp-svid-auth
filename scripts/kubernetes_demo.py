"""Local Kubernetes/containerd lab in a dedicated CNCF Lima VM.

Only the three security repositories are mounted. No host kubeconfig, registry push,
Docker API, ECS service or unrelated cluster is used. Captured output is never included
in runtime errors because it may contain credential material.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from mcp_svid_auth.policy import Policy
from scripts.lab_runtime import SERVICES, DemoRuntimeError
from scripts.local_identity_profile import ISOLATED

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
CONFIG = DEPLOY / "kubernetes"
DATA = DEPLOY / ".data"
VM = "security-lab"
NAMESPACE = "security-lab"
OWNER = {"app.kubernetes.io/part-of": "security-lab"}
SOCKET = "/run/spire/security-lab"
IMAGES_FILE = DATA / "kubernetes-images.json"
REPOS = ("mcp-svid-auth", "mcp-spiffe-bridge", "hipaa-fhir-mcp")


def lima(
    args: list[str], *, timeout: int = 120, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("limactl")
    if executable is None:
        raise DemoRuntimeError("Lima is not installed")
    try:
        return subprocess.run(  # noqa: S603 - argument array, no shell
            [executable, *args],
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise DemoRuntimeError("Lima operation failed or timed out") from None


def guest(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return lima(["shell", VM, "sudo", *args], **kwargs)


def checked(result: subprocess.CompletedProcess[str]) -> str:
    if result.returncode:
        raise DemoRuntimeError("Kubernetes lab operation failed")
    return result.stdout


def kube(
    args: list[str],
    *,
    namespace: str | None = NAMESPACE,
    timeout: int = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return guest(
        [
            "k3s",
            "kubectl",
            "--kubeconfig=/etc/rancher/k3s/k3s.yaml",
            "--server=https://127.0.0.1:6443",
            *(["--namespace", namespace] if namespace else []),
            *args,
        ],
        timeout=timeout,
        input_text=input_text,
    )


def apply(documents: list[dict[str, Any]]) -> None:
    checked(kube(["apply", "-f", "-"], namespace=None, input_text=yaml.safe_dump_all(documents)))


def resource(kind: str, name: str, *, namespace: str = NAMESPACE, **fields: Any) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace, "labels": dict(OWNER)},
        **fields,
    }


def configmap(name: str, data: dict[str, str], namespace: str) -> dict[str, Any]:
    return resource("ConfigMap", name, namespace=namespace, data=data)


def service(name: str, port: int, namespace: str = NAMESPACE) -> dict[str, Any]:
    return resource(
        "Service",
        name,
        namespace=namespace,
        spec={"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]},
    )


def controller(
    name: str, pod: dict[str, Any], namespace: str = NAMESPACE, *, daemon: bool = False
) -> dict[str, Any]:
    result = resource(
        "DaemonSet" if daemon else "Deployment",
        name,
        namespace=namespace,
        spec={
            "selector": {"matchLabels": {"app": name}},
            "template": {"metadata": {"labels": {**OWNER, "app": name}}, "spec": pod},
        },
    )
    result["apiVersion"] = "apps/v1"
    if not daemon:
        result["spec"]["replicas"] = 1
        result["spec"]["strategy"] = {"type": "Recreate"}
    return result


def runtime_up() -> None:
    inventory = checked(lima(["list", "--format", "{{.Name}}"])).splitlines()
    if VM in inventory:
        verify_instance()
        checked(lima(["start", "--tty=false", VM], timeout=600))
    else:
        if ISOLATED:
            raise DemoRuntimeError("Isolated identity requires the existing shared lab VM")
        config = yaml.safe_load((DEPLOY / "lima-kubernetes.yaml").read_text())
        config["mounts"] = [
            {"location": str(ROOT.parent / name), "writable": False} for name in REPOS
        ]
        if not all((ROOT.parent / name / "package.json").is_file() for name in REPOS[1:]):
            raise DemoRuntimeError("sibling security repositories are required")
        DATA.mkdir(exist_ok=True)
        profile = DATA / "lima-kubernetes.yaml"
        profile.write_text(yaml.safe_dump(config, sort_keys=False))
        checked(lima(["start", "--tty=false", "--name=" + VM, str(profile)], timeout=600))
    checked(kube(["wait", "--for=condition=Ready", "node/security-lab", "--timeout=90s"]))
    print("Dedicated Lima Kubernetes/containerd node ready", flush=True)


def verify_instance() -> None:
    entries = [json.loads(line) for line in checked(lima(["list", "--json"])).splitlines() if line]
    instance = next((entry for entry in entries if entry["name"] == VM), None)
    if instance is None:
        raise DemoRuntimeError("dedicated VM is absent; run make runtime-up")
    config = instance["config"]
    mounts = config.get("mounts", [])
    mount_root = Path(os.environ.get("SVID_LAB_MOUNT_ROOT", str(ROOT))).resolve()
    expected = {str(mount_root.parent / name) for name in REPOS}
    if {mount["location"] for mount in mounts} != expected or any(
        mount.get("writable") for mount in mounts
    ):
        raise DemoRuntimeError("VM does not have this lab's restricted mounts")
    if (
        instance["cpus"] != 2
        or instance["memory"] != 4 * 1024**3
        or config["containerd"].get("system")
        or config["containerd"].get("user")
    ):
        raise DemoRuntimeError("VM runtime or resource limits differ from the lab")
    if config["ssh"].get("forwardAgent") or config["ssh"].get("loadDotSSHPubKeys"):
        raise DemoRuntimeError("VM shares host SSH credentials")
    forwarding = config.get("portForwards", [])
    if not forwarding or not (
        forwarding[0].get("ignore")
        and forwarding[0].get("proto") == "any"
        and forwarding[0].get("guestPortRange") == [1, 65535]
        and forwarding[0].get("guestIP") == "0.0.0.0"  # noqa: S104 - disables all forwarding
        and forwarding[0].get("guestIPMustBeZero") is False
    ):
        raise DemoRuntimeError("VM has automatic host port forwarding enabled")
    if not any(
        "Dedicated local security lab Kubernetes and containerd" in item.get("script", "")
        for item in config.get("provision", [])
    ):
        raise DemoRuntimeError("VM belongs to another project")


def build_image(name: str, context: Path, file: Path) -> str:
    tag = "localhost/security-lab/" + name + ":local"
    print("Building local OCI image: " + name, flush=True)
    checked(
        guest(
            [
                "buildah",
                "bud",
                "--isolation=chroot",
                "--network=host",
                "--layers=false",
                "--force-rm",
                "--tag",
                tag,
                "--file",
                str(file),
                str(context),
            ],
            timeout=900,
        )
    )
    staging = checked(guest(["mktemp", "--directory", "--tmpdir", "security-lab.XXXXXXXX"])).strip()
    archive = staging + "/image.tar"
    try:
        checked(
            guest(["buildah", "push", tag, "docker-archive:" + archive + ":" + tag], timeout=180)
        )
        checked(
            guest(["k3s", "ctr", "--namespace", "k8s.io", "images", "import", archive], timeout=180)
        )
        listing = checked(guest(["k3s", "ctr", "--namespace", "k8s.io", "images", "list"]))
        digest = next(
            (
                line.split()[2]
                for line in listing.splitlines()
                if line.split() and line.split()[0] == tag
            ),
            None,
        )
        if digest is None or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise DemoRuntimeError("imported image digest unavailable")
        pinned = tag.split(":local")[0] + "@" + digest
        checked(
            guest(["k3s", "ctr", "--namespace", "k8s.io", "images", "tag", "--force", tag, pinned])
        )
        return pinned
    finally:
        checked(guest(["rm", "--force", archive]))
        checked(guest(["rmdir", staging]))


def build() -> dict[str, str]:
    DATA.mkdir(exist_ok=True)
    # Stage integration sources outside the clean-room authorization repository.
    staging_root = ROOT.parent / "hipaa-fhir-mcp" / "deploy" / ".data"
    staging_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kubernetes-build-", dir=staging_root) as staging:
        return build_from_context(Path(staging))


def build_from_context(context: Path) -> dict[str, str]:
    # Copy an explicit source inventory, excluding Git, local secrets and node_modules.
    for name in REPOS:
        destination = context / name
        destination.mkdir(exist_ok=True)
        source = ROOT.parent / name
        files = (
            ["package.json", "pnpm-lock.yaml", "tsconfig.json"]
            if name != REPOS[0]
            else ["README.md", "LICENSE", "NOTICE", "pyproject.toml", "uv.lock"]
        )
        if name == "mcp-spiffe-bridge":
            files += ["tsup.config.ts", "pnpm-workspace.yaml"]
        for filename in files:
            shutil.copyfile(source / filename, destination / filename)
        shutil.copytree(source / "src", destination / "src", dirs_exist_ok=True)
        if name == "hipaa-fhir-mcp":
            shutil.copytree(
                source / "deploy/kubernetes", destination / "deploy/kubernetes", dirs_exist_ok=True
            )
    shutil.copytree(CONFIG, context / REPOS[0] / "deploy/kubernetes", dirs_exist_ok=True)
    for filename in ("probe_svid.py", "probe_mtls.py"):
        shutil.copyfile(DEPLOY / filename, context / REPOS[0] / "deploy" / filename)
    # This allowlisted source snapshot contains no credentials. COPY preserves modes,
    # so the caller's private umask must not make image code unreadable to non-root users.
    context.chmod(0o755)
    for path in context.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(0o644)
    images = {
        "auth": build_image("auth", context, CONFIG / "Auth.Containerfile"),
        "fhir": build_image("fhir", context, CONFIG / "Fhir.Containerfile"),
    }
    IMAGES_FILE.write_text(json.dumps(images, indent=2) + "\n")
    return images


def spire_server_documents() -> list[dict[str, Any]]:
    namespace = "spire-system"
    role = resource(
        "ClusterRole",
        "security-lab-spire-server",
        namespace=namespace,
        rules=[
            {"apiGroups": [""], "resources": ["pods", "nodes"], "verbs": ["get"]},
            {
                "apiGroups": ["authentication.k8s.io"],
                "resources": ["tokenreviews"],
                "verbs": ["create"],
            },
        ],
    )
    role["apiVersion"] = "rbac.authorization.k8s.io/v1"
    del role["metadata"]["namespace"]
    binding = resource(
        "ClusterRoleBinding",
        "security-lab-spire-server",
        namespace=namespace,
        roleRef={
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role["metadata"]["name"],
        },
        subjects=[{"kind": "ServiceAccount", "name": "spire-server", "namespace": namespace}],
    )
    binding["apiVersion"] = "rbac.authorization.k8s.io/v1"
    del binding["metadata"]["namespace"]
    pod = {
        "serviceAccountName": "spire-server",
        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
        "containers": [
            {
                "name": "spire-server",
                "image": SERVICES["spire-server"]["image"],
                "args": ["-config", "/opt/spire/conf/server/server.conf"],
                "readinessProbe": {
                    "exec": {"command": ["/opt/spire/bin/spire-server", "healthcheck"]},
                    "periodSeconds": 2,
                    "timeoutSeconds": 3,
                    "failureThreshold": 45,
                },
                "resources": {
                    "requests": {"cpu": "50m", "memory": "64Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [
                    {"name": "config", "mountPath": "/opt/spire/conf/server", "readOnly": True},
                    {"name": "data", "mountPath": "/opt/spire/data/server"},
                ],
            }
        ],
        "volumes": [
            {"name": "config", "configMap": {"name": "spire-server-config"}},
            {"name": "data", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
        ],
    }
    return [
        resource("ServiceAccount", "spire-server", namespace=namespace),
        role,
        binding,
        configmap(
            "spire-server-config", {"server.conf": (CONFIG / "server.conf").read_text()}, namespace
        ),
        service("spire-server", 8081, namespace),
        controller("spire-server", pod, namespace),
    ]


def spire_agent_documents(bundle: str) -> list[dict[str, Any]]:
    namespace = "spire-system"
    role = resource(
        "ClusterRole",
        "security-lab-spire-agent",
        namespace=namespace,
        rules=[{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]}],
    )
    role["apiVersion"] = "rbac.authorization.k8s.io/v1"
    del role["metadata"]["namespace"]
    binding = resource(
        "ClusterRoleBinding",
        "security-lab-spire-agent",
        namespace=namespace,
        roleRef={
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role["metadata"]["name"],
        },
        subjects=[{"kind": "ServiceAccount", "name": "spire-agent", "namespace": namespace}],
    )
    binding["apiVersion"] = "rbac.authorization.k8s.io/v1"
    del binding["metadata"]["namespace"]
    pod = {
        "serviceAccountName": "spire-agent",
        "hostPID": True,
        "containers": [
            {
                "name": "spire-agent",
                "image": SERVICES["spire-agent"]["image"],
                "args": ["-config", "/opt/spire/conf/agent/agent.conf"],
                "env": [
                    {
                        "name": "MY_NODE_NAME",
                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                    }
                ],
                "securityContext": {"runAsUser": 0},
                "resources": {
                    "requests": {"cpu": "50m", "memory": "64Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                },
                "volumeMounts": [
                    {"name": "config", "mountPath": "/opt/spire/conf/agent", "readOnly": True},
                    {"name": "bundle", "mountPath": "/opt/spire/bootstrap", "readOnly": True},
                    {"name": "data", "mountPath": "/opt/spire/data/agent"},
                    {"name": "sockets", "mountPath": "/run/spire/sockets"},
                    {"name": "psat", "mountPath": "/var/run/secrets/tokens", "readOnly": True},
                ],
            }
        ],
        "volumes": [
            {"name": "config", "configMap": {"name": "spire-agent-config"}},
            {"name": "bundle", "configMap": {"name": "spire-bundle"}},
            {"name": "data", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
            {"name": "sockets", "hostPath": {"path": SOCKET, "type": "DirectoryOrCreate"}},
            {
                "name": "psat",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "path": "spire-agent",
                                "expirationSeconds": 600,
                                "audience": "spire-server",
                            }
                        }
                    ]
                },
            },
        ],
    }
    return [
        resource("ServiceAccount", "spire-agent", namespace=namespace),
        role,
        binding,
        configmap(
            "spire-agent-config", {"agent.conf": (CONFIG / "agent.conf").read_text()}, namespace
        ),
        configmap("spire-bundle", {"bundle.pem": bundle}, namespace),
        controller("spire-agent", pod, namespace, daemon=True),
    ]


def application_pod(name: str, image: str, command: list[str]) -> dict[str, Any]:
    account = "authz" if name == "authz-strict" else name
    container: dict[str, Any] = {
        "name": name,
        "image": image,
        "imagePullPolicy": "Never",
        "command": command,
        "env": [
            {"name": "SPIFFE_ENDPOINT_SOCKET", "value": "unix:///run/spire/sockets/agent.sock"}
        ],
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "500m", "memory": "384Mi"},
        },
        "securityContext": {
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "volumeMounts": [
            {"name": "sockets", "mountPath": "/run/spire/sockets", "readOnly": True},
            {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - isolated per-pod emptyDir
        ],
    }
    pod: dict[str, Any] = {
        "serviceAccountName": account,
        "securityContext": {"fsGroup": 1000},
        "automountServiceAccountToken": False,
        "containers": [container],
        "volumes": [
            {"name": "sockets", "hostPath": {"path": SOCKET, "type": "Directory"}},
            {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
        ],
    }
    if name.startswith("authz"):
        container["volumeMounts"].append(
            {"name": "policy", "mountPath": "/policy", "readOnly": True}
        )
        pod["volumes"].append(
            {"name": "policy", "hostPath": {"path": str(DATA / "policy"), "type": "Directory"}}
        )
    return pod


def applications(images: dict[str, str]) -> list[dict[str, Any]]:
    documents = [
        resource("ServiceAccount", name)
        for name in (
            "authz",
            "notes-a",
            "notes-b",
            "notes-rogue",
            "agent-research",
            "agent-intruder",
            "agent-impostor",
            "fhir",
        )
    ]
    for name in ("authz", "authz-strict", "notes-a", "notes-b", "notes-rogue"):
        command = [str(arg) for arg in SERVICES[name]["command"]]
        if name.startswith("authz"):
            command = [
                "--policy=/policy/policy.yaml" if arg.startswith("--policy=") else arg
                for arg in command
            ]
        port = next(int(arg.split("=", 1)[1]) for arg in command if arg.startswith("--port="))
        documents.extend(
            [controller(name, application_pod(name, images["auth"], command)), service(name, port)]
        )
    documents.extend(
        [
            controller(
                "fhir", application_pod("fhir", images["fhir"], ["node", "/lab/fhir-gateway.mjs"])
            ),
            service("fhir", 8443),
        ]
    )
    return documents


def server(args: list[str]) -> str:
    return checked(
        kube(
            ["exec", "deployment/spire-server", "--", "/opt/spire/bin/spire-server", *args],
            namespace="spire-system",
        )
    )


def register() -> None:
    parent = "spiffe://example.org/node/security-lab"
    server(
        [
            "entry",
            "create",
            "-node",
            "-parentID",
            "spiffe://example.org/spire/server",
            "-spiffeID",
            parent,
            "-selector",
            "k8s_psat:cluster:security-lab",
            "-selector",
            "k8s_psat:agent_ns:spire-system",
            "-selector",
            "k8s_psat:agent_sa:spire-agent",
        ]
    )
    for identity, account in (
        ("authz", "authz"),
        ("mcp/notes-a", "notes-a"),
        ("mcp/notes-b", "notes-b"),
        ("agent/research", "agent-research"),
        ("agent/intruder", "agent-intruder"),
        ("agent/intruder", "agent-impostor"),
        ("mcp/fhir", "fhir"),
    ):
        args = [
            "entry",
            "create",
            "-parentID",
            parent,
            "-spiffeID",
            "spiffe://example.org/" + identity,
            "-selector",
            "k8s:ns:" + NAMESPACE,
            "-selector",
            "k8s:sa:" + account,
            "-jwtSVIDTTL",
            "60",
            "-jwtSVIDIncludeJTI",
        ]
        if account == "fhir":
            args += ["-dns", "fhir.security-lab.svc.cluster.local"]
        server(args)


def owned_namespace(name: str) -> bool:
    result = kube(["get", "namespace", name, "--ignore-not-found", "-o", "json"])
    checked(result)
    if not result.stdout.strip():
        return False
    if (
        json.loads(result.stdout)["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
        != "security-lab"
    ):
        raise DemoRuntimeError("namespace belongs to another project")
    return True


def up() -> None:
    try:
        Policy.load(CONFIG / "policy.yaml")
    except (ValueError, KeyError, AttributeError):
        raise DemoRuntimeError("invalid lab policy") from None
    if any(owned_namespace(name) for name in (NAMESPACE, "spire-system")):
        raise DemoRuntimeError("lab namespaces already exist; run make down first")
    DATA.mkdir(exist_ok=True)
    (DATA / "policy").mkdir(exist_ok=True)
    (DATA / "policy/policy.yaml").write_text((CONFIG / "policy.yaml").read_text())
    images = build()
    apply(
        [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": OWNER}}
            for name in (NAMESPACE, "spire-system")
        ]
    )
    apply(spire_server_documents())
    checked(
        kube(
            ["rollout", "status", "deployment/spire-server", "--timeout=180s"],
            namespace="spire-system",
            timeout=200,
        )
    )
    bundle = server(["bundle", "show"])
    if "BEGIN CERTIFICATE" not in bundle or "PRIVATE KEY" in bundle:
        raise DemoRuntimeError("public SPIRE bundle unavailable")
    apply(spire_agent_documents(bundle))
    register()
    apply(applications(images))
    from scripts.kubernetes_ui import deploy  # noqa: PLC0415 - UI also uses the lab driver

    deploy()
    result = compose_command(
        [
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            "python",
            "agent-research",
            "/app/deploy/probe_svid.py",
            "ready",
        ],
        timeout=150,
    )
    if result.returncode or '"ok": true' not in result.stdout:
        raise DemoRuntimeError("workload readiness failed")
    print("Kubernetes security lab ready", flush=True)


def compose_command(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    if args[:2] == ["logs", "--no-log-prefix"] and len(args) == 3:
        return kube(["logs", "deployment/" + args[2]], timeout=timeout)
    if args[:1] == ["restart"] and len(args) == 2:
        checked(kube(["rollout", "restart", "deployment/" + args[1]]))
        return kube(
            ["rollout", "status", "deployment/" + args[1], "--timeout=90s"], timeout=timeout
        )
    if args[:4] != ["run", "--rm", "--no-deps", "-T"]:
        raise DemoRuntimeError("unsupported scenario operation")
    remaining = args[4:]
    entrypoint = "mcp-svid-agent"
    if remaining[:1] == ["--entrypoint"]:
        entrypoint, remaining = remaining[1], remaining[2:]
    if not remaining or remaining[0] not in ("agent-research", "agent-intruder", "agent-impostor"):
        raise DemoRuntimeError("unsupported transient service")
    name = "probe-" + uuid.uuid4().hex[:12]
    images = json.loads(IMAGES_FILE.read_text())
    pod = resource(
        "Pod",
        name,
        spec=application_pod(remaining[0], images["auth"], [entrypoint, *remaining[1:]]),
    )
    # Copying the research label does not copy its authenticated ServiceAccount.
    pod["metadata"]["labels"]["org.example.svid.workload"] = "agent-research"
    pod["spec"]["restartPolicy"] = "Never"
    apply([pod])
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            result = json.loads(checked(kube(["get", "pod", name, "-o", "json"])))
            statuses = result.get("status", {}).get("containerStatuses", [])
            terminated = statuses[0].get("state", {}).get("terminated") if statuses else None
            if terminated:
                logs = checked(kube(["logs", name]))
                return subprocess.CompletedProcess(args, terminated["exitCode"], logs, "")
            time.sleep(1)
        raise DemoRuntimeError("scenario pod timed out")
    finally:
        checked(kube(["delete", "pod", name, "--ignore-not-found", "--wait=false"]))


def down() -> None:
    if ISOLATED:
        raise DemoRuntimeError("Isolated identity cannot remove shared workloads")
    # Validate every namespace before removing anything, including cluster-scoped RBAC.
    selected = [
        name
        for name in (NAMESPACE, "spire-system", "security-lab-identity")
        if owned_namespace(name)
    ]
    from scripts.kubernetes_ui import stop  # noqa: PLC0415 - UI also uses the lab driver

    stop()
    from scripts.zitadel_demo import ACCOUNTS, PROFILE  # noqa: PLC0415 - optional identity profile

    PROFILE.unlink(missing_ok=True)
    ACCOUNTS.unlink(missing_ok=True)
    if selected:
        checked(kube(["delete", "namespace", *selected, "--timeout=90s"], timeout=120))
    for kind in ("clusterrolebinding", "clusterrole"):
        checked(
            kube(
                [
                    "delete",
                    kind,
                    "--selector=app.kubernetes.io/part-of=security-lab",
                    "--ignore-not-found",
                ]
            )
        )
    checked(guest(["rm", "--force", SOCKET + "/agent.sock"]))
    print("Only security lab namespaces, RBAC and workload socket removed", flush=True)


def render() -> None:
    from scripts.kubernetes_ui import documents  # noqa: PLC0415 - UI also uses the lab driver

    images = {
        "auth": "localhost/security-lab/auth@sha256:" + "0" * 64,
        "fhir": "localhost/security-lab/fhir@sha256:" + "0" * 64,
    }
    DATA.mkdir(exist_ok=True)
    path = DATA / "kubernetes-preview.yaml"
    path.write_text(
        yaml.safe_dump_all(
            [
                *spire_server_documents(),
                *spire_agent_documents("PUBLIC BUNDLE GENERATED AT RUNTIME"),
                *applications(images),
                *documents(),
            ],
            sort_keys=False,
        )
    )
    print("Review preview: " + str(path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=("runtime-up", "runtime-stop", "up", "down", "render", "build", "register"),
    )
    operation = parser.parse_args().operation
    try:
        if ISOLATED and operation in {"runtime-stop", "up", "down", "build", "register"}:
            raise DemoRuntimeError("Isolated identity cannot change shared workloads")
        if operation not in ("runtime-up", "render"):
            verify_instance()
        if operation == "runtime-up":
            runtime_up()
        elif operation == "runtime-stop":
            checked(lima(["stop", VM], timeout=120))
        elif operation == "up":
            up()
        elif operation == "down":
            down()
        elif operation == "build":
            build()
        elif operation == "register":
            register()
        else:
            render()
    except DemoRuntimeError as exc:
        print(json.dumps({"event": "runtime_failed", "reason": str(exc)}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
