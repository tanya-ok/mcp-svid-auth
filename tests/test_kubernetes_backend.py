"""Check isolation and authorization failures without requiring a running VM."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_svid_auth.policy import Policy
from scripts import kubernetes_demo as lab
from scripts.lab_runtime import DemoRuntimeError


@pytest.mark.parametrize("foreign", ["security-lab", "spire-system", "security-lab-identity"])
def test_foreign_namespace_prevents_every_teardown_operation(
    foreign: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutations: list[list[str]] = []

    def kube(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["get", "namespace"]:
            labels = {"app.kubernetes.io/part-of": "other"} if args[2] == foreign else lab.OWNER
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"metadata": {"labels": labels}}), ""
            )
        mutations.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(lab, "kube", kube)
    with pytest.raises(DemoRuntimeError, match="another project"):
        lab.down()
    assert not mutations


def test_workload_tokens_are_not_mounted_and_identities_do_not_use_labels() -> None:
    for document in lab.applications(
        {"auth": "auth@sha256:" + "a" * 64, "fhir": "fhir@sha256:" + "b" * 64}
    ):
        if document["kind"] != "Deployment":
            continue
        pod = document["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True
        assert "ecs" not in document["metadata"]["name"]
    config = (lab.CONFIG / "agent.conf").read_text()
    assert "skip_kubelet_verification = false" in config
    assert 'WorkloadAttestor "docker"' not in config
    profile = yaml.safe_load((lab.DEPLOY / "lima-kubernetes.yaml").read_text())
    assert profile["containerd"] == {"system": False, "user": False}
    assert profile["mounts"] == []
    assert profile["ssh"]["forwardAgent"] is False


def test_fhir_token_checks_use_real_crypto() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the shared FHIR gateway")
    result = subprocess.run(
        [node, "--test", str(Path(__file__).with_name("token-verifier.test.mjs"))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_shared_policy_parses_with_real_authorization_code() -> None:
    policy = Policy.load(lab.CONFIG / "policy.yaml")
    assert policy.grant(
        "spiffe://example.org/agent/research",
        "https://fhir.security-lab.svc.cluster.local:8443/mcp",
        {"fhir:read"},
    ) == frozenset({"fhir:read"})
    assert set(policy.grants) == {
        "spiffe://example.org/agent/research",
        "spiffe://example.org/mcp/notes-a",
    }


def test_kubernetes_client_is_pinned_to_the_guest_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def guest(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(lab, "guest", guest)
    lab.kube(["get", "pods"])
    assert "--server=https://127.0.0.1:6443" in calls[0]
    assert "--kubeconfig=/etc/rancher/k3s/k3s.yaml" in calls[0]


def test_foreign_vm_is_refused_before_guest_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    instance = {
        "name": lab.VM,
        "cpus": 2,
        "memory": 4 * 1024**3,
        "config": {"mounts": [{"location": "/another-project", "writable": True}]},
    }
    monkeypatch.setattr(
        lab, "lima", lambda args: subprocess.CompletedProcess(args, 0, json.dumps(instance), "")
    )
    with pytest.raises(DemoRuntimeError, match="restricted mounts"):
        lab.verify_instance()


def test_private_umask_cannot_make_public_image_code_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in lab.REPOS:
        repository = tmp_path / name
        (repository / "src").mkdir(parents=True)
        (repository / "src/public.py").write_text("# Public source\n")
        files = (
            ["README.md", "LICENSE", "NOTICE", "pyproject.toml", "uv.lock"]
            if name == lab.REPOS[0]
            else ["package.json", "pnpm-lock.yaml", "tsconfig.json"]
        )
        if name == "mcp-spiffe-bridge":
            files += ["tsup.config.ts", "pnpm-workspace.yaml"]
        for filename in files:
            (repository / filename).write_text("public fixture\n")
        if name == "hipaa-fhir-mcp":
            (repository / "deploy/kubernetes").mkdir(parents=True)
            (repository / "deploy/kubernetes/public.mjs").write_text("// Public source\n")
        (repository / ".data").mkdir()
        (repository / ".data/private.json").write_text('{"synthetic": true}')
        (repository / ".git").mkdir()
        (repository / ".git/config").write_text("local metadata")

    context = tmp_path / "context"
    context.mkdir()
    monkeypatch.setattr(lab, "ROOT", tmp_path / lab.REPOS[0])
    monkeypatch.setattr(lab, "IMAGES_FILE", tmp_path / "images.json")

    def build(name: str, snapshot: Path, _file: Path) -> str:
        assert snapshot.stat().st_mode & 0o777 == 0o755
        for path in snapshot.rglob("*"):
            assert path.stat().st_mode & 0o777 == (0o755 if path.is_dir() else 0o644)
            assert ".data" not in path.parts and ".git" not in path.parts
        assert (snapshot / lab.REPOS[0] / "deploy/probe_svid.py").is_file()
        assert (snapshot / lab.REPOS[0] / "deploy/probe_mtls.py").is_file()
        return name + "@sha256:" + "a" * 64

    monkeypatch.setattr(lab, "build_image", build)
    previous = os.umask(0o077)
    try:
        assert set(lab.build_from_context(context)) == {"auth", "fhir"}
    finally:
        os.umask(previous)


def test_integration_staging_never_imports_sibling_source_into_clean_room(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "mcp-svid-auth"
    data = root / "deploy/.data"
    data.mkdir(parents=True)
    monkeypatch.setattr(lab, "ROOT", root)
    monkeypatch.setattr(lab, "DATA", data)

    def build(context: Path) -> dict[str, str]:
        assert context.is_relative_to(tmp_path / "hipaa-fhir-mcp/deploy/.data")
        assert not context.is_relative_to(root)
        return {"auth": "synthetic", "fhir": "synthetic"}

    monkeypatch.setattr(lab, "build_from_context", build)
    assert lab.build() == {"auth": "synthetic", "fhir": "synthetic"}
    assert not list((tmp_path / "hipaa-fhir-mcp/deploy/.data").iterdir())
