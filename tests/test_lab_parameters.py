"""The Lima instance name and repository locations are parameters, with unchanged defaults."""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import kubernetes_demo as lab

ROOT = Path(__file__).resolve().parent.parent


def vm_name(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", "from scripts import kubernetes_demo as lab; print(lab.VM)"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", **environment},
        timeout=60,
    )


def test_default_vm_name_is_unchanged() -> None:
    result = vm_name({})
    assert result.returncode == 0
    assert result.stdout.strip() == "security-lab"


def test_environment_selects_the_lima_instance() -> None:
    result = vm_name({"LAB_VM": "svid-prod-lab"})
    assert result.returncode == 0
    assert result.stdout.strip() == "svid-prod-lab"


@pytest.mark.parametrize("name", ["", "Security-Lab", "../escape", "a b", "-lead", "x" * 64])
def test_unsafe_instance_names_are_refused(name: str) -> None:
    assert vm_name({"LAB_VM": name}).returncode != 0


def test_namespace_node_and_cluster_names_do_not_follow_the_instance_name() -> None:
    assert lab.NAMESPACE == "security-lab"
    profile = (lab.DEPLOY / "lima-kubernetes.yaml").read_text()
    assert "node-name: security-lab" in profile
    assert "cluster:security-lab" in (lab.ROOT / "scripts/kubernetes_demo.py").read_text()


def test_every_limactl_call_uses_the_configured_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def lima(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(lab, "VM", "svid-prod-lab")
    monkeypatch.setattr(lab, "lima", lima)
    lab.guest(["true"])
    assert calls[-1][:2] == ["shell", "svid-prod-lab"]
    lab.kube(["get", "pods"])
    assert calls[-1][:2] == ["shell", "svid-prod-lab"]


def test_new_instance_is_created_under_the_configured_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in lab.REPOS[1:]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "package.json").write_text("{}")
    calls: list[list[str]] = []

    def lima(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        listing = "other-vm\n" if args[0] == "list" else ""
        return subprocess.CompletedProcess(args, 0, listing, "")

    for name in lab.REPOS[1:]:
        monkeypatch.setenv("SVID_LAB_REPO_" + name.upper().replace("-", "_"), str(tmp_path / name))
    monkeypatch.setattr(lab, "VM", "svid-prod-lab")
    monkeypatch.setattr(lab, "ISOLATED", False)
    monkeypatch.setattr(lab, "DATA", tmp_path / "data")
    monkeypatch.setattr(lab, "lima", lima)
    lab.runtime_up()
    start = next(call for call in calls if call[0] == "start")
    assert "--name=svid-prod-lab" in start
    assert all(call[1] == "svid-prod-lab" for call in calls if call[0] == "shell")
    profile = yaml.safe_load((tmp_path / "data/lima-kubernetes.yaml").read_text())
    assert {mount["location"] for mount in profile["mounts"]} == {
        str(lab.repo_path(name)) for name in lab.REPOS
    }


def test_repository_locations_default_to_siblings_and_accept_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SVID_LAB_REPO_MCP_SPIFFE_BRIDGE", raising=False)
    monkeypatch.delenv("SVID_LAB_REPO_HIPAA_FHIR_MCP", raising=False)
    assert lab.repo_path("mcp-svid-auth") == lab.ROOT
    assert lab.repo_path("mcp-spiffe-bridge") == lab.ROOT.parent / "mcp-spiffe-bridge"
    monkeypatch.setenv("SVID_LAB_REPO_HIPAA_FHIR_MCP", str(tmp_path / "fhir"))
    assert lab.repo_path("hipaa-fhir-mcp") == (tmp_path / "fhir").resolve()
    assert lab.repo_path("mcp-spiffe-bridge") == lab.ROOT.parent / "mcp-spiffe-bridge"
