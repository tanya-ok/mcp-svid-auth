"""Bounded, allowlisted observations for the local read-only UI."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_svid_auth.policy import Policy
from scripts import kubernetes_demo as lab
from scripts.lab_runtime import DemoRuntimeError
from scripts.local_identity_profile import ISOLATED
from scripts.local_identity_profile import NAMESPACE as IDENTITY_NAMESPACE
from scripts.zitadel_demo import PROFILE

SERVICES = (
    ("spire-server", "spire-system", "Identity authority", "SPIRE"),
    ("spire-agent", "spire-system", "Workload attestation", "SPIRE"),
    ("authz", "security-lab", "Authorization", "mcp-svid-auth"),
    ("authz-strict", "security-lab", "Single-use assertion comparison", "mcp-svid-auth"),
    ("notes-a", "security-lab", "Scoped MCP tools", "mcp-svid-auth"),
    ("notes-b", "security-lab", "Upstream MCP tools", "mcp-svid-auth"),
    ("notes-rogue", "security-lab", "Untrusted-issuer negative fixture", "mcp-svid-auth"),
    (
        "fhir",
        "security-lab",
        "mTLS gateway and synthetic tools",
        "hipaa-fhir-mcp + mcp-spiffe-bridge",
    ),
    ("headlamp", "security-lab", "Read-only interface", "Headlamp"),
)
IDENTITIES = (
    ("authz", "authz"),
    ("mcp/notes-a", "notes-a"),
    ("mcp/notes-b", "notes-b"),
    ("agent/research", "agent-research"),
    ("agent/intruder", "agent-intruder"),
    ("agent/intruder", "agent-impostor"),
    ("mcp/fhir", "fhir"),
)
IDENTITY_SERVICES = (
    ("zitadel", IDENTITY_NAMESPACE, "Human identity provider", "ZITADEL"),
    ("zitadel-login", IDENTITY_NAMESPACE, "Human sign-in", "ZITADEL Login V2"),
    ("identity-postgres", IDENTITY_NAMESPACE, "Ephemeral identity data", "PostgreSQL"),
)
CALLERS = {"spiffe://example.org/" + identity for identity, _ in IDENTITIES}
RESOURCES = {
    "http://notes-a:8101/mcp",
    "http://notes-b:8102/mcp",
    "https://fhir.security-lab.svc.cluster.local:8443/mcp",
}
SCOPES = {"notes:read", "notes:write", "fhir:read"}
SCENARIOS = (
    "Allowlisted read and write",
    "Per-tool scope denial",
    "Unlisted identity denied",
    "Cross-resource replay denied",
    "Copied labels cannot copy ServiceAccount identity",
    "Untrusted issuer refused",
    "Explicit cached SVID reuse",
    "Own identity for upstream calls",
    "Revoked grants deny new tokens",
    "Identity does not establish intent",
    "Signing-key restart and public-key refresh",
    "SVID renewal and expired assertion denial",
    "Strict single-use assertion denial",
    "Audit links and terminal checkpoint",
    "FHIR mTLS and OAuth allow/deny cases",
    "Disallowed client certificate refused",
    "Missing client certificate refused",
    "FHIR audit caller and safe output",
)


def timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC).isoformat() if parsed.utcoffset() is not None else None


def audit_rows(source: str, text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines()[-64:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        at = timestamp(item.get("timestamp"))
        outcome = item.get("decision", item.get("status"))
        if (
            at is None
            or not isinstance(outcome, str)
            or outcome not in {"allow", "deny", "issued", "success", "error"}
        ):
            continue
        caller = item.get("spiffe_id")
        rows.append(
            {
                "at": at,
                "source": source,
                "outcome": outcome,
                "caller": caller if isinstance(caller, str) and caller in CALLERS else None,
            }
        )
    return rows


def demo_result(path: Path) -> dict[str, Any] | None:
    if not path.is_file() or path.stat().st_size > 65536:
        return None
    try:
        item = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(item, dict) or item.get("backend") != "lima-kubernetes-containerd":
        return None
    at = timestamp(item.get("timestamp"))
    results = item.get("results")
    if at is None or not isinstance(results, list) or len(results) > 18:
        return None
    completed = {
        row.get("scenario")
        for row in results
        if isinstance(row, dict) and type(row.get("scenario")) is int and row.get("passed") is True
    }
    return {
        "at": at,
        "passed": item.get("passed") is True and completed == set(range(1, 19)),
        "results": [
            {"number": number, "title": title, "passed": number in completed}
            for number, title in enumerate(SCENARIOS, 1)
        ],
    }


def permissions(path: Path) -> list[dict[str, Any]]:
    policy = Policy.load(path)
    if policy.trust_domain != "example.org":
        raise DemoRuntimeError("unexpected UI policy")
    rows = []
    for caller, resources in policy.grants.items():
        if caller not in CALLERS:
            raise DemoRuntimeError("unexpected UI policy")
        for resource, scopes in resources.items():
            if resource not in RESOURCES or not scopes <= SCOPES:
                raise DemoRuntimeError("unexpected UI policy")
            rows.append({"caller": caller, "resource": resource, "scopes": sorted(scopes)})
    return rows


def observe(namespace: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(
        lab.checked(
            lab.kube(["get", "pods,deployments,daemonsets", "-o", "json"], namespace=namespace)
        )
    )
    return value


def logs(name: str) -> str:
    return lab.checked(lab.kube(["logs", "deployment/" + name, "--tail=64", "--limit-bytes=65536"]))


def guest_memory() -> dict[str, float]:
    fields = {}
    for line in lab.checked(lab.guest(["cat", "/proc/meminfo"])).splitlines():
        parts = line.split()
        if parts[0] in {"MemTotal:", "MemAvailable:"}:
            fields[parts[0]] = int(parts[1]) / 1024
    return {"used_mib": round(fields["MemTotal:"] - fields["MemAvailable:"], 1)}


def service_rows(observations: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    selected = SERVICES + (IDENTITY_SERVICES if IDENTITY_NAMESPACE in observations else ())
    for name, namespace, role, project in selected:
        items = observations[namespace].get("items", [])
        controllers = [
            item
            for item in items
            if item.get("kind") in {"Deployment", "DaemonSet"}
            and item.get("metadata", {}).get("name") == name
        ]
        status = controllers[0].get("status", {}) if controllers else {}
        desired = (
            status.get("desiredNumberScheduled", controllers[0].get("spec", {}).get("replicas", 1))
            if controllers
            else 1
        )
        ready = status.get("numberReady", status.get("readyReplicas", 0))
        restarts = sum(
            state.get("restartCount", 0)
            for item in items
            if item.get("kind") == "Pod"
            and item.get("metadata", {}).get("labels", {}).get("app") == name
            for state in item.get("status", {}).get("containerStatuses", [])
        )
        result.append(
            {
                "name": name,
                "namespace": namespace,
                "role": role,
                "project": project,
                "desired": desired,
                "ready": ready,
                "restarts": restarts,
            }
        )
    return result


def snapshot() -> dict[str, Any]:
    evidence = lab.DATA
    if ISOLATED:
        source = Path(os.environ.get("SVID_LAB_MOUNT_ROOT", str(lab.ROOT))).resolve()
        evidence = source / "deploy" / ".data"
    namespaces = ["security-lab", "spire-system"]
    if PROFILE.exists():
        if not lab.owned_namespace(IDENTITY_NAMESPACE):
            raise DemoRuntimeError("Human identity observation unavailable")
        namespaces.append(IDENTITY_NAMESPACE)
    with ThreadPoolExecutor(max_workers=7) as pool:
        observations = {name: pool.submit(observe, name) for name in namespaces}
        streams = {
            name: pool.submit(logs, name) for name in ("authz", "notes-a", "notes-b", "fhir")
        }
        memory = pool.submit(guest_memory)
        audit = [row for name, job in streams.items() for row in audit_rows(name, job.result())]
        return {
            "version": 1,
            "at": datetime.now(UTC).isoformat(),
            "services": service_rows({name: job.result() for name, job in observations.items()}),
            "memory": memory.result(),
            "identities": [
                {
                    "workload": account,
                    "id": "spiffe://example.org/" + identity,
                    "namespace": "security-lab",
                    "account": account,
                }
                for identity, account in IDENTITIES
            ],
            "permissions": permissions(evidence / "policy/policy.yaml"),
            "audit": sorted(audit, key=lambda row: row["at"], reverse=True)[:60],
            "demo": demo_result(evidence / "demo-report.json"),
        }
