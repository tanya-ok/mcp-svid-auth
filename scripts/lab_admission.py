"""ServiceAccount admission policy for the lab, and the negative test that proves it.

A SPIFFE ID is granted to whoever can start a pod with the matching ServiceAccount, so
the lab limits both which ServiceAccounts may be used and which principals may launch
workloads with them. The policy is a ValidatingAdmissionPolicy evaluated by the API
server for every principal, including cluster administrators.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from subprocess import CompletedProcess
from typing import Any

from scripts.lab_runtime import DemoRuntimeError

NAMESPACE = "security-lab"
SPIRE_NAMESPACE = "spire-system"
POLICY_POD = "security-lab-serviceaccounts-pod"
POLICY_TEMPLATE = "security-lab-serviceaccounts-template"
TESTER = "lab-admission-tester"

APPLICATION_ACCOUNTS = (
    "authz",
    "notes-a",
    "notes-b",
    "notes-rogue",
    "agent-research",
    "agent-intruder",
    "agent-impostor",
    "fhir",
)
ALLOWED_ACCOUNTS = {
    NAMESPACE: (*APPLICATION_ACCOUNTS, "headlamp"),
    SPIRE_NAMESPACE: ("spire-server", "spire-agent"),
}
# The lab operator (k3s admin certificate) and the controllers that turn a Deployment or
# DaemonSet, which the operator created, into ReplicaSets and pods. Job, CronJob and
# StatefulSet controllers are deliberately absent: they cannot start protected identities.
CREATORS = (
    "system:admin",
    "system:serviceaccount:kube-system:deployment-controller",
    "system:serviceaccount:kube-system:replicaset-controller",
    "system:serviceaccount:kube-system:daemon-set-controller",
)

Kube = Callable[..., CompletedProcess[str]]


def literal(values: tuple[str, ...]) -> str:
    return json.dumps(list(values))


def policy(
    name: str, spec_path: str, operations: list[str], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    account = (
        "has(variables.spec.serviceAccountName) ? variables.spec.serviceAccountName : 'default'"
    )
    previous = (
        f"request.operation == 'CREATE' ? '' : (has(oldObject.{spec_path}.serviceAccountName)"
        f" ? oldObject.{spec_path}.serviceAccountName : 'default')"
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/part-of": "security-lab"}},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    dict(rule, apiVersions=["v1"], operations=operations) for rule in rules
                ]
            },
            "variables": [
                {"name": "spec", "expression": f"object.{spec_path}"},
                {"name": "account", "expression": account},
                {"name": "previous", "expression": previous},
                {
                    "name": "changed",
                    "expression": (
                        "request.operation == 'CREATE' || variables.account != variables.previous"
                    ),
                },
                {
                    "name": "allowed",
                    "expression": (
                        f"namespaceObject.metadata.name == '{SPIRE_NAMESPACE}' ? "
                        f"variables.account in {literal(ALLOWED_ACCOUNTS[SPIRE_NAMESPACE])} : "
                        f"variables.account in {literal(ALLOWED_ACCOUNTS[NAMESPACE])}"
                    ),
                },
            ],
            "validations": [
                {
                    "expression": "!variables.changed || variables.allowed",
                    "message": "ServiceAccount is not on the lab allow list",
                    "reason": "Forbidden",
                },
                {
                    "expression": (
                        f"!variables.changed || request.userInfo.username in {literal(CREATORS)}"
                    ),
                    "message": "principal may not launch workloads with a lab ServiceAccount",
                    "reason": "Forbidden",
                },
            ],
        },
    }


def binding(name: str) -> dict[str, Any]:
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/part-of": "security-lab"}},
        "spec": {
            "policyName": name,
            "validationActions": ["Deny"],
            "matchResources": {
                "namespaceSelector": {
                    "matchExpressions": [
                        {
                            "key": "kubernetes.io/metadata.name",
                            "operator": "In",
                            "values": [NAMESPACE, SPIRE_NAMESPACE],
                        }
                    ]
                }
            },
        },
    }


def documents() -> list[dict[str, Any]]:
    return [
        policy(
            POLICY_POD,
            "spec",
            ["CREATE"],
            [{"apiGroups": [""], "resources": ["pods"]}],
        ),
        binding(POLICY_POD),
        policy(
            POLICY_TEMPLATE,
            "spec.template.spec",
            ["CREATE", "UPDATE"],
            [
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments", "daemonsets", "replicasets", "statefulsets"],
                },
                {"apiGroups": ["batch"], "resources": ["jobs"]},
            ],
        ),
        binding(POLICY_TEMPLATE),
    ]


def probe_pod(account: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "admission-probe", "namespace": NAMESPACE},
        "spec": {
            "serviceAccountName": account,
            "automountServiceAccountToken": False,
            "containers": [{"name": "probe", "image": "localhost/security-lab/auth:local"}],
        },
    }


def probe_deployment(account: str) -> dict[str, Any]:
    pod = probe_pod(account)
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "admission-probe", "namespace": NAMESPACE},
        "spec": {
            "selector": {"matchLabels": {"app": "admission-probe"}},
            "template": {"metadata": {"labels": {"app": "admission-probe"}}, "spec": pod["spec"]},
        },
    }


def tester_rbac() -> list[dict[str, Any]]:
    return [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": TESTER, "namespace": NAMESPACE},
            "rules": [
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
                {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"]},
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": TESTER, "namespace": NAMESPACE},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": TESTER},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": TESTER}],
        },
    ]


def denied_by_policy(result: CompletedProcess[str]) -> bool:
    """True only for an admission denial, never for an RBAC refusal or another error."""
    return result.returncode != 0 and any(
        f"ValidatingAdmissionPolicy '{name}'" in result.stderr
        for name in (POLICY_POD, POLICY_TEMPLATE)
    )


def admitted(result: CompletedProcess[str]) -> bool:
    return result.returncode == 0


def attempt(kube: Kube, document: dict[str, Any], principal: str | None) -> CompletedProcess[str]:
    """Server-side dry run: the request passes authorization and admission but stores nothing."""
    impersonation = [f"--as={principal}"] if principal else []
    return kube(
        ["create", "--dry-run=server", "--output=name", "--filename=-", *impersonation],
        namespace=None,
        input_text=json.dumps(document),
    )


def check(kube: Kube, apply: Callable[[list[dict[str, Any]]], None]) -> list[tuple[str, bool]]:
    """Return one verdict per expectation; every verdict must be True."""
    apply(tester_rbac())
    try:
        return [
            (
                "unprivileged principal denied a pod with an allowed ServiceAccount",
                denied_by_policy(attempt(kube, probe_pod("agent-research"), TESTER)),
            ),
            (
                "unprivileged principal denied a Deployment with an allowed ServiceAccount",
                denied_by_policy(attempt(kube, probe_deployment("agent-research"), TESTER)),
            ),
            (
                "ServiceAccount outside the allow list denied even for the administrator",
                denied_by_policy(attempt(kube, probe_pod("default"), None)),
            ),
            (
                "operator admitted a pod with an allowed ServiceAccount",
                admitted(attempt(kube, probe_pod("agent-research"), None)),
            ),
        ]
    finally:
        kube(
            ["delete", "rolebinding,role", TESTER, "--ignore-not-found"],
            namespace=NAMESPACE,
        )


def require(kube: Kube, apply: Callable[[list[dict[str, Any]]], None]) -> None:
    if not all(passed for _, passed in check(kube, apply)):
        raise DemoRuntimeError("ServiceAccount admission policy check failed")
