"""The admission policy test must pass with the policy and fail without it."""

import json
import subprocess
from typing import Any

import pytest

from scripts import kubernetes_demo as lab
from scripts import kubernetes_ui as ui
from scripts import lab_admission as admission
from scripts.lab_runtime import DemoRuntimeError

DIGEST = "sha256:" + "a" * 64
IMAGES = {"auth": "auth-image" + "@" + DIGEST, "fhir": "fhir-image" + "@" + DIGEST}


class FakeApiServer:
    """Stands in for the API server: RBAC allows the tester to create, the policy may be absent."""

    def __init__(self, *, enforce: bool) -> None:
        self.enforce = enforce
        self.calls: list[list[str]] = []

    def __call__(
        self, args: list[str], *, namespace: str | None = None, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        if args[0] == "delete":
            return subprocess.CompletedProcess(args, 0, "", "")
        assert args[0] == "create" and "--dry-run=server" in args
        document = json.loads(input_text or "{}")
        pod = (
            document["spec"] if document["kind"] == "Pod" else document["spec"]["template"]["spec"]
        )
        principal = next(
            (a.split("=", 1)[1] for a in args if a.startswith("--as=")), "system:admin"
        )
        if self.enforce and (
            pod["serviceAccountName"] not in admission.ALLOWED_ACCOUNTS[admission.NAMESPACE]
            or principal not in admission.CREATORS
        ):
            message = f"denied request: ValidatingAdmissionPolicy '{admission.POLICY_POD}' denied"
            return subprocess.CompletedProcess(args, 1, "", message)
        return subprocess.CompletedProcess(args, 0, document["kind"] + "/admission-probe", "")


def test_negative_checks_pass_with_the_policy() -> None:
    server = FakeApiServer(enforce=True)
    verdicts = admission.check(server, lambda documents: None)
    assert [passed for _, passed in verdicts] == [True, True, True, True]
    assert server.calls[-1][0] == "delete"


def test_negative_checks_fail_without_the_policy() -> None:
    server = FakeApiServer(enforce=False)
    verdicts = admission.check(server, lambda documents: None)
    assert [passed for _, passed in verdicts] == [False, False, False, True]
    with pytest.raises(DemoRuntimeError, match="admission policy check failed"):
        admission.require(server, lambda documents: None)


def test_tester_permissions_are_removed_even_when_a_request_fails() -> None:
    deleted: list[bool] = []

    def broken(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[0] == "delete":
            deleted.append(True)
            return subprocess.CompletedProcess(args, 0, "", "")
        raise DemoRuntimeError("Lima operation failed or timed out")

    with pytest.raises(DemoRuntimeError):
        admission.check(broken, lambda documents: None)
    assert deleted == [True]


@pytest.mark.parametrize(
    "stderr",
    [
        'Error from server (Forbidden): pods is forbidden: User "x" cannot create resource "pods"',
        "connection refused",
        "",
    ],
)
def test_rbac_refusal_or_other_failure_is_not_counted_as_an_admission_denial(stderr: str) -> None:
    result = subprocess.CompletedProcess([], 1, "", stderr)
    assert admission.denied_by_policy(result) is False


def test_policies_deny_for_every_principal_and_fail_closed() -> None:
    documents = admission.documents()
    policies = [d for d in documents if d["kind"] == "ValidatingAdmissionPolicy"]
    bindings = [d for d in documents if d["kind"] == "ValidatingAdmissionPolicyBinding"]
    assert {p["metadata"]["name"] for p in policies} == {d["spec"]["policyName"] for d in bindings}
    for item in policies:
        assert item["spec"]["failurePolicy"] == "Fail"
        assert "matchConditions" not in item["spec"]
    for item in bindings:
        assert item["spec"]["validationActions"] == ["Deny"]
        selector = item["spec"]["matchResources"]["namespaceSelector"]["matchExpressions"][0]
        assert set(selector["values"]) == {"security-lab", "spire-system"}


def test_controllers_that_could_start_protected_identities_are_not_creators() -> None:
    names = " ".join(admission.CREATORS)
    for controller in ("job-controller", "cronjob-controller", "statefulset-controller"):
        assert controller not in names
    assert "system:masters" not in names
    assert not any(
        name.startswith("system:serviceaccount:security-lab") for name in admission.CREATORS
    )


def test_every_lab_workload_uses_an_allowed_account() -> None:
    rendered = [
        *lab.spire_server_documents(),
        *lab.spire_agent_documents("bundle"),
        *lab.applications(IMAGES),
        *ui.documents(),
    ]
    seen = 0
    for document in rendered:
        if document["kind"] not in {"Deployment", "DaemonSet"}:
            continue
        namespace = document["metadata"]["namespace"]
        account = document["spec"]["template"]["spec"]["serviceAccountName"]
        assert account in admission.ALLOWED_ACCOUNTS[namespace], (namespace, account)
        seen += 1
    assert seen == 9


def test_render_includes_the_policy() -> None:
    kinds = {d["kind"] for d in admission.documents()}
    assert kinds == {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
