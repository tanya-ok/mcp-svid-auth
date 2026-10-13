"""Security boundaries of the local viewer, using real HTTP request handling."""

import asyncio
import base64
import json
import socket
import subprocess
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import httpx2
import pytest
import yaml

from scripts import headlamp_data as data
from scripts import kubernetes_demo as lab
from scripts import kubernetes_ui as ui
from scripts import zitadel_demo as identity
from scripts.lab_runtime import DemoRuntimeError
from scripts.local_identity_profile import NAMESPACE as IDENTITY_NAMESPACE


@pytest.fixture(autouse=True)
def isolated_identity_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Unit checks must not read or mutate the operator's live identity profile.
    monkeypatch.setattr(identity, "PROFILE", tmp_path / "human-auth.json")


def request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    upstream: Any = None,
    token: Any = None,
    observe: Any = None,
) -> httpx2.Response:
    async def run() -> httpx2.Response:
        transport = httpx2.MockTransport(
            upstream or (lambda _: httpx2.Response(200, json={"ok": True}))
        )
        app = ui.create_app(
            token or (lambda: "viewer-credential"),
            observe or (lambda: {"services": []}),
            "stop-capability",
            transport=transport,
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:4466"
        ) as client:
            return await client.request(method, path, headers=headers)

    return asyncio.run(run())


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.example.org"},
        {"Origin": "https://attacker.example.org"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
def test_remote_browser_and_rebinding_requests_are_denied(headers: dict[str, str]) -> None:
    def forbidden() -> str:
        pytest.fail("credentials must not be fetched for a rejected request")

    response = request("GET", "/config", headers=headers, token=forbidden)
    assert response.status_code == 403
    assert response.json() == {"error": "local_access_only"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("DELETE", "/clusters/main/api/v1/namespaces/security-lab/pods/example"),
        ("PATCH", "/clusters/main/apis/apps/v1/namespaces/security-lab/deployments/authz"),
        ("POST", "/clusters/main/api/v1/namespaces/security-lab/pods"),
        ("GET", "/clusters/main/api/v1/namespaces/security-lab/secrets"),
        ("GET", "/clusters/main/api/v1/namespaces/security-lab/pods/example/exec"),
    ],
)
def test_mutation_secrets_and_exec_never_reach_headlamp(method: str, path: str) -> None:
    def forbidden(_: httpx2.Request) -> httpx2.Response:
        pytest.fail("a rejected operation must not reach Headlamp")

    assert request(method, path, upstream=forbidden).status_code in {403, 405}


def test_proxy_replaces_credentials_and_identity_headers_and_strips_cookies() -> None:
    captured = []

    class Body(httpx2.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b'{"ok":true}'

    def upstream(req: httpx2.Request) -> httpx2.Response:
        captured.append(req)
        return httpx2.Response(
            200,
            stream=Body(),
            headers={"Set-Cookie": "credential=private", "Authorization": "private"},
        )

    response = request(
        "GET",
        "/config",
        headers={
            "Authorization": "Bearer incoming",
            "Cookie": "old=private",
            "X-Forwarded-User": "impersonator",
            "X-Forwarded-Id-Token": "incoming",
            "X-Forwarded-Email": "spoof@example.org",
        },
        upstream=upstream,
    )
    assert response.status_code == 200
    assert captured[0].headers["Host"] == "127.0.0.1:4466"
    assert captured[0].headers["X-Forwarded-User"] == "Local lab viewer"
    assert captured[0].headers["X-Forwarded-Id-Token"] == "viewer-credential"
    assert "authorization" not in captured[0].headers
    assert "cookie" not in captured[0].headers
    assert "x-forwarded-email" not in captured[0].headers
    assert "set-cookie" not in response.headers
    assert "authorization" not in response.headers


def test_credential_failure_is_closed_and_has_no_exception_text() -> None:
    def unavailable() -> str:
        raise RuntimeError("sensitive upstream diagnostics")

    response = request("GET", "/config", token=unavailable)
    assert response.status_code == 503
    assert response.json() == {"error": "ui_unavailable"}
    assert "sensitive" not in response.text


def test_observation_failure_does_not_return_old_status_or_exception_text() -> None:
    def unavailable() -> dict[str, Any]:
        raise RuntimeError("private diagnostic")

    response = request("GET", "/_lab/snapshot", observe=unavailable)
    assert response.status_code == 503
    assert response.json() == {"error": "lab_unavailable"}


def test_stop_requires_the_session_capability() -> None:
    assert request("POST", "/_lab/stop").status_code == 403
    assert (
        request("POST", "/_lab/stop", headers={"X-Lab-Stop": "stop-capability"}).status_code == 200
    )


def test_session_probe_requires_its_capability_and_never_requests_a_credential() -> None:
    def forbidden() -> str:
        pytest.fail("local lifecycle checks must not request a Kubernetes credential")

    for method, capability in (("GET", ""), ("GET", "wrong"), ("POST", "stop-capability")):
        assert (
            request(
                method, "/_lab/session", headers={"X-Lab-Session": capability}, token=forbidden
            ).status_code
            == 403
        )
    response = request(
        "GET", "/_lab/session", headers={"X-Lab-Session": "stop-capability"}, token=forbidden
    )
    assert response.json() == {"running": True}
    assert "stop-capability" not in response.text


def test_non_ascii_lifecycle_header_is_refused_without_server_error() -> None:
    app = ui.create_app(lambda: "unused", lambda: {}, "stop-capability")

    async def run() -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app), base_url="http://127.0.0.1:4466"
        ) as client:
            return await client.post("/_lab/stop", headers=[(b"x-lab-stop", b"\xff")])

    assert asyncio.run(run()).status_code == 403
    assert app.state.stop_requested is False


@pytest.fixture
def local_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"nonce": "a" * 43}))
    monkeypatch.setattr(ui, "SESSION", path)
    monkeypatch.setattr(ui, "LOCK", tmp_path / "launch.lock")
    return path


@pytest.mark.parametrize("reply", [{"running": False}, {"running": True, "private": "ignored"}])
def test_unverified_running_viewer_is_not_replaced(
    reply: dict[str, Any], local_session: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = httpx2.Client
    transport = httpx2.MockTransport(lambda _: httpx2.Response(200, json=reply))
    monkeypatch.setattr(httpx2, "Client", lambda **kwargs: original(transport=transport, **kwargs))
    with pytest.raises(DemoRuntimeError, match="UI session could not be verified"):
        ui.start()
    assert local_session.exists()


@pytest.mark.parametrize("operation", [ui.start, ui.stop])
def test_stale_record_is_preserved_if_a_loopback_port_is_occupied(
    operation: Any, local_session: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = httpx2.Client

    def unavailable(req: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("private diagnostic", request=req)

    monkeypatch.setattr(
        httpx2,
        "Client",
        lambda **kwargs: original(transport=httpx2.MockTransport(unavailable), **kwargs),
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        monkeypatch.setattr(ui, "PORT", listener.getsockname()[1])
        with pytest.raises(DemoRuntimeError, match="UI loopback port already in use"):
            operation()
    assert local_session.exists()


def test_start_is_idempotent_for_a_verified_viewer(
    local_session: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = httpx2.Client
    transport = httpx2.MockTransport(lambda _: httpx2.Response(200, json={"running": True}))
    monkeypatch.setattr(httpx2, "Client", lambda **kwargs: original(transport=transport, **kwargs))
    spawn = Mock(side_effect=AssertionError("must not start a duplicate viewer"))
    monkeypatch.setattr(subprocess, "Popen", spawn)
    ui.start()
    spawn.assert_not_called()
    assert local_session.exists()


def test_cleanup_removes_session_even_when_guest_shutdown_fails(
    local_session: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(args: list[str]) -> subprocess.CompletedProcess[str]:
        assert local_session.exists()
        if "show" in args:
            return subprocess.CompletedProcess(args, 0, "loaded\n", "")
        assert args == ["systemctl", "stop", ui.UNIT]
        return subprocess.CompletedProcess(args, 1, "", "private diagnostic")

    monkeypatch.setattr(lab, "guest", unavailable)
    with pytest.raises(DemoRuntimeError, match="Kubernetes lab operation failed"):
        ui.close_session(None)
    assert not local_session.exists()


@pytest.mark.parametrize("state", ["loaded", "not-found"])
def test_forwarder_cleanup_is_idempotent_and_uses_only_its_fixed_unit(
    state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def guest(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert args[2] == ui.UNIT
        return subprocess.CompletedProcess(args, 0, state if args[1] == "show" else "", "")

    monkeypatch.setattr(lab, "guest", guest)
    ui.stop_forwarder()
    assert len(calls) == (2 if state == "loaded" else 1)


def test_forwarder_shutdown_failure_is_not_silently_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def guest(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, "loaded", "")
        return subprocess.CompletedProcess(args, 1, "", "private diagnostic")

    monkeypatch.setattr(lab, "guest", guest)
    with pytest.raises(DemoRuntimeError, match="Kubernetes lab operation failed"):
        ui.stop_forwarder()


@pytest.mark.parametrize("status", [200, 503])
def test_backend_probe_has_no_credential_and_detects_unavailability(status: int) -> None:
    def upstream(req: httpx2.Request) -> httpx2.Response:
        assert req.method == "HEAD"
        assert req.headers["host"] == "127.0.0.1:4466"
        assert "authorization" not in req.headers
        assert "x-forwarded-id-token" not in req.headers
        return httpx2.Response(status)

    async def run() -> bool:
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(upstream)) as client:
            return await ui.backend_available(client)

    assert asyncio.run(run()) is (status == 200)


def test_rbac_has_no_cluster_grants_mutations_secrets_or_exec() -> None:
    docs = ui.documents()
    assert not any(doc["kind"] in {"ClusterRole", "ClusterRoleBinding", "Service"} for doc in docs)
    roles = [doc for doc in docs if doc["kind"] == "Role"]
    assert {doc["metadata"]["namespace"] for doc in roles} == {"security-lab", "spire-system"}
    for doc in roles:
        for rule in doc["rules"]:
            assert set(rule["verbs"]) <= {"get", "list", "watch"}
            assert not set(rule["resources"]) & {
                "secrets",
                "pods/exec",
                "pods/attach",
                "serviceaccounts/token",
            }
    pod = next(doc for doc in docs if doc["kind"] == "Deployment")["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert not any(volume.get("hostPath") for volume in pod["volumes"])
    assert "-listen-addr=127.0.0.1" in pod["containers"][0]["args"]
    assert "@sha256:" in pod["containers"][0]["image"]


@pytest.mark.parametrize("flag", [None, True])
def test_forwarding_must_also_ignore_loopback_listeners(
    flag: bool | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = yaml.safe_load((lab.DEPLOY / "lima-kubernetes.yaml").read_text())
    assert config["portForwards"][0]["guestIPMustBeZero"] is False
    config["mounts"] = [
        {"location": str(lab.ROOT.parent / name), "writable": False} for name in lab.REPOS
    ]
    config["portForwards"][0]["guestIPMustBeZero"] = flag
    instance = {"name": lab.VM, "cpus": 2, "memory": 4 * 1024**3, "config": config}
    monkeypatch.setattr(
        lab, "lima", lambda args: subprocess.CompletedProcess(args, 0, json.dumps(instance), "")
    )
    with pytest.raises(DemoRuntimeError, match="automatic host port forwarding"):
        lab.verify_instance()


def test_audit_projection_drops_unverified_fields_and_untrusted_identities() -> None:
    at = "2026-10-05T12:00:00+00:00"
    rows = [
        {
            "timestamp": at,
            "decision": "allow",
            "spiffe_id": "spiffe://example.org/agent/research",
            "reason": "sensitive details",
            "token": "private",
        },
        {"timestamp": at, "decision": "deny", "spiffe_id": "spiffe://example.org/unlisted"},
        {"timestamp": at, "decision": [], "spiffe_id": []},
    ]
    result = data.audit_rows("authz", "\n".join(json.dumps(row) for row in rows))
    assert len(result) == 2
    assert set(result[0]) == {"at", "source", "outcome", "caller"}
    assert result[1]["caller"] is None
    assert "sensitive" not in json.dumps(result)
    assert "private" not in json.dumps(result)


def test_demo_projection_uses_known_titles_and_requires_all_scenarios(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report = {
        "backend": "lima-kubernetes-containerd",
        "timestamp": "2026-10-05T12:00:00+00:00",
        "passed": True,
        "results": [{"scenario": 1, "passed": True, "description": "sensitive details"}],
        "failure": "private diagnostics",
    }
    path.write_text(json.dumps(report))
    result = data.demo_result(path)
    assert result is not None and result["passed"] is False
    assert len(result["results"]) == 18
    assert "sensitive" not in json.dumps(result)
    assert "private" not in json.dumps(result)


def test_identity_service_projection_excludes_pod_details_and_unknown_workloads() -> None:
    observations: dict[str, dict[str, Any]] = {
        namespace: {"items": []} for namespace in ("security-lab", "spire-system")
    }
    observations[IDENTITY_NAMESPACE] = {
        "items": [
            {
                "kind": "Deployment",
                "metadata": {"name": "zitadel", "annotations": {"private": "diagnostic"}},
                "spec": {"replicas": 1, "private": "credential"},
                "status": {"readyReplicas": 1},
            },
            {
                "kind": "Pod",
                "metadata": {"labels": {"app": "zitadel"}},
                "status": {"containerStatuses": [{"restartCount": 2}]},
                "spec": {"env": [{"value": "credential"}]},
            },
            {"kind": "Deployment", "metadata": {"name": "unrelated-private-workload"}},
        ]
    }
    rows = data.service_rows(observations)
    assert len(rows) == 12
    provider = next(row for row in rows if row["name"] == "zitadel")
    assert provider["ready"] == 1 and provider["restarts"] == 2
    assert "private" not in json.dumps(rows) and "credential" not in json.dumps(rows)


def test_unowned_identity_namespace_stops_snapshot_before_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "human-auth.json"
    profile.write_text("{}")
    monkeypatch.setattr(data, "PROFILE", profile)
    monkeypatch.setattr(lab, "owned_namespace", lambda _: False)
    monkeypatch.setattr(data, "observe", Mock(side_effect=AssertionError("must not inspect")))
    with pytest.raises(DemoRuntimeError, match="Human identity observation unavailable"):
        data.snapshot()


def test_ui_policy_is_actual_file_and_refuses_unknown_values(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "trust_domain: example.org\nclients:\n"
        "  - spiffe_id: spiffe://example.org/agent/research\n"
        "    resources:\n      http://notes-b:8102/mcp: [notes:read]\n"
    )
    assert data.permissions(path)[0]["scopes"] == ["notes:read"]
    path.write_text(
        "trust_domain: example.org\nclients:\n"
        "  - spiffe_id: spiffe://example.org/unlisted\n    resources: {}\n"
    )
    with pytest.raises(DemoRuntimeError, match="unexpected UI policy"):
        data.permissions(path)


@pytest.mark.parametrize("malformed", [False, True])
def test_expired_ui_credential_is_removed_when_refresh_fails(
    malformed: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    viewer = ui.ViewerToken()
    claims = {"sub": "system:serviceaccount:security-lab:headlamp", "exp": time.time() + 600}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    minted = "header." + payload + ".signature"
    monkeypatch.setattr(lab, "kube", lambda args: subprocess.CompletedProcess(args, 0, minted, ""))
    assert viewer.get() == minted
    viewer.expires = time.time() - 1
    if malformed:
        payload = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
        monkeypatch.setattr(
            lab,
            "kube",
            lambda args: subprocess.CompletedProcess(args, 0, "h." + payload + ".s", ""),
        )
    else:
        monkeypatch.setattr(
            lab, "kube", lambda args: subprocess.CompletedProcess(args, 1, "", "sensitive details")
        )
    with pytest.raises(DemoRuntimeError, match="UI credential unavailable"):
        viewer.get()
    assert viewer.value == ""
    assert viewer.expires == 0


def test_port_preflight_refuses_a_foreign_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        monkeypatch.setattr(ui, "PORT", listener.getsockname()[1])
        with pytest.raises(DemoRuntimeError, match="UI loopback port already in use"):
            ui.check_ports()


def test_oversized_permission_review_is_rejected_before_credential_use() -> None:
    def forbidden() -> str:
        pytest.fail("oversized request must not obtain a credential")

    app = ui.create_app(forbidden, lambda: {}, "stop-capability")

    async def run() -> httpx2.Response:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app), base_url="http://127.0.0.1:4466"
        ) as client:
            return await client.post(sorted(ui.AUTH_QUERIES)[0], content=b"x" * 65537)

    assert asyncio.run(run()).status_code == 413


def test_isolated_panel_cannot_start_without_human_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ui, "ISOLATED", True)
    with pytest.raises(DemoRuntimeError, match="requires a human identity profile"):
        ui.start()


def test_isolated_panel_cannot_create_shared_workloads(monkeypatch: pytest.MonkeyPatch) -> None:
    create = Mock()
    deploy = Mock()
    monkeypatch.setattr(ui, "ISOLATED", True)
    monkeypatch.setattr(lab, "runtime_up", Mock())
    monkeypatch.setattr(lab, "owned_namespace", lambda _: False)
    monkeypatch.setattr(lab, "up", create)
    monkeypatch.setattr(ui, "deploy", deploy)
    with pytest.raises(DemoRuntimeError, match="requires existing shared workloads"):
        ui.prepare_workloads()
    create.assert_not_called()
    deploy.assert_not_called()


def test_isolated_public_port_does_not_change_headlamp_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ui, "PORT", 4566)
    captured: list[httpx2.Request] = []

    def upstream(request: httpx2.Request) -> httpx2.Response:
        captured.append(request)
        return httpx2.Response(200, stream=httpx2.ByteStream(b"read-only"))

    app = ui.create_app(
        lambda: "viewer-credential",
        lambda: {},
        "stop-capability",
        transport=httpx2.MockTransport(upstream),
    )

    async def run() -> None:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app), base_url="http://127.0.0.1:4566"
        ) as browser:
            assert (await browser.get("/")).status_code == 200

    asyncio.run(run())
    assert captured[0].headers["host"] == "127.0.0.1:4466"
