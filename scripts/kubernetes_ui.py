"""Headlamp with a local identity-aware proxy and bounded lab observations."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx2
import uvicorn
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route

from scripts import headlamp_data
from scripts import kubernetes_demo as lab
from scripts import zitadel_demo as identity
from scripts.identity_proxy import create_proxy
from scripts.lab_runtime import DemoRuntimeError
from scripts.local_identity_profile import (
    IDENTITY_PORT,
    IDENTITY_TUNNEL_PORT,
    ISOLATED,
    LOGIN_PORT,
    LOGIN_TUNNEL_PORT,
    VIEWER_PORT,
    VIEWER_TUNNEL_PORT,
)
from scripts.oidc_gate import OidcGate, Settings

PORT = VIEWER_PORT
TUNNEL_PORT = VIEWER_TUNNEL_PORT
BACKEND = f"http://127.0.0.1:{TUNNEL_PORT}"
SESSION = identity.DATA / "headlamp-session.json"
LOCK = identity.DATA / "headlamp-launch.lock"
UNIT = "security-lab-passkey-headlamp-forward" if ISOLATED else "security-lab-headlamp-forward"
PLUGIN = lab.DEPLOY / "headlamp"
HEADLAMP_IMAGE = (
    "ghcr.io/headlamp-k8s/headlamp:v0.45.0"
    "@sha256:db3f0e0fc58d358d41daa3fe7fc852437552c7ee873c3645470f7b86a8e0db49"
)
AUTH_QUERIES = {
    "/clusters/main/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
    "/clusters/main/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
    "/clusters/main/apis/authentication.k8s.io/v1/selfsubjectreviews",
}


def documents() -> list[dict[str, Any]]:
    result = [lab.resource("ServiceAccount", "headlamp")]
    for namespace in ("security-lab", "spire-system"):
        role = lab.resource(
            "Role",
            "security-lab-headlamp",
            namespace=namespace,
            rules=[
                {
                    "apiGroups": [""],
                    "resources": ["pods", "services", "events"],
                    "verbs": ["get", "list", "watch"],
                },
                {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments", "daemonsets", "replicasets"],
                    "verbs": ["get", "list", "watch"],
                },
            ],
        )
        binding = lab.resource(
            "RoleBinding",
            "security-lab-headlamp",
            namespace=namespace,
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "security-lab-headlamp",
            },
            subjects=[{"kind": "ServiceAccount", "name": "headlamp", "namespace": "security-lab"}],
        )
        role["apiVersion"] = binding["apiVersion"] = "rbac.authorization.k8s.io/v1"
        result.extend([role, binding])
    result.append(
        lab.configmap(
            "headlamp-plugin",
            {name: (PLUGIN / name).read_text() for name in ("main.js", "package.json")},
            "security-lab",
        )
    )
    pod = {
        "serviceAccountName": "headlamp",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
        "containers": [
            {
                "name": "headlamp",
                "image": HEADLAMP_IMAGE,
                "args": [
                    "-in-cluster",
                    "-listen-addr=127.0.0.1",
                    "-port=4466",
                    "-proxy-auth=true",
                    "-plugins-dir=/headlamp/plugins",
                    "-user-plugins-dir=/var/headlamp/user-plugins",
                    "-watch-plugins-changes=false",
                    "-enable-dynamic-clusters=false",
                ],
                "env": [
                    {"name": "HEADLAMP_CONFIG_TRACING_ENABLED", "value": "false"},
                    {"name": "HEADLAMP_CONFIG_METRICS_ENABLED", "value": "false"},
                    {"name": "HEADLAMP_STATIC_PLUGINS_DIR", "value": ""},
                    {"name": "XDG_CONFIG_HOME", "value": "/var/headlamp/config"},
                    {"name": "XDG_CACHE_HOME", "value": "/var/headlamp/cache"},
                    {"name": "TMPDIR", "value": "/var/headlamp"},
                ],
                "readinessProbe": {
                    "exec": {
                        "command": ["/bin/sh", "-c", "wget -qO- http://127.0.0.1:4466/ >/dev/null"]
                    },
                    "periodSeconds": 2,
                    "timeoutSeconds": 3,
                    "failureThreshold": 60,
                },
                "resources": {
                    "requests": {"cpu": "25m", "memory": "64Mi"},
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "volumeMounts": [
                    {
                        "name": "plugin",
                        "mountPath": "/headlamp/plugins/security-lab",
                        "readOnly": True,
                    },
                    {"name": "tmp", "mountPath": "/var/headlamp"},
                    {
                        "name": "api",
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                        "readOnly": True,
                    },
                ],
            }
        ],
        "volumes": [
            {"name": "plugin", "configMap": {"name": "headlamp-plugin"}},
            {"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}},
            {
                "name": "api",
                "projected": {
                    "sources": [
                        {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                        {
                            "configMap": {
                                "name": "kube-root-ca.crt",
                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                            }
                        },
                        {
                            "downwardAPI": {
                                "items": [
                                    {
                                        "path": "namespace",
                                        "fieldRef": {"fieldPath": "metadata.namespace"},
                                    }
                                ]
                            }
                        },
                    ]
                },
            },
        ],
    }
    result.append(lab.controller("headlamp", pod))
    return result


def deploy() -> None:
    lab.apply(documents())
    lab.checked(
        lab.kube(["rollout", "status", "deployment/headlamp", "--timeout=180s"], timeout=200)
    )


class ViewerToken:
    """Only the local proxy holds the short-lived, read-only Kubernetes credential."""

    def __init__(self) -> None:
        self.value = ""
        self.expires = 0.0
        self.lock = threading.Lock()

    def get(self) -> str:
        with self.lock:
            now = time.time()
            if now + 120 < self.expires:
                return self.value
            try:
                value = lab.checked(
                    lab.kube(["create", "token", "headlamp", "--duration=10m"])
                ).strip()
                payload = value.split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                expiry = float(claims["exp"])
                if (
                    claims["sub"] != "system:serviceaccount:security-lab:headlamp"
                    or not now < expiry <= now + 650
                ):
                    raise ValueError
            except (ValueError, TypeError, KeyError, IndexError, DemoRuntimeError):
                self.value, self.expires = "", 0.0
                raise DemoRuntimeError("UI credential unavailable") from None
            self.value, self.expires = value, expiry
            return self.value


class ObservationCache:
    def __init__(self, read: Callable[[], dict[str, Any]]) -> None:
        self.read = read
        self.value: dict[str, Any] | None = None
        self.at = 0.0
        self.lock = threading.Lock()

    def get(self) -> dict[str, Any]:
        with self.lock:
            if self.value is None or time.monotonic() - self.at > 10:
                self.value = self.read()
                self.at = time.monotonic()
            return self.value


def local_request(request: Request) -> bool:
    expected = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
    if request.headers.get("host") not in expected:
        return False
    origin = request.headers.get("origin")
    if origin and origin not in {"http://" + host for host in expected}:
        return False
    return request.headers.get("sec-fetch-site") not in {"cross-site", "same-site"}


def forwarded_headers(request: Request, credential: str) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower()
        in {"accept", "accept-encoding", "content-type", "user-agent", "if-none-match"}
    }
    headers.update(
        {
            "Host": "127.0.0.1:4466",
            "X-Forwarded-User": "Local lab viewer",
            "X-Forwarded-Id-Token": credential,
        }
    )
    return headers


def create_app(
    token: Callable[[], str],
    observe: Callable[[], dict[str, Any]],
    stop_nonce: str,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
    gate: OidcGate | None = None,
) -> Starlette:
    cache = ObservationCache(observe)
    app = Starlette()

    async def preflight(request: Request) -> Response | None:  # noqa: PLR0911 - explicit auth denials
        callback = (
            gate is not None
            and request.method == "GET"
            and request.url.path == "/_auth/callback"
            and request.headers.get("host") == f"localhost:{PORT}"
            and request.headers.get("origin") in {None, f"http://localhost:{PORT}"}
            and request.headers.get("sec-fetch-site") != "cross-site"
        )
        signed_navigation = (
            gate is not None
            and request.method == "GET"
            and request.url.path == "/c/main/security-lab"
            and request.headers.get("host") == f"localhost:{PORT}"
            and request.headers.get("origin") is None
            and request.headers.get("sec-fetch-site") == "same-site"
            and request.headers.get("sec-fetch-dest") == "document"
            and request.headers.get("sec-fetch-mode") == "navigate"
            and gate.authenticated(request)
        )
        if not local_request(request) and not (callback or signed_navigation):
            return JSONResponse({"error": "local_access_only"}, status_code=403)
        path = unquote(request.url.path)
        if (
            gate is not None
            and request.method == "GET"
            and request.headers.get("host") == f"127.0.0.1:{PORT}"
            and path not in {"/_lab/session", "/_lab/stop"}
        ):
            return RedirectResponse(
                f"http://localhost:{PORT}"
                + request.url.path
                + ("?" + request.url.query if request.url.query else ""),
                status_code=303,
            )
        if path == "/_lab/session":
            if request.method != "GET" or not secrets.compare_digest(
                request.headers.get("x-lab-session", "").encode(), stop_nonce.encode()
            ):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            return JSONResponse({"running": not app.state.stop_requested})
        if path == "/_lab/stop":
            if request.method != "POST" or not secrets.compare_digest(
                request.headers.get("x-lab-stop", "").encode(), stop_nonce.encode()
            ):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            app.state.stop_requested = True
            return JSONResponse({"stopping": True})
        if gate is not None:
            return await gate.route(request)
        return None

    async def dispatch(request: Request) -> Response:  # noqa: PLR0911 - explicit HTTP denials
        response = await preflight(request)
        if response is not None:
            return response
        path = unquote(request.url.path)
        if request.method not in {"GET", "HEAD"} and not (
            request.method == "POST" and path in AUTH_QUERIES
        ):
            return JSONResponse({"error": "read_only"}, status_code=405)
        if path == "/_lab/snapshot":
            try:
                value = dict(await asyncio.to_thread(cache.get))
                if gate is not None:
                    value["viewer"] = {"provider": "ZITADEL", "role": "viewer"}
                return JSONResponse(value, headers={"Cache-Control": "no-store"})
            except Exception:
                return JSONResponse({"error": "lab_unavailable"}, status_code=503)
        if path.startswith("//") or any(
            segment in {"exec", "attach", "portforward", "secrets"} for segment in path.split("/")
        ):
            return JSONResponse({"error": "read_only"}, status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 65536:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        client = httpx2.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx2.Timeout(30, connect=5),
        )
        try:
            credential = await asyncio.to_thread(token)
            upstream = await client.send(
                client.build_request(
                    request.method,
                    BACKEND
                    + request.url.path
                    + ("?" + request.url.query if request.url.query else ""),
                    content=bytes(body),
                    headers=forwarded_headers(request, credential),
                ),
                stream=True,
            )
        except Exception:
            await client.aclose()
            return JSONResponse({"error": "ui_unavailable"}, status_code=503)

        async def close() -> None:
            await upstream.aclose()
            await client.aclose()

        headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower()
            in {"content-type", "content-encoding", "content-length", "etag", "last-modified"}
        }
        headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            }
        )
        return StreamingResponse(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers=headers,
            background=BackgroundTask(close),
        )

    app.state.stop_requested = False
    app.routes.append(
        Route(
            "/{path:path}",
            dispatch,
            methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        )
    )
    return app


def session_nonce() -> str | None:
    if not SESSION.is_file():
        return None
    try:
        state = json.loads(SESSION.read_text())
        nonce = state["nonce"]
        if not isinstance(nonce, str) or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce) is None:
            raise ValueError
        return nonce
    except (OSError, ValueError, TypeError, KeyError):
        raise DemoRuntimeError("UI session record invalid") from None


@contextlib.contextmanager
def launch_lock() -> Iterator[None]:
    identity.DATA.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def running() -> bool:
    nonce = session_nonce()
    if nonce is None:
        return False
    try:
        with httpx2.Client(trust_env=False, timeout=2) as client:
            response = client.get(
                f"http://127.0.0.1:{PORT}/_lab/session", headers={"X-Lab-Session": nonce}
            )
        if response.status_code != 200 or response.json() != {"running": True}:
            raise DemoRuntimeError("UI session could not be verified")
        return True
    except httpx2.ConnectError:
        return False
    except (ValueError, httpx2.HTTPError):
        raise DemoRuntimeError("UI session could not be verified") from None


def announce() -> None:
    print(f"Read-only Headlamp: http://127.0.0.1:{PORT}/c/main/security-lab", flush=True)
    print("make ui-stop closes the local connection", flush=True)


def configured_identity() -> Settings | None:
    profile = identity.settings()
    if ISOLATED and profile is None:
        raise DemoRuntimeError("Isolated panel requires a human identity profile")
    return profile


def start() -> None:
    configured_identity()
    with launch_lock():
        if running():
            announce()
            return
        check_ports()
        SESSION.unlink(missing_ok=True)
        process = subprocess.Popen(
            [sys.executable, "-m", "scripts.kubernetes_ui", "serve"],
            cwd=lab.ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 300
            while process.poll() is None:
                if running():
                    announce()
                    return
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
            raise DemoRuntimeError("UI background startup failed")
        except Exception:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise


def stop() -> None:
    with launch_lock():
        _stop()


def _stop() -> None:
    nonce = session_nonce()
    if nonce is None:
        return
    try:
        with httpx2.Client(trust_env=False, timeout=5) as client:
            response = client.post(
                f"http://127.0.0.1:{PORT}/_lab/stop", headers={"X-Lab-Stop": nonce}
            )
            if response.status_code != 200:
                raise DemoRuntimeError("UI stop refused")
    except httpx2.ConnectError:
        check_ports()
        SESSION.unlink(missing_ok=True)
        return
    except httpx2.HTTPError:
        raise DemoRuntimeError("UI session unavailable") from None
    deadline = time.monotonic() + 15
    while SESSION.exists():
        if time.monotonic() >= deadline:
            raise DemoRuntimeError("UI shutdown did not complete")
        time.sleep(0.2)


async def backend_available(client: httpx2.AsyncClient) -> bool:
    try:
        response = await client.head(BACKEND, headers={"Host": "127.0.0.1:4466"})
        return response.status_code == 200
    except httpx2.HTTPError:
        return False


async def run_server(app: Starlette, tunnel: subprocess.Popen[bytes]) -> None:
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=PORT,
            access_log=False,
            log_level="critical",
            timeout_graceful_shutdown=5,
        )
    )
    proxy = getattr(app.state, "identity_proxy", None)
    identity_server = (
        uvicorn.Server(
            uvicorn.Config(
                proxy, host="127.0.0.1", port=IDENTITY_PORT, access_log=False, log_level="critical"
            )
        )
        if proxy
        else None
    )
    identity_task = asyncio.create_task(identity_server.serve()) if identity_server else None
    task = asyncio.create_task(server.serve())
    at = time.monotonic()
    async with httpx2.AsyncClient(trust_env=False, timeout=2) as client:
        while not task.done():
            if app.state.stop_requested or tunnel.poll() is not None:
                server.should_exit = True
            if identity_task is not None and identity_task.done():
                server.should_exit = True
            if time.monotonic() - at >= 10:
                if not await backend_available(client):
                    server.should_exit = True
                if identity_server is not None:
                    try:
                        response = await client.get(
                            identity.API_BACKEND + "/.well-known/openid-configuration",
                            headers={"Host": f"localhost:{IDENTITY_PORT}"},
                        )
                        if response.status_code != 200:
                            server.should_exit = True
                    except httpx2.HTTPError:
                        server.should_exit = True
                at = time.monotonic()
            await asyncio.sleep(0.2)
    await task
    if identity_server is not None and identity_task is not None:
        identity_server.should_exit = True
        await identity_task


def stop_forwarder() -> None:
    query = ["systemctl", "show", UNIT, "--property=LoadState", "--value"]
    state = lab.checked(lab.guest(query)).strip()
    if state == "not-found":
        return
    if state != "loaded":
        raise DemoRuntimeError("UI forwarder state unavailable")
    result = lab.guest(["systemctl", "stop", UNIT])
    if result.returncode != 0 and lab.checked(lab.guest(query)).strip() == "not-found":
        return
    lab.checked(result)


def close_session(tunnel: subprocess.Popen[bytes] | None, *, human: bool = False) -> None:
    try:
        if tunnel is not None:
            tunnel.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                tunnel.wait(timeout=5)
            if tunnel.poll() is None:
                tunnel.kill()
                tunnel.wait()
        stop_forwarder()
        if human:
            identity.stop_forwarders()
    finally:
        SESSION.unlink(missing_ok=True)


def check_ports() -> None:
    ports = (
        (PORT, TUNNEL_PORT, IDENTITY_PORT, IDENTITY_TUNNEL_PORT, LOGIN_TUNNEL_PORT)
        if configured_identity() is not None
        else (PORT, TUNNEL_PORT)
    )
    for port in ports:
        try:
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))
        except OSError:
            raise DemoRuntimeError("UI loopback port already in use") from None


def identity_forwarding(enabled: bool) -> list[str]:
    if not enabled:
        return []
    identity.start_forwarders()
    return [
        "-L",
        f"127.0.0.1:{IDENTITY_TUNNEL_PORT}:127.0.0.1:{IDENTITY_PORT}",
        "-L",
        f"127.0.0.1:{LOGIN_TUNNEL_PORT}:127.0.0.1:{LOGIN_PORT}",
    ]


def prepare_workloads() -> None:
    lab.runtime_up()
    present = [lab.owned_namespace(name) for name in ("security-lab", "spire-system")]
    if not any(present):
        if ISOLATED:
            raise DemoRuntimeError("Isolated identity requires existing shared workloads")
        lab.up()
    elif not all(present):
        raise DemoRuntimeError("incomplete lab; run make down")
    if ISOLATED:
        lab.checked(lab.kube(["get", "deployment/headlamp"]))
    else:
        deploy()


def serve() -> None:
    if SESSION.exists():
        raise DemoRuntimeError("UI session already exists; run make ui-stop")
    check_ports()
    config_identity = configured_identity()
    prepare_workloads()
    config = Path(lab.checked(lab.lima(["list", lab.VM, "--format", "{{.SSHConfigFile}}"])).strip())
    executable = shutil.which("ssh")
    if executable is None or not config.is_file():
        raise DemoRuntimeError("Lima SSH configuration unavailable")
    command = [
        "k3s",
        "kubectl",
        "--kubeconfig=/etc/rancher/k3s/k3s.yaml",
        "--server=https://127.0.0.1:6443",
        "--namespace",
        "security-lab",
        "port-forward",
        "--address=127.0.0.1",
        "deployment/headlamp",
        f"{PORT}:4466",
    ]
    tunnel: subprocess.Popen[bytes] | None = None
    nonce = secrets.token_urlsafe(32)
    try:
        # A killed host viewer can leave this fixed unit in its dedicated VM.
        stop_forwarder()
        lab.checked(
            lab.guest(
                [
                    "systemd-run",
                    "--unit=" + UNIT,
                    "--collect",
                    "--property=RuntimeMaxSec=8h",
                    *command,
                ]
            )
        )
        additional = identity_forwarding(config_identity is not None)
        tunnel = subprocess.Popen(  # noqa: S603 - verified Lima SSH config, fixed loopback ports
            [
                executable,
                "-F",
                str(config),
                "-N",
                "-o",
                "ControlPath=none",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                f"127.0.0.1:{TUNNEL_PORT}:127.0.0.1:{PORT}",
                *additional,
                "lima-" + lab.VM,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 60
        with httpx2.Client(trust_env=False, timeout=2) as client:
            while True:
                if tunnel.poll() is not None:
                    raise DemoRuntimeError("UI SSH tunnel failed")
                try:
                    if client.get(BACKEND, headers={"Host": "127.0.0.1:4466"}).status_code == 200:
                        break
                except httpx2.HTTPError:
                    pass
                if time.monotonic() >= deadline:
                    raise DemoRuntimeError("Headlamp did not become available")
                time.sleep(0.5)
        descriptor = os.open(SESSION, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"nonce": nonce}, stream)
        viewer = ViewerToken()
        gate = OidcGate(config_identity) if config_identity is not None else None
        app = create_app(viewer.get, headlamp_data.snapshot, nonce, gate=gate)
        if gate is not None:
            app.state.identity_proxy = create_proxy()
        announce()
        asyncio.run(run_server(app, tunnel))
    finally:
        close_session(tunnel, human=config_identity is not None)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("start", "serve", "stop"))
    try:
        {"start": start, "serve": serve, "stop": stop}[parser.parse_args().operation]()
    except DemoRuntimeError:
        print("UI operation failed; credentials and captured output are not displayed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
