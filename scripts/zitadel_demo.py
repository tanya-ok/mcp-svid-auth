"""On-demand, synthetic human identity profile in the existing owned Lima VM."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import yaml

from scripts import kubernetes_demo as lab
from scripts.lab_runtime import DemoRuntimeError
from scripts.local_identity_profile import (
    IDENTITY_PORT,
    IDENTITY_TUNNEL_PORT,
    ISOLATED,
    LOGIN_PORT,
    LOGIN_TUNNEL_PORT,
    NAMESPACE,
    UNIT_PREFIX,
)
from scripts.oidc_gate import CALLBACK, ISSUER, Settings
from scripts.passwordless_policy import (
    closed_google_provider_options,
    native_passkey_login_settings,
    require_closed_google_provider,
    require_login_settings,
)

DATA = lab.DATA / "passkey" if ISOLATED else lab.DATA
PROFILE = DATA / "human-auth.json"
ACCOUNTS = DATA / "human-demo-accounts.json"
API_BACKEND = f"http://127.0.0.1:{IDENTITY_TUNNEL_PORT}"
LOGIN_BACKEND = f"http://127.0.0.1:{LOGIN_TUNNEL_PORT}"
FORWARDS = (
    (UNIT_PREFIX + "-api", "zitadel", IDENTITY_PORT, 8080),
    (UNIT_PREFIX + "-login", "zitadel-login", LOGIN_PORT, 3000),
)
ZITADEL_IMAGE = (
    "ghcr.io/zitadel/zitadel:v4.19.4"
    "@sha256:90a3045b80a2b5b395e1e770302076906af3a5911225af7c464b4f3bd00d0a1b"
)
LOGIN_IMAGE = (
    "ghcr.io/zitadel/zitadel-login:v4.19.4"
    "@sha256:93ffd1395b827f685ba29c02fa70aee881fc21102519c4e2bbb0b89c0e00f42c"
)
POSTGRES_IMAGE = (
    "docker.io/library/postgres:17-bookworm"
    "@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826"
)


def write_private(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)


def settings() -> Settings | None:
    if not PROFILE.exists():
        return None
    try:
        if PROFILE.stat().st_mode & 0o077:
            raise ValueError
        value = json.loads(PROFILE.read_text())
        if not isinstance(value, dict):
            raise ValueError
        return Settings.parse(value)
    except (OSError, ValueError, TypeError):
        raise DemoRuntimeError("Human identity profile invalid") from None


def secret(name: str, values: dict[str, str]) -> dict[str, Any]:
    return lab.resource("Secret", name, namespace=NAMESPACE, stringData=values)


def secret_env(variable: str, key: str, name: str = "identity-bootstrap") -> dict[str, Any]:
    return {"name": variable, "valueFrom": {"secretKeyRef": {"name": name, "key": key}}}


def container(name: str, image: str, memory: str, uid: int) -> dict[str, Any]:
    return {
        "name": name,
        "image": image,
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "750m", "memory": memory},
        },
        "securityContext": {
            "runAsUser": uid,
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def workload(
    name: str, item: dict[str, Any], uid: int, volumes: list[dict[str, Any]]
) -> dict[str, Any]:
    return lab.controller(
        name,
        {
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "securityContext": {"fsGroup": uid},
            "containers": [item],
            "volumes": volumes,
        },
        NAMESPACE,
    )


def database_documents() -> list[dict[str, Any]]:
    item = container("postgres", POSTGRES_IMAGE, "384Mi", 999)
    item["args"] = ["postgres", "-c", "shared_buffers=64MB", "-c", "max_connections=30"]
    item["env"] = [
        secret_env("POSTGRES_PASSWORD", "db_admin_password"),
        {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
    ]
    item["volumeMounts"] = [
        {"name": "data", "mountPath": "/var/lib/postgresql/data"},
        {"name": "run", "mountPath": "/var/run/postgresql"},
        {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - private pod emptyDir
    ]
    item["readinessProbe"] = {
        "exec": {"command": ["pg_isready", "-U", "postgres"]},
        "periodSeconds": 2,
    }
    volumes = [
        {"name": name, "emptyDir": {"sizeLimit": "1Gi" if name == "data" else "64Mi"}}
        for name in ("data", "run", "tmp")
    ]
    return [
        lab.service("identity-postgres", 5432, NAMESPACE),
        workload("identity-postgres", item, 999, volumes),
    ]


def api_documents(expiration: str) -> list[dict[str, Any]]:
    config = {
        "ExternalDomain": "localhost",
        "ExternalPort": IDENTITY_PORT,
        "ExternalSecure": False,
        "TLS": {"Enabled": False},
        "Telemetry": {"Enabled": False},
        "Log": {"Level": "error"},
        "Metrics": {"Type": "none"},
        "DefaultInstance": {
            "Features": {"LoginV2": {"Required": True, "BaseURI": ISSUER + "/ui/v2/login/"}},
            "OIDCSettings": {"IdTokenLifetime": "10m", "AccessTokenLifetime": "10m"},
        },
        "OIDC": {
            "DefaultLoginURLV2": ISSUER + "/ui/v2/login/login?authRequest=",
            "DefaultLogoutURLV2": ISSUER + "/ui/v2/login/logout?post_logout_redirect=",
        },
        "Database": {
            "postgres": {
                "Host": "identity-postgres",
                "Port": 5432,
                "Database": "zitadel",
                "User": {"Username": "zitadel", "SSL": {"Mode": "disable"}},
                "Admin": {"Username": "postgres", "SSL": {"Mode": "disable"}},
                "MaxOpenConns": 10,
                "MaxIdleConns": 5,
            }
        },
    }
    steps = {
        "FirstInstance": {
            "InstanceName": "Local security lab",
            "DefaultLanguage": "en",
            "PatPath": "/bootstrap/admin.pat",
            "LoginClientPatPath": "/bootstrap/login.pat",
            "Org": {
                "Name": "Security lab",
                "Human": {
                    "UserName": "bootstrap-admin",
                    "FirstName": "Lab",
                    "LastName": "Admin",
                    "Email": {"Address": "bootstrap@example.org", "Verified": True},
                    "PasswordChangeRequired": False,
                },
                "Machine": {
                    "Machine": {"Username": "lab-bootstrap", "Name": "Lab bootstrap"},
                    "Pat": {"ExpirationDate": expiration},
                },
                "LoginClient": {
                    "Machine": {"Username": "lab-login", "Name": "Lab login"},
                    "Pat": {"ExpirationDate": expiration},
                },
            },
        }
    }
    item = container("zitadel", ZITADEL_IMAGE, "640Mi", 1000)
    item["args"] = [
        "start-from-init",
        "--config",
        "/config/zitadel.yaml",
        "--steps",
        "/config/steps.yaml",
        "--masterkeyFile",
        "/secrets/masterkey",
        "--tlsMode",
        "disabled",
    ]
    item["env"] = [
        secret_env("ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD", "db_admin_password"),
        secret_env("ZITADEL_DATABASE_POSTGRES_USER_PASSWORD", "db_password"),
        secret_env("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD", "admin_password"),
        {"name": "GOMEMLIMIT", "value": "512MiB"},
    ]
    item["volumeMounts"] = [
        {"name": "config", "mountPath": "/config", "readOnly": True},
        {"name": "secrets", "mountPath": "/secrets", "readOnly": True},
        {"name": "bootstrap", "mountPath": "/bootstrap"},
        {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - private pod emptyDir
    ]
    item["readinessProbe"] = {
        "httpGet": {"path": "/debug/ready", "port": 8080},
        "periodSeconds": 2,
        "failureThreshold": 90,
    }
    volumes = [
        {"name": "config", "configMap": {"name": "identity-config"}},
        {"name": "secrets", "secret": {"secretName": "identity-bootstrap", "defaultMode": 0o440}},
        {"name": "bootstrap", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
    ]
    return [
        lab.configmap(
            "identity-config",
            {"zitadel.yaml": yaml.safe_dump(config), "steps.yaml": yaml.safe_dump(steps)},
            NAMESPACE,
        ),
        lab.service("zitadel", 8080, NAMESPACE),
        workload("zitadel", item, 1000, volumes),
    ]


def login_documents() -> list[dict[str, Any]]:
    item = container("zitadel-login", LOGIN_IMAGE, "384Mi", 1000)
    item["env"] = [
        {"name": "ZITADEL_API_URL", "value": "http://zitadel:8080"},
        {"name": "NEXT_PUBLIC_BASE_PATH", "value": "/ui/v2/login"},
        {
            "name": "CUSTOM_REQUEST_HEADERS",
            "value": f"Host:localhost:{IDENTITY_PORT},X-Forwarded-Proto:http",
        },
        {"name": "ZITADEL_SERVICE_USER_TOKEN_FILE", "value": "/bootstrap/token"},
        secret_env("ZITADEL_SESSION_COOKIE_SECRET", "cookie_secret"),
        {"name": "NEXT_TELEMETRY_DISABLED", "value": "1"},
        {"name": "NODE_OPTIONS", "value": "--max-old-space-size=256"},
        {"name": "HOSTNAME", "value": "0.0.0.0"},  # noqa: S104 - isolated pod, no host port
        {"name": "PORT", "value": "3000"},
    ]
    item["volumeMounts"] = [
        {"name": "bootstrap", "mountPath": "/bootstrap", "readOnly": True},
        {"name": "tmp", "mountPath": "/tmp"},  # noqa: S108 - private pod emptyDir
    ]
    item["readinessProbe"] = {
        "httpGet": {"path": "/ui/v2/login/healthy", "port": 3000},
        "periodSeconds": 2,
        "failureThreshold": 60,
    }
    return [
        lab.service("zitadel-login", 3000, NAMESPACE),
        workload(
            "zitadel-login",
            item,
            1000,
            [
                {
                    "name": "bootstrap",
                    "secret": {"secretName": "identity-login", "defaultMode": 0o440},
                },
                {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
            ],
        ),
    ]


def network_policy() -> dict[str, Any]:
    value = lab.resource(
        "NetworkPolicy",
        "identity-local-only",
        namespace=NAMESPACE,
        spec={
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {}}]}],
            "egress": [
                {"to": [{"podSelector": {}}]},
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ],
                    "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                },
            ],
        },
    )
    value["apiVersion"] = "networking.k8s.io/v1"
    return value


def stop_forwarders() -> None:
    for unit, _, _, _ in FORWARDS:
        query = ["systemctl", "show", unit, "--property=LoadState", "--value"]
        if lab.checked(lab.guest(query)).strip() == "not-found":
            continue
        result = lab.guest(["systemctl", "stop", unit])
        if result.returncode and lab.checked(lab.guest(query)).strip() == "not-found":
            continue
        lab.checked(result)


def start_forwarders() -> None:
    if not lab.owned_namespace(NAMESPACE):
        raise DemoRuntimeError("Human identity namespace absent")
    stop_forwarders()
    for unit, name, port, target in FORWARDS:
        lab.checked(
            lab.guest(
                [
                    "systemd-run",
                    "--quiet",
                    "--collect",
                    "--unit=" + unit,
                    "--property=RuntimeMaxSec=8h",
                    "k3s",
                    "kubectl",
                    "--namespace",
                    NAMESPACE,
                    "port-forward",
                    "--address=127.0.0.1",
                    "deployment/" + name,
                    f"{port}:{target}",
                ]
            )
        )


def ssh_arguments() -> list[str]:
    config = Path(lab.checked(lab.lima(["list", lab.VM, "--format", "{{.SSHConfigFile}}"])).strip())
    executable = shutil.which("ssh")
    if executable is None or not config.is_file():
        raise DemoRuntimeError("Lima SSH configuration unavailable")
    return [
        executable,
        "-F",
        str(config),
        "-N",
        "-o",
        "ControlPath=none",
        "-o",
        "ExitOnForwardFailure=yes",
        "-L",
        f"127.0.0.1:{IDENTITY_TUNNEL_PORT}:127.0.0.1:{IDENTITY_PORT}",
        "-L",
        f"127.0.0.1:{LOGIN_TUNNEL_PORT}:127.0.0.1:{LOGIN_PORT}",
        "lima-" + lab.VM,
    ]


@contextlib.contextmanager
def connection() -> Iterator[None]:
    start_forwarders()
    process = subprocess.Popen(  # noqa: S603 - verified local SSH arguments
        ssh_arguments(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with httpx2.Client(trust_env=False, timeout=2) as client:
            deadline = time.monotonic() + 60
            while True:
                try:
                    response = client.get(
                        API_BACKEND + "/.well-known/openid-configuration",
                        headers={"Host": f"localhost:{IDENTITY_PORT}"},
                    )
                    if response.status_code == 200:
                        break
                except httpx2.HTTPError:
                    pass
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise DemoRuntimeError("Human identity tunnel unavailable")
                time.sleep(0.2)
        yield
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        if process.poll() is None:
            process.kill()
            process.wait()
        stop_forwarders()


class Bootstrap:
    def __init__(self, credential: str) -> None:
        self.client = httpx2.Client(
            base_url=API_BACKEND,
            trust_env=False,
            timeout=20,
            headers={"Host": f"localhost:{IDENTITY_PORT}", "Authorization": "Bearer " + credential},
        )

    def call(self, path: str, value: dict[str, Any], *, method: str = "POST") -> dict[str, Any]:
        try:
            response = self.client.request(method, path, json=value)
            response.raise_for_status()
            result: Any = response.json()
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (httpx2.HTTPError, ValueError):
            raise DemoRuntimeError("Human identity provisioning failed") from None

    def verify_login_policy(self, org_id: str, expected: dict[str, object]) -> None:
        self.client.headers["x-zitadel-orgid"] = org_id
        result = self.call("/management/v1/policies/login", {}, method="GET")
        raw = result.get("policy")
        if (
            not isinstance(raw, dict)
            or raw.get("isDefault", False) is not False
            or result.get("isDefault", False) is not False
            or not isinstance(raw.get("details"), dict)
            or raw["details"].get("resourceOwner") != org_id
        ):
            raise DemoRuntimeError("Unsafe human login policy")
        aliases = {"allowLocalAuthentication": "allowUsernamePassword"}
        actual: dict[str, object] = {}
        for name, value in expected.items():
            if name == "passkeysType":
                actual[name] = (
                    "PASSKEYS_TYPE_ALLOWED"
                    if raw.get("passwordlessType") == "PASSWORDLESS_TYPE_ALLOWED"
                    else "PASSKEYS_TYPE_NOT_ALLOWED"
                )
            else:
                default: object = (
                    False if isinstance(value, bool) else ([] if isinstance(value, list) else None)
                )
                actual[name] = raw.get(aliases.get(name, name), default)
        require_login_settings(actual, expected)

    def verify_native_policy(self, org_id: str) -> None:
        self.verify_login_policy(org_id, native_passkey_login_settings())

    def verify_google_provider(self, org_id: str, provider_id: str, client_id: str) -> None:
        self.client.headers["x-zitadel-orgid"] = org_id
        result = self.call("/management/v1/idps/templates/" + provider_id, {}, method="GET")
        provider = result.get("idp")
        if (
            not isinstance(provider, dict)
            or provider.get("id") != provider_id
            or provider.get("type") != "PROVIDER_TYPE_GOOGLE"
            or provider.get("owner") != "IDP_OWNER_TYPE_ORG"
            or provider.get("state") != "IDP_STATE_ACTIVE"
            or not isinstance(provider.get("details"), dict)
            or provider["details"].get("resourceOwner") != org_id
        ):
            raise DemoRuntimeError("Unsafe external identity policy")
        config = provider.get("config")
        if not isinstance(config, dict) or not isinstance(config.get("google"), dict):
            raise DemoRuntimeError("Unsafe external identity policy")
        google = config["google"]
        if google.get("clientId") != client_id or google.get("scopes") != [
            "openid",
            "profile",
            "email",
        ]:
            raise DemoRuntimeError("Unsafe external identity policy")
        options = config.get("options", {})
        if not isinstance(options, dict):
            raise DemoRuntimeError("Unsafe external identity policy")
        normalized = {
            name: options.get(name, default)
            for name, default in closed_google_provider_options().items()
        }
        require_closed_google_provider(normalized)
        active = self.call("/management/v1/policies/login/idps/_search", {})
        entries = active.get("result")
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
            or entries[0].get("idpId") != provider_id
        ):
            raise DemoRuntimeError("Unsafe external identity policy")

    def user(self, label: str, org_id: str) -> str:
        return str(
            self.call(
                "/v2/users/human",
                {
                    "username": label + "@example.org",
                    "organization": {"orgId": org_id},
                    "profile": {"givenName": "Lab", "familyName": label.title()},
                    "email": {"email": label + "@example.org", "isVerified": True},
                },
            )["userId"]
        )

    def provision(self) -> tuple[Settings, dict[str, Any]]:
        organization = self.call("/management/v1/orgs", {"name": "Security lab demo users"})
        org_id = str(organization["id"])
        self.client.headers["x-zitadel-orgid"] = org_id
        policy = native_passkey_login_settings()
        policy["allowUsernamePassword"] = policy.pop("allowLocalAuthentication")
        policy["passwordlessType"] = "PASSWORDLESS_TYPE_ALLOWED"
        policy.pop("passkeysType")
        self.call("/management/v1/policies/login", policy)
        self.verify_native_policy(org_id)
        project = self.call(
            "/management/v1/projects", {"name": "Security lab viewer", "projectRoleAssertion": True}
        )
        project_id = str(project["id"])
        if str(project["details"]["resourceOwner"]) != org_id:
            raise DemoRuntimeError("Human identity organization mismatch")
        self.call(
            f"/management/v1/projects/{project_id}/roles",
            {"roleKey": "viewer", "displayName": "Read-only viewer"},
        )
        app = self.call(
            f"/management/v1/projects/{project_id}/apps/oidc",
            {
                "name": "Local Headlamp gate",
                "redirectUris": [CALLBACK],
                "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
                "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
                "appType": "OIDC_APP_TYPE_WEB",
                "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
                "devMode": True,
                "idTokenRoleAssertion": True,
            },
        )
        accounts: dict[str, Any] = {}
        for label in ("viewer", "unprivileged"):
            user_id = self.user(label, org_id)
            if label == "viewer":
                self.call(
                    f"/management/v1/users/{user_id}/grants",
                    {"projectId": project_id, "roleKeys": ["viewer"]},
                )
            accounts[label] = {
                "username": label + "@example.org",
                "user_id": user_id,
            }
        return Settings.parse(
            {
                "client_id": app["clientId"],
                "project_id": project_id,
                "org_id": org_id,
                "approved_subjects": [accounts["viewer"]["user_id"]],
            }
        ), accounts


def ready(name: str) -> None:
    lab.checked(
        lab.kube(
            ["rollout", "status", "deployment/" + name, "--timeout=240s"],
            namespace=NAMESPACE,
            timeout=260,
        )
    )


def read_bootstrap(name: str) -> str:
    if name not in {"admin", "login"} or not lab.owned_namespace(NAMESPACE):
        raise DemoRuntimeError("Identity bootstrap unavailable")
    pods = json.loads(
        lab.checked(
            lab.kube(["get", "pods", "--selector=app=zitadel", "-o", "json"], namespace=NAMESPACE)
        )
    )["items"]
    if len(pods) != 1:
        raise DemoRuntimeError("Identity bootstrap unavailable")
    metadata = pods[0]["metadata"]
    uid = metadata.get("uid", "")
    if (
        not re.fullmatch(r"[a-f0-9-]{36}", uid)
        or metadata.get("labels", {}).get("app.kubernetes.io/part-of") != "security-lab"
    ):
        raise DemoRuntimeError("Identity bootstrap unavailable")
    path = f"/var/lib/kubelet/pods/{uid}/volumes/kubernetes.io~empty-dir/bootstrap/{name}.pat"
    value = lab.checked(lab.guest(["cat", path])).strip()
    if not value or len(value) > 4096:
        raise DemoRuntimeError("Identity bootstrap unavailable")
    return value


def up() -> None:
    from scripts.kubernetes_ui import stop  # noqa: PLC0415 - driver integration

    stop()
    lab.runtime_up()
    DATA.mkdir(parents=True, exist_ok=True)
    if lab.owned_namespace(NAMESPACE):
        if settings() is None:
            raise DemoRuntimeError("Incomplete identity profile; run make ui-login-down")
        for name in ("identity-postgres", "zitadel", "zitadel-login"):
            ready(name)
        config = settings()
        if config is None:
            raise DemoRuntimeError("Human identity profile unavailable")
        with connection():
            verifier = Bootstrap(read_bootstrap("admin"))
            try:
                verifier.verify_native_policy(config.org_id)
            finally:
                verifier.client.close()
        print("Existing human identity profile ready", flush=True)
        return
    PROFILE.unlink(missing_ok=True)
    ACCOUNTS.unlink(missing_ok=True)
    namespace = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NAMESPACE, "labels": lab.OWNER},
    }
    values = {
        name: secrets.token_urlsafe(32)
        for name in ("db_admin_password", "db_password", "cookie_secret")
    }
    values.update(
        {
            "masterkey": secrets.token_urlsafe(24),
            "admin_password": "Demo!" + secrets.token_urlsafe(24),
        }
    )
    expiration = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    lab.apply(
        [
            namespace,
            secret("identity-bootstrap", values),
            network_policy(),
            *database_documents(),
            *api_documents(expiration),
        ]
    )
    ready("identity-postgres")
    ready("zitadel")
    login_token = read_bootstrap("login")
    lab.apply([secret("identity-login", {"token": login_token}), *login_documents()])
    ready("zitadel-login")
    with connection():
        bootstrap = Bootstrap(read_bootstrap("admin"))
        try:
            config, accounts = bootstrap.provision()
        finally:
            bootstrap.client.close()
    write_private(ACCOUNTS, accounts)
    write_private(
        PROFILE,
        {
            "client_id": config.client_id,
            "project_id": config.project_id,
            "org_id": config.org_id,
            "approved_subjects": sorted(config.approved_subjects),
        },
    )
    print(
        "Synthetic OIDC profile ready; credentials remain in the ignored local account file",
        flush=True,
    )


def down() -> None:
    if lab.owned_namespace(NAMESPACE):
        lab.checked(lab.kube(["delete", "namespace", NAMESPACE, "--timeout=90s"], timeout=120))
    PROFILE.unlink(missing_ok=True)
    ACCOUNTS.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("up", "down"))
    try:
        lab.verify_instance()
        operation = parser.parse_args().operation
        if operation == "up":
            up()
        else:
            from scripts.kubernetes_ui import stop  # noqa: PLC0415 - driver integration

            stop()
            down()
    except (DemoRuntimeError, KeyError, ValueError):
        print("Human identity operation failed; credentials and captured output are not displayed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
