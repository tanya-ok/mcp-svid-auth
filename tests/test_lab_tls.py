"""Service-to-service TLS in the lab: real certificates, no disabled verification."""

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import kubernetes_demo as lab
from scripts import lab_tls, run_demo
from scripts.lab_runtime import SERVICES, DemoRuntimeError

DIGEST = "sha256:" + "a" * 64
IMAGES = {"auth": "auth-image" + "@" + DIGEST, "fhir": "fhir-image" + "@" + DIGEST}
FORBIDDEN_FLAGS = ("--allow-http", "--allow-private-network", "--insecure", "--no-verify")


def test_leaf_is_a_server_certificate_signed_by_the_lab_ca_only() -> None:
    ca_key, ca = lab_tls.new_authority()
    pem, key_pem = lab_tls.issue(ca_key, ca, "notes-a")
    leaf = x509.load_pem_x509_certificate(pem.encode())
    leaf.verify_directly_issued_by(ca)
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == lab_tls.hostnames("notes-a")
    assert leaf.not_valid_after_utc - datetime.now(UTC) <= timedelta(hours=25)
    assert isinstance(leaf.public_key(), ec.EllipticCurvePublicKey)
    assert "BEGIN PRIVATE KEY" in key_pem
    _, other_ca = lab_tls.new_authority()
    with pytest.raises(InvalidSignature):
        leaf.verify_directly_issued_by(other_ca)


def test_clients_verify_hostname_and_reject_an_unknown_ca(tmp_path: Path) -> None:
    ca_key, ca = lab_tls.new_authority()
    pem, key_pem = lab_tls.issue(ca_key, ca, "authz")
    (tmp_path / "tls.crt").write_text(pem)
    (tmp_path / "tls.key").write_text(key_pem)
    (tmp_path / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    _, stranger = lab_tls.new_authority()
    (tmp_path / "stranger.crt").write_bytes(stranger.public_bytes(serialization.Encoding.PEM))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(tmp_path / "tls.crt", tmp_path / "tls.key")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    def serve() -> None:
        for _ in range(3):
            connection, _ = listener.accept()
            try:
                with server_context.wrap_socket(connection, server_side=True) as secure:
                    secure.sendall(b"ok")
            except ssl.SSLError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def connect(cafile: str, hostname: str) -> bytes:
        context = ssl.create_default_context(cafile=str(tmp_path / cafile))
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as secure,
        ):
            return secure.recv(2)

    assert connect("ca.crt", "authz") == b"ok"
    with pytest.raises(ssl.SSLCertVerificationError):
        connect("stranger.crt", "authz")
    with pytest.raises(ssl.SSLCertVerificationError):
        connect("ca.crt", "notes-a")
    thread.join(timeout=5)
    listener.close()


def test_runtime_documents_hold_one_secret_per_server_and_a_public_ca() -> None:
    documents = lab_tls.documents()
    secrets = {d["metadata"]["name"]: d for d in documents if d["kind"] == "Secret"}
    assert set(secrets) == {lab_tls.secret_name(name) for name in lab_tls.SERVERS}
    assert all(d["type"] == "kubernetes.io/tls" for d in secrets.values())
    ca = next(d for d in documents if d["kind"] == "ConfigMap")
    assert "PRIVATE KEY" not in ca["data"]["ca.crt"]
    keys = {d["stringData"]["tls.key"] for d in secrets.values()}
    assert len(keys) == len(lab_tls.SERVERS)


def test_review_preview_has_no_key_material() -> None:
    text = yaml.safe_dump_all(lab_tls.documents(placeholder=True))
    assert "BEGIN" not in text
    assert "KEY GENERATED AT RUNTIME" in text


def test_no_lab_service_uses_plain_http_or_relaxed_checks() -> None:
    for name, service in SERVICES.items():
        for argument in service.get("command", []):
            assert not str(argument).startswith("http://"), (name, argument)
            assert not any(str(argument).startswith(flag) for flag in FORBIDDEN_FLAGS), name
            assert "http://" not in str(argument), (name, argument)
    policy = (lab.CONFIG / "policy.yaml").read_text()
    assert "http://" not in policy
    assert "http://" not in (lab.DEPLOY / "probe_svid.py").read_text()


def test_every_https_server_gets_a_certificate_and_every_pod_trusts_the_lab_ca() -> None:
    served = {
        name
        for name, service in SERVICES.items()
        if any(str(arg).startswith("--tls-cert=") for arg in service.get("command", []))
    }
    assert served == set(lab_tls.SERVERS)
    for name in served:
        command = SERVICES[name]["command"]
        assert "--tls-key=/tls/tls.key" in command
        assert "--tls-cert=/tls/tls.crt" in command
    for document in lab.applications(IMAGES):
        if document["kind"] != "Deployment":
            continue
        pod = document["spec"]["template"]["spec"]
        name = document["metadata"]["name"]
        mounts = {m["name"]: m for m in pod["containers"][0]["volumeMounts"]}
        assert mounts["ca"]["mountPath"] == lab_tls.CA_MOUNT and mounts["ca"]["readOnly"]
        assert ("tls" in mounts) == (name in lab_tls.SERVERS)
        env = {e["name"]: e["value"] for e in pod["containers"][0]["env"]}
        assert env["NODE_EXTRA_CA_CERTS"] == lab_tls.CA_FILE
        assert "NODE_TLS_REJECT_UNAUTHORIZED" not in env


def test_clients_in_clients_trust_the_ca_file_and_relax_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[list[str]] = []

    def command(args: list[str], **kwargs: Any) -> str:
        captured.append(args)
        return '{"event": "token"}'

    monkeypatch.setattr(run_demo, "command", command)
    run_demo.agent()
    arguments = captured[0]
    assert arguments[arguments.index("--ca-file") + 1] == lab_tls.CA_FILE
    assert not {"--allow-http", "--allow-private-network"} & set(arguments)
    assert all(a.startswith("https://") for a in (run_demo.A, run_demo.B, run_demo.ISSUER))


def test_url_policy_relaxation_fails_the_scenario(monkeypatch: pytest.MonkeyPatch) -> None:
    relaxed = '{"event": "url_policy_relaxed", "allow_http": true}\n{"event": "token"}'
    monkeypatch.setattr(run_demo, "command", lambda *args, **kwargs: relaxed)
    with pytest.raises(run_demo.DemoError, match="relaxed"):
        run_demo.agent()


GATEWAY = 'x\nconst issuer = "http://authz:8100";\ny\n'
PROBE = (
    'ISSUER = "http://authz:8100"\n'
    'wrong = token("http://notes-a:8101/mcp", "notes:read")\n'
    "    result = httpx2.post(\n"
    '        ISSUER + "/token",\n'
    "        timeout=10,\n"
    "        trust_env=False,\n"
    "        data={\n"
)


def stage(tmp_path: Path, gateway: str = GATEWAY, probe: str = PROBE) -> Path:
    (tmp_path / "fhir-gateway.mjs").write_text(gateway)
    (tmp_path / "probe_fhir.py").write_text(probe)
    return tmp_path


def test_staged_fhir_sources_use_https_and_the_lab_ca(tmp_path: Path) -> None:
    lab.adapt_fhir_sources(stage(tmp_path))
    gateway = (tmp_path / "fhir-gateway.mjs").read_text()
    probe = (tmp_path / "probe_fhir.py").read_text()
    assert "http://" not in gateway + probe
    assert f'cafile="{lab_tls.CA_FILE}"' in probe
    assert "verify=False" not in probe
    again = probe
    lab.adapt_fhir_sources(tmp_path)
    assert (tmp_path / "probe_fhir.py").read_text() == again


def test_changed_fhir_sources_stop_the_build_instead_of_silently_staying_on_http(
    tmp_path: Path,
) -> None:
    with pytest.raises(DemoRuntimeError, match="TLS edits"):
        lab.adapt_fhir_sources(stage(tmp_path, gateway="const issuer = issuerFromEnv();\n"))
