"""Per-run certificate authority for service-to-service TLS inside the lab.

The CA and every server key are generated in memory when the lab starts and reach the
cluster only as Secrets applied over stdin. Nothing is written to disk and the
review preview contains placeholders. Clients trust exactly this CA with `--ca-file`
(or `NODE_EXTRA_CA_CERTS`); certificate and hostname verification stay on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NAMESPACE = "security-lab"
SERVERS = ("authz", "authz-strict", "notes-a", "notes-b", "notes-rogue")
CA_CONFIGMAP = "lab-ca"
CA_MOUNT = "/tls-ca"
CA_FILE = CA_MOUNT + "/ca.crt"
TLS_MOUNT = "/tls"
VALID_FOR = timedelta(hours=24)
OWNER = {"app.kubernetes.io/part-of": "security-lab"}


def secret_name(server: str) -> str:
    return "tls-" + server


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _pem_key(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _pem_certificate(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _builder(subject: str, issuer: x509.Name, key: ec.EllipticCurvePrivateKey) -> Any:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + VALID_FOR)
    )


def new_authority() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name("security-lab CA")
    certificate = (
        _builder("security-lab CA", subject, key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def hostnames(server: str) -> list[str]:
    base = f"{server}.{NAMESPACE}.svc"
    return [server, base, base + ".cluster.local"]


def issue(
    authority_key: ec.EllipticCurvePrivateKey, authority_certificate: x509.Certificate, server: str
) -> tuple[str, str]:
    """Return (certificate PEM, private key PEM) for one server."""
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        _builder(server, authority_certificate.subject, key)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames(server)]), False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(authority_key, hashes.SHA256())
    )
    return _pem_certificate(certificate), _pem_key(key)


def documents(*, placeholder: bool = False) -> list[dict[str, Any]]:
    """CA ConfigMap and one TLS Secret per server; the preview carries no key material."""
    if placeholder:
        ca_pem = "PUBLIC CA GENERATED AT RUNTIME"
        material = dict.fromkeys(SERVERS, ("CERTIFICATE GENERATED AT RUNTIME", ""))
    else:
        authority_key, authority_certificate = new_authority()
        ca_pem = _pem_certificate(authority_certificate)
        material = {
            server: issue(authority_key, authority_certificate, server) for server in SERVERS
        }
    metadata = {"namespace": NAMESPACE, "labels": dict(OWNER)}
    result: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": CA_CONFIGMAP, **metadata},
            "data": {"ca.crt": ca_pem},
        }
    ]
    for server, (certificate, key) in material.items():
        result.append(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "type": "kubernetes.io/tls",
                "metadata": {"name": secret_name(server), **metadata},
                "stringData": {
                    "tls.crt": certificate,
                    "tls.key": key or "KEY GENERATED AT RUNTIME",
                },
            }
        )
    return result
