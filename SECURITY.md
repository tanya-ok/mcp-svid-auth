# Security

Not yet production-ready. Do not deploy it to protect real data until the remaining items in `docs/production-readiness.md` are closed for your environment.

## Supported versions

| Component | Supported |
|---|---|
| Package | The `main` branch. No version has been released; `0.1.0` in `pyproject.toml` is a placeholder |
| Python | 3.12 and 3.13 (CI matrix) |
| Optional servers | Valkey or Redis 7+ for `--state-store-url`; OpenBao or Vault with the transit engine for `--transit-address` (tested with Vault 2.1.1) |

From the first release the project follows Semantic Versioning for its public interface: command-line flags of the console scripts, the revocation file format, the checkpoint format and the [audit event contract](docs/architecture/contracts/audit-event.md). Removing or changing the meaning of any of them needs a major version; the audit record carries `schema_version`. Security fixes go to the latest release only.

## Reporting

Report a vulnerability privately to the repository owner through GitHub private vulnerability reporting. Do not open a public issue.

## Known limitations

- The lab runs on Kubernetes (k3s on containerd) inside a Lima VM. The SPIRE agent uses the Kubernetes workload attestor with namespace and ServiceAccount selectors. No containerd or other runtime socket is mounted into SPIRE or application pods; application pods receive only the Workload API socket. The SPIRE agent has root and host PID access inside the VM, and anyone who can start a pod with an authorized ServiceAccount can assume its identity. See `docs/security.md` and `docs/kubernetes-lab.md`.
- JWT-SVID replay: authz defaults to `--svid-replay reject` (each `jti` once, shared by replicas with `--state-store-url`), but the lab runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent re-serves cached SVIDs. There a stolen SVID is usable until it expires.
- Authz needs a key file, an OpenBao or Vault transit signer, or the development-only `--dev-ephemeral-signing-key`. No cloud KMS adapter.
- Both servers support HTTPS and mTLS, but the lab cluster network still runs plain HTTP.
- No ServiceAccount admission policy: anyone allowed to use an authorized ServiceAccount obtains its identity.
- Log shipping, durable audit storage and the checkpoint signing host are operator responsibilities. See `docs/operations.md`.

See the threat model table in [README.md](README.md) and the STPA-Sec analysis in `docs/threat-model.md`.
