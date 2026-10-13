# Security

This is a proof of concept. Do not deploy it to protect real data.

## Reporting

Report a vulnerability privately to the repository owner through GitHub private vulnerability reporting. Do not open a public issue.

## Known limitations

- The lab runs on Kubernetes (k3s on containerd) inside a Lima VM. The SPIRE agent uses the Kubernetes workload attestor with namespace and ServiceAccount selectors. No containerd or other runtime socket is mounted into SPIRE or application pods; application pods receive only the Workload API socket. The SPIRE agent has root and host PID access inside the VM, and anyone who can start a pod with an authorized ServiceAccount can assume its identity. See `docs/security.md` and `docs/kubernetes-lab.md`.
- JWT-SVID replay: authz defaults to `--svid-replay reject` (each `jti` once), but the lab runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent re-serves cached SVIDs. There a stolen SVID is usable until it expires. Access tokens are not tracked by `jti`.
- Authz signing keys live in memory. Planned rotation keeps public-key overlap; a restart still loses the old keys.
- Services talk plain HTTP inside the lab cluster network.

See the threat model table in [README.md](README.md) and the STPA-Sec analysis in `docs/threat-model.md`.
