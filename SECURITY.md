# Security

This is a proof of concept. Do not deploy it to protect real data.

## Reporting

Report a vulnerability privately to the repository owner through GitHub private vulnerability reporting. Do not open a public issue.

## Known limitations

- The SPIRE agent uses the docker workload attestor and has the Docker socket mounted. The Docker API has no read-only mode. See `docs/security.md`.
- JWT-SVID replay: authz defaults to `--svid-replay reject` (each `jti` once), but the compose demo runs `allow-reuse-within-lifetime` because the SPIRE 1.15.3 agent re-serves cached SVIDs. There a stolen SVID is usable until it expires. Access tokens are not tracked by `jti`.
- The authz signing key lives in memory and rotates only on restart.
- Services talk plain HTTP inside the compose network.

See the threat model table in [README.md](README.md) and the STPA-Sec analysis in `docs/threat-model.md`.
