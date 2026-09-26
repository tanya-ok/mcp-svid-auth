# Security

This is a proof of concept. Do not deploy it to protect real data.

## Reporting

Report a vulnerability privately to the repository owner through GitHub private vulnerability reporting. Do not open a public issue.

## Known limitations

- Unix workload attestor is UID based.
- JWT-SVIDs are not tracked by `jti`. A stolen SVID is usable until it expires.
- The authz signing key lives in memory and rotates only on restart.
- Services talk plain HTTP inside the compose network.
- No `tools/list` filtering, no client-side issuer allowlist, no JWKS refetch on unknown `kid`.

See the threat model table in [README.md](README.md).
