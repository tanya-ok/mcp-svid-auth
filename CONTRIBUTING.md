# Contributing

This is a proof of concept. Small, focused changes are welcome.

## Setup and checks

```sh
uv sync --locked
make check
```

`make check` runs ruff, formatting, strict mypy, the configuration docs drift check and pytest. It must pass before every commit. Changes to `deploy/`, token formats or the auth flow also need the lab demo described in [docs/kubernetes-lab.md](docs/kubernetes-lab.md).

## Rules

- Read [AGENTS.md](AGENTS.md). Do not weaken a security invariant; any change that touches one needs a test proving it still holds.
- Use synthetic data only: `example.org` trust domains, runtime-generated keys, no real tokens, JWKS, join tokens or personal data.
- English only. No em dashes or en dashes.
- Commit format `type(scope): Subject`, scope optional. Types: `feat fix docs test chore ci refactor security perf`. Capitalized subject, no trailing period.
- Never bypass hooks with `--no-verify`.

## Security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
