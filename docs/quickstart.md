# Quickstart

## Requirements

| Need | For |
|---|---|
| Python 3.12+ | Everything |
| [uv](https://docs.astral.sh/uv/) | Dependencies and running commands |
| Docker daemon | `make demo` only |

## Install

```sh
git clone https://github.com/tanya-ok/mcp-svid-auth.git
cd mcp-svid-auth
uv sync
```

`uv sync` installs the package, its console scripts and the `dev` dependency group from `uv.lock`.

## Offline checks

```sh
make check
```

| Target | Runs |
|---|---|
| `make lint` | `ruff check`, `ruff format --check .`, `mypy` (strict) |
| `make test` | `pytest -q` |
| `make check` | `lint` then `test` |

Offline tests need no SPIRE. They use `LocalSvidIssuer`, a local ES256 key that stands in for SPIRE and mints JWT-SVIDs. `mcp-svid-authz --static-jwks` accepts a JWKS file for the same purpose.

Optional anonymization check: put one term per line in `tests/denylist.txt` (git-ignored). `tests/test_no_identifiers.py` then fails on any match in the tree or history.

## SPIRE demo

```sh
make demo
make down
```

`make demo` runs `deploy/demo.sh`, which:

1. Starts the SPIRE server (1.15.3, pinned by digest) and exports its bundle.
2. Generates a join token and starts the SPIRE agent.
3. Registers five workloads by container label (`deploy/register.sh`).
4. Builds and starts `authz`, `notes-a` and `notes-b`.
5. Runs the ten [demo scenarios](demo.md), prints the audit lines and verifies the notes-a and notes-b audit chains.

`make down` removes the compose stack and its volumes.

## Build these docs

```sh
uv run --group docs zensical serve
uv run --group docs zensical build --strict
```

The site is written to `site/` (git-ignored).
