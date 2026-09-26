# AGENTS.md

Instructions for AI coding agents (and humans) working in this repository. Vendor-neutral; `CLAUDE.md` points here. Project skills live in `.claude/skills/` (`roadmap-export`, `invariant-check`).

## What this project is

A proof of concept: SPIFFE JWT-SVIDs used as OAuth client credentials for MCP servers, so agents never hold static API keys. Not production software. Read `README.md` and `docs/security.md` before changing behaviour.

| Module | Role |
|---|---|
| `src/mcp_svid_auth/authz.py` | Token endpoint. Validates the JWT-SVID assertion, applies `policy.py`, issues 5-minute ES256 access tokens bound to one `resource` |
| `src/mcp_svid_auth/mcp_server.py` | MCP server (Streamable HTTP). Validates tokens, enforces per-tool scopes, writes audit lines |
| `src/mcp_svid_auth/agent_client.py` | Agent side. Fetches its SVID, gets a token, calls tools. `--steal-token` demo |
| `src/mcp_svid_auth/stdio_wrapper.py` | Local stdio launcher that hands the child a short-lived token file |
| `src/mcp_svid_auth/spiffe_keys.py` | Workload API and static-JWKS key sources |
| `deploy/` | SPIRE server and agent in Docker Compose, registration and demo scripts |

## Commands

| Task | Command |
|---|---|
| Install | `uv sync --locked` |
| Lint, types, tests | `make check` |
| Integration demo (needs Docker) | `make demo`, then `make down` |
| Docs build | `uv run --locked --only-group docs zensical build --strict --clean` |

Run `make check` before every commit. Run `make demo` after any change to `deploy/`, token formats, or the auth flow, and update the README Status table with the real result.

## Security invariants (do not weaken)

1. **Deny by default.** A tool without a declared scope must stop the server from starting. Unknown tools and unparseable bodies get 400. Oversized bodies get 413.
2. **Audience binding.** Access tokens carry exactly one `aud`, the MCP server's canonical URI. Servers reject any other audience.
3. **No token passthrough.** A server never forwards an incoming token anywhere. If a server needs to call something upstream, it gets its own credential.
4. **Strict token checks.** Resource side accepts only `typ: at+jwt`, ES256, and requires `iss`, `aud`, `exp`, `iat`. SVIDs must carry `iat` and stay under the configured maximum lifetime.
5. **No secrets in output.** Error responses use fixed strings. Exception text, tokens and keys never reach responses or audit lines.
6. **Fail closed.** If a credential cannot be refreshed before expiry, the stdio wrapper deletes the token file, stops the child and exits non-zero.
7. **Keys are generated at runtime.** Never commit a private key, a real JWKS, or a join token.

Any change that touches one of these needs a test that proves the invariant still holds.

## Provenance and privacy

- Clean-room project. Do not copy code, text, rule names or structure from any employer repository, internal plugin or private project. Write from public standards and this repository only.
- Fixtures and examples use `example.org` trust domains only.
- `tests/test_no_identifiers.py` scans the tree and full history. It reads a git-ignored `tests/denylist.txt`; never commit that file and never put its contents anywhere tracked.
- Commit author email must be the maintainer's personal address. Check before the first commit in a new clone.
- The roadmap is public in `.beads/issues.jsonl`. Issues labelled `personal` (writing, newsletter, career) stay local and are filtered out of the export. Drop the `owner` field from the export.

## Style

- Python 3.12+, `ruff` and `mypy --strict` clean, tests in `pytest`.
- Dependencies: upper-bound every major; images pinned by digest; GitHub Actions pinned by full commit SHA with a version comment.
- No em dashes or en dashes anywhere, including code, docs and commit messages. Use a plain hyphen.
- English only in the repository.

## Commits

- Format `type: Subject`, where type is one of `feat fix docs test chore ci refactor security perf`. Capitalized subject, no trailing period.
- Small logical commits; each should pass `make check` on its own.
- Never bypass hooks (`--no-verify`). If a hook fails, fix the cause.
- Normal pushes only. `main` is protected against force pushes and deletion.

## Out of scope for agents

- Changing repository visibility, security settings, or GitHub Pages settings.
- Publishing releases or packages.
- Anything that sends data to an external service beyond fetching public documentation.
