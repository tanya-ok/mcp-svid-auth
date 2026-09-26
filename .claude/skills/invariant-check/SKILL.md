---
name: invariant-check
description: Review a change against the security invariants in AGENTS.md before committing. Use for any change to authz.py, mcp_server.py, stdio_wrapper.py, spiffe_keys.py, policy.py, token formats or deploy/.
---

# Invariant check

Run before committing a change that touches the auth path.

1. `git diff --stat` and read every changed hunk in `src/` and `deploy/`.
2. For each invariant in `AGENTS.md` (deny by default, audience binding, no token passthrough, strict token checks, no secrets in output, fail closed, runtime keys), state in one line whether the change touches it and how.
3. For every touched invariant, point to the test that proves it still holds. If there is none, write it first.
4. Run `make check`. If `deploy/` or the token flow changed, run `make demo` and `make down`, and update the README Status table.
5. Run `uv run pytest -q tests/test_no_identifiers.py` and `gitleaks detect --source . --no-banner` if available.
6. Report: touched invariants, tests, results. Do not commit if any step fails.
