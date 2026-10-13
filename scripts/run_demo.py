"""Assert every real-stack scenario, retaining only safe outcomes in the report."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_svid_auth.audit import create_checkpoint, verify_lines
from scripts.kubernetes_demo import compose_command
from scripts.lab_runtime import DemoRuntimeError

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
A, B, ISSUER = "http://notes-a:8101/mcp", "http://notes-b:8102/mcp", "http://authz:8100"
RW = "notes:read notes:write"
SEARCH = 'notes.search={"query":"welcome"}'
WRITE = 'notes.write={"text":"injected instruction"}'


class DemoError(Exception):
    """Safe, operator-facing failure; never contains captured process output."""


def command(args: list[str], *, expected: int = 0, timeout: int = 120) -> str:
    try:
        result = compose_command(args, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, DemoRuntimeError):
        raise DemoError("command failed or timed out") from None
    if result.returncode != expected:
        raise DemoError(f"expected exit {expected}, received {result.returncode}")
    return result.stdout


def events(output: str) -> list[dict[str, Any]]:
    result = []
    for line in output.splitlines():
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict) and "event" in parsed:
            result.append(parsed)
    if not result:
        raise DemoError("no structured outcome")
    return result


def agent(
    resource: str = A,
    scope: str = RW,
    *,
    service: str = "agent-research",
    expected: int = 0,
    extra: list[str] | None = None,
) -> list[dict[str, Any]]:
    rows = events(
        command(
            [
                "run",
                "--rm",
                "--no-deps",
                "-T",
                service,
                "--trusted-issuer",
                ISSUER,
                "--allow-http",
                "--allow-private-network",
                "--resource",
                resource,
                "--scope",
                scope,
                *(extra or []),
            ],
            expected=expected,
        )
    )
    # The lab relaxes the URL policy on purpose; the client must say so exactly once.
    relaxed = [r for r in rows if r.get("event") == "url_policy_relaxed"]
    require(
        relaxed
        == [{"event": "url_policy_relaxed", "allow_http": True, "allow_private_network": True}],
        "relaxed URL policy not reported",
    )
    return [r for r in rows if r.get("event") != "url_policy_relaxed"]


def require(condition: bool, description: str) -> None:
    if not condition:
        raise DemoError(description)


def check_calls(
    rows: list[dict[str, Any]], resource: str, scope: str, expected: list[tuple[str, str]]
) -> None:
    tokens = [r for r in rows if r["event"] == "token"]
    calls = [r for r in rows if r["event"] == "call"]
    require(
        len(tokens) == 1
        and tokens[0].get("resource") == resource
        and tokens[0].get("scope") == scope
        and tokens[0].get("expires_in") == 300,
        "token metadata mismatch",
    )
    require(len(calls) == len(expected), "missing or extra tool outcome")
    for row, (tool, marker) in zip(calls, expected, strict=True):
        require(
            row.get("tool") == tool and marker in str(row.get("result")), "tool outcome mismatch"
        )


def wait_for_restart_key(*, timeout: float = 120) -> None:
    """Wait only for the resource server's asynchronous JWKS refresh."""
    deadline = time.monotonic() + timeout
    while True:
        rows = agent(scope="notes:read", extra=["--call", SEARCH])
        calls = [row for row in rows if row.get("event") == "call"]
        pending = len(calls) == 1 and calls[0].get("result") == (
            'HTTP 401: Bearer error="invalid_token"'
        )
        if not pending:
            check_calls(rows, A, "notes:read", [("notes.search", "welcome")])
            return
        # A pending key refresh must still carry the correct token/call evidence.
        check_calls(
            rows, A, "notes:read", [("notes.search", 'HTTP 401: Bearer error="invalid_token"')]
        )
        require(time.monotonic() < deadline, "restart key refresh timed out")
        time.sleep(1)


def check_denial(rows: list[dict[str, Any]], code: str) -> None:
    require(
        len(rows) == 1
        and rows[0].get("event") == "token_denied"
        and rows[0].get("error") == f"400 {code}",
        "token denial mismatch",
    )


def probe(mode: str) -> dict[str, Any]:
    rows = events(
        command(
            [
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--entrypoint",
                "python",
                "agent-research",
                "/app/deploy/probe_svid.py",
                mode,
            ],
            timeout=360,
        )
    )
    require(len(rows) == 1, "unexpected probe outcome count")
    return rows[0]


def audit_lines(service: str) -> list[str]:
    output = command(["logs", "--no-log-prefix", service])
    return [line for line in output.splitlines() if line.startswith('{"record_id"')]


def scenarios(record: Any) -> None:  # noqa: PLR0915 - numbered demonstration
    check_calls(agent(), A, RW, [("notes.search", "welcome"), ("notes.write", "stored note #")])
    record(1, "allowlisted read and write")
    check_calls(
        agent(B, "notes:read"),
        B,
        "notes:read",
        [
            ("notes.search", "welcome"),
            ("notes.write", 'HTTP 403: Bearer error="insufficient_scope"'),
        ],
    )
    record(2, "per-tool scope denial")
    check_denial(agent(service="agent-intruder", expected=2), "unauthorized_client")
    record(3, "unlisted identity denied")
    check_calls(
        agent(extra=["--steal-token", B]),
        A,
        RW,
        [
            ("notes.search", 'HTTP 401: Bearer error="invalid_token"'),
            ("notes.write", 'HTTP 401: Bearer error="invalid_token"'),
        ],
    )
    require(
        any("InvalidAudienceError" in line for line in audit_lines("notes-b")),
        "wrong-audience audit absent",
    )
    record(4, "cross-resource replay denied")
    check_denial(agent(service="agent-impostor", expected=2), "unauthorized_client")
    record(5, "copied labels do not impersonate another ServiceAccount")
    rogue = agent("http://notes-rogue:8103/mcp", "notes:read", expected=2)
    require(len(rogue) == 1 and rogue[0].get("event") == "issuer_refused", "issuer refusal absent")
    record(6, "untrusted issuer refused")
    require(
        probe("replay")
        == {
            "event": "svid_replay",
            "statuses": [200, 200],
            "issued": [True, True],
            "second_error": None,
        },
        "reuse mode mismatch",
    )
    observed = probe("issuance")
    require(
        observed.get("event") == "issuer_observation"
        and observed.get("fetches") == 3
        and 1 <= observed.get("distinct_assertions", 0) <= 3
        and observed.get("all_have_jti") is True
        and observed.get("distinct_jti") == observed.get("distinct_assertions")
        and observed.get("accepted") is True,
        "real issuer observation failed",
    )
    record(
        7,
        "cached SVID reuse permitted; three real fetches yielded "
        + str(observed["distinct_assertions"])
        + " distinct signed assertions",
    )
    check_calls(
        agent(scope="notes:read", extra=["--call", 'notes.search_upstream={"query":"welcome"}']),
        A,
        "notes:read",
        [("notes.search_upstream", "welcome")],
    )
    downstream = [json.loads(line) for line in audit_lines("notes-b")]
    require(
        any(
            r["spiffe_id"] == "spiffe://example.org/mcp/notes-a"
            and r["decision"] == "allow"
            and r["tool"] == "notes.search"
            for r in downstream
        ),
        "upstream workload identity absent",
    )
    record(8, "own upstream identity; byte-level no-passthrough proof in offline tests")
    policy_path = DEPLOY / ".data/policy/policy.yaml"
    original = policy_path.read_text()
    check_calls(
        agent(B, "notes:read", extra=["--call", SEARCH]),
        B,
        "notes:read",
        [("notes.search", "welcome")],
    )
    policy_path.write_text(original.replace("      http://notes-b:8102/mcp: [notes:read]\n", "", 1))
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            time.sleep(1)
            if '"decision":"policy_reload"' in command(["logs", "--no-log-prefix", "authz"]):
                # The initial reload is also logged. A denied request is the decisive assertion.
                try:
                    rows = agent(B, "notes:read", expected=2, extra=["--call", SEARCH])
                except DemoError:
                    continue
                check_denial(rows, "invalid_target")
                break
        else:
            raise DemoError("grant was not revoked before the deadline")
    finally:
        policy_path.write_text(original)
    record(9, "new tokens denied after policy revocation")
    check_calls(
        agent(scope="notes:read", extra=["--call", WRITE]),
        A,
        "notes:read",
        [("notes.write", 'HTTP 403: Bearer error="insufficient_scope"')],
    )
    check_calls(agent(extra=["--call", WRITE]), A, RW, [("notes.write", "stored note #")])
    record(10, "identity cannot determine intent; a granted write still succeeds")
    command(["restart", "authz"])
    require(probe("ready").get("ok") is True, "restart readiness failed")
    wait_for_restart_key()
    rotated = probe("rotation")
    require(
        rotated.get("event") == "planned_rotation"
        and all(
            rotated.get(name) is True
            for name in (
                "prepublished",
                "public_only",
                "old_and_new_keys_present",
                "old_token_accepted",
                "new_token_accepted",
            )
        ),
        "planned key overlap failed",
    )
    record(11, "restart key accepted; planned overlap preserves old and new tokens")
    life = probe("lifecycle")
    require(
        life.get("event") == "svid_lifecycle"
        and life.get("successful_requests", 0) >= 2
        and life.get("renewed_after_expiry") is True
        and life.get("tool_after_expiry") is True
        and life.get("old_status") == 401
        and life.get("old_error") == "invalid_client",
        "SVID renewal or expiry failure",
    )
    record(12, "continued token requests through SVID expiry; expired assertion refused")
    require(
        probe("strict")
        == {
            "event": "strict_replay",
            "statuses": [200, 401],
            "issued": [True, False],
            "second_error": "invalid_client",
        },
        "strict replay was not denied",
    )
    record(13, "default strict SVID single-use rejection")
    for service in ("notes-a", "notes-b"):
        lines = audit_lines(service)
        require(bool(lines) and not verify_lines(lines)[1], "invalid audit chain")
        checkpoint = create_checkpoint(lines)
        require(bool(verify_lines(lines[:-1], checkpoint)[1]), "tail deletion not detected")
        (DEPLOY / f".data/{service}.jsonl").write_text("\n".join(lines) + "\n")
        (DEPLOY / f".data/{service}.checkpoint.json").write_text(checkpoint.to_json())
    record(14, "audit links verify; checkpoint detects tail deletion")
    for number, mode, service in (
        (15, "allowed", "agent-research"),
        (16, "intruder", "agent-intruder"),
        (17, "no-cert", "agent-research"),
    ):
        rows = events(
            command(
                [
                    "run",
                    "--rm",
                    "--no-deps",
                    "-T",
                    "--entrypoint",
                    "python",
                    service,
                    "/app/deploy/probe_fhir.py",
                    mode,
                ]
            )
        )
        require(len(rows) == 1 and rows[0].get("ok") is True, "FHIR integration or denial failed")
        record(number, "FHIR SPIRE mTLS/OAuth: " + mode)
    output = command(["logs", "--no-log-prefix", "fhir"])
    audit_probe = subprocess.run(  # noqa: S603 - explicit local script, no shell
        [
            sys.executable,
            str(ROOT.parent / "hipaa-fhir-mcp/deploy/kubernetes/probe_fhir.py"),
            "audit",
        ],
        input=output,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    rows = events(audit_probe.stdout)
    require(
        audit_probe.returncode == 0 and len(rows) == 1 and rows[0].get("ok") is True,
        "FHIR audit verification failed",
    )
    record(18, "FHIR audit caller and data minimization verified")


def main() -> None:
    report: dict[str, Any] = {
        "version": 1,
        "timestamp": datetime.now(UTC).isoformat(),
        "spire": "1.15.3",
        "svid_ttl_seconds": 60,
        "backend": "lima-kubernetes-containerd",
        "results": [],
        "passed": False,
    }

    def record(number: int, description: str) -> None:
        report["results"].append({"scenario": number, "passed": True, "description": description})
        print(f"PASS {number}: {description}", flush=True)

    try:
        scenarios(record)
        report["passed"] = True
    except DemoError as exc:
        report["failure"] = str(exc)
        print(f"FAIL: {exc}", flush=True)
    finally:
        (DEPLOY / ".data/demo-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        raise SystemExit(1)
    print(f"All {len(report['results'])} scenarios passed. Report: deploy/.data/demo-report.json")


if __name__ == "__main__":
    main()
