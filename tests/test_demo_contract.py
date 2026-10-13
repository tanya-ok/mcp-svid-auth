"""The demo gate must fail on missing evidence and unexpected success or denial."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scripts import run_demo as demo
from scripts.run_demo import A, DemoError, check_calls, check_denial, command, events


@pytest.mark.parametrize("output", ["", "{}", "traceback", '{"event":"token"}\n'])
def test_missing_calls_never_pass(output: str) -> None:
    with pytest.raises(DemoError):
        check_calls(events(output), A, "notes:read", [("notes.search", "welcome")])


@pytest.mark.parametrize(
    "rows", [[], [{"event": "token"}], [{"event": "token_denied", "error": "400 invalid_scope"}]]
)
def test_unexpected_denial_or_success_never_pass(rows: list[dict[str, Any]]) -> None:
    with pytest.raises(DemoError):
        check_denial(rows, "unauthorized_client")


def test_wrong_process_exit_is_failure_without_raw_output(monkeypatch: Any) -> None:
    class Failed:
        returncode = 1
        stdout = "secret token"
        stderr = "private exception"

    monkeypatch.setattr("scripts.run_demo.compose_command", lambda *args, **kwargs: Failed())
    with pytest.raises(DemoError, match="expected exit 0, received 1") as failure:
        command(["run", "agent-research"])
    assert "secret" not in str(failure.value)


def test_scope_denial_requires_both_token_and_call_evidence() -> None:
    rows: list[dict[str, Any]] = [
        {"event": "token", "resource": A, "scope": "notes:read", "expires_in": 300},
        {
            "event": "call",
            "tool": "notes.write",
            "result": 'HTTP 403: Bearer error="insufficient_scope"',
        },
    ]
    check_calls(
        events("\n".join(json.dumps(r) for r in rows)),
        A,
        "notes:read",
        [("notes.write", 'HTTP 403: Bearer error="insufficient_scope"')],
    )
    rows[1]["result"] = "stored note #2"
    with pytest.raises(DemoError):
        check_calls(rows, A, "notes:read", [("notes.write", "HTTP 403")])


def test_restart_wait_retries_only_pending_key_and_requires_success(monkeypatch: Any) -> None:
    token = {"event": "token", "resource": A, "scope": "notes:read", "expires_in": 300}
    pending = [
        token,
        {
            "event": "call",
            "tool": "notes.search",
            "result": 'HTTP 401: Bearer error="invalid_token"',
        },
    ]
    good = [token, {"event": "call", "tool": "notes.search", "result": "welcome"}]
    rows = iter([pending, good])
    monkeypatch.setattr(demo, "agent", lambda **kwargs: next(rows))
    monkeypatch.setattr("scripts.run_demo.time.sleep", lambda _: None)
    demo.wait_for_restart_key()
    monkeypatch.setattr(demo, "agent", lambda **kwargs: pending)
    with pytest.raises(DemoError, match="timed out"):
        demo.wait_for_restart_key(timeout=0)
    monkeypatch.setattr(
        demo,
        "agent",
        lambda **kwargs: [token, {"event": "call", "tool": "notes.search", "result": "unexpected"}],
    )
    with pytest.raises(DemoError, match="tool outcome mismatch"):
        demo.wait_for_restart_key()
