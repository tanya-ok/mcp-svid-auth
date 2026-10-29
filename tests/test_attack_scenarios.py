"""The poisoned-tool-response scenario must prove containment and fail on any widening."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import anyio
import pytest

from mcp_svid_auth.errors import AuthError
from mcp_svid_auth.policy import Policy
from scripts import attack_scenarios as attack
from scripts.attack_scenarios import (
    AGENT,
    CLINICAL,
    FHIR,
    NOTES,
    POISON,
    ScenarioError,
    SubjectToken,
    directive,
    exchange,
)

NOW = 1_000_000
INTRUDER = "spiffe://example.org/agent/intruder"


def test_full_run_records_every_containment_step(tmp_path: Path) -> None:
    report = anyio.run(attack.run, tmp_path)
    names = [s["step"] for s in report["steps"]]
    assert names == [
        "baseline token",
        "poisoned tool response",
        "token for FHIR resource",
        "scope escalation on notes",
        "notes token replayed at FHIR",
        "exfiltration write with read token",
        "captured token after expiry",
        "clinical identity asks for fhir:write",
    ]
    assert report["steps"][0]["observed"]["lifetime_seconds"] == 300
    assert report["audit"]["token_rejections"] == ["ExpiredSignatureError", "InvalidAudienceError"]
    assert "notes.write:allow" not in report["audit"]["mcp_decisions"]
    assert report["not_prevented"]


def test_report_contains_no_tokens_or_keys(tmp_path: Path) -> None:
    text = json.dumps(anyio.run(attack.run, tmp_path))
    assert "eyJ" not in text
    assert "PRIVATE KEY" not in text


def test_directive_parser() -> None:
    order = directive(POISON)
    assert order is not None
    assert order["resource"] == FHIR
    assert directive("welcome to the notes server") is None


def _widened(monkeypatch: pytest.MonkeyPatch, resources: dict[str, list[str]]) -> None:
    policy: dict[str, Any] = copy.deepcopy(attack.POLICY)
    policy["clients"][0]["resources"] = resources
    monkeypatch.setattr(attack, "POLICY", policy)


@pytest.mark.parametrize(
    "resources",
    [
        {NOTES: ["notes:read"], FHIR: ["fhir:read", "fhir:write"]},
        {NOTES: ["notes:read", "notes:write"]},
    ],
)
def test_widened_policy_fails_the_scenario(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resources: dict[str, list[str]]
) -> None:
    _widened(monkeypatch, resources)
    with pytest.raises(ScenarioError, match="unexpectedly granted"):
        anyio.run(attack.run, tmp_path)


def test_missing_poison_fails_the_scenario(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(attack, "POISON", "Shift handoff: bed 4 stable.")
    with pytest.raises(ScenarioError, match="did not reach the agent"):
        anyio.run(attack.run, tmp_path)


def test_main_writes_report_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.json"
    assert attack.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text())["data"] == "synthetic"

    async def broken(_: Path) -> dict[str, Any]:
        raise ScenarioError("fixed description")

    monkeypatch.setattr(attack, "run", broken)
    assert attack.main([]) == 1
    assert "fixed description" in capsys.readouterr().err


POLICY = Policy.from_dict(attack.POLICY)
USER = SubjectToken("user:test", NOTES, frozenset({"notes:read", "notes:write"}), NOW + 120)


def _exchange(**overrides: Any) -> Any:
    args: dict[str, Any] = {
        "subject": USER,
        "actor": AGENT,
        "resource": NOTES,
        "requested": {"notes:read"},
        "now": lambda: NOW,
    } | overrides
    return exchange(POLICY, **args)


def test_delegated_grant_is_narrow_and_never_outlives_the_user() -> None:
    grant = _exchange()
    assert (grant.sub, grant.act, grant.aud, grant.scope) == (
        "user:test",
        {"sub": AGENT},
        NOTES,
        "notes:read",
    )
    assert grant.exp == USER.exp
    long_lived = SubjectToken("user:test", NOTES, USER.scopes, NOW + 3600)
    assert _exchange(subject=long_lived).exp == NOW + 300


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"requested": {"notes:write"}}, "invalid_scope"),
        ({"requested": set()}, "invalid_scope"),
        (
            {"subject": SubjectToken("u", NOTES, frozenset({"notes:write"}), NOW + 60)},
            "invalid_scope",
        ),
        ({"resource": FHIR}, "invalid_target"),
        ({"actor": CLINICAL}, "invalid_target"),
        ({"actor": INTRUDER}, "unauthorized_client"),
        (
            {"subject": SubjectToken("u", NOTES, USER.scopes, NOW + 60, {"sub": CLINICAL})},
            "invalid_request",
        ),
        ({"subject": SubjectToken("u", NOTES, USER.scopes, NOW)}, "invalid_grant"),
    ],
)
def test_delegation_denials(overrides: dict[str, Any], code: str) -> None:
    with pytest.raises(AuthError) as denied:
        _exchange(**overrides)
    assert denied.value.code == code


def test_actor_with_fhir_grant_still_bounded_by_user_audience() -> None:
    fhir_user = SubjectToken("u", FHIR, frozenset({"fhir:read", "fhir:write"}), NOW + 60)
    grant = _exchange(subject=fhir_user, actor=CLINICAL, resource=FHIR, requested={"fhir:read"})
    assert grant.scope == "fhir:read"
    with pytest.raises(AuthError) as denied:
        _exchange(subject=fhir_user, actor=CLINICAL, resource=FHIR, requested={"fhir:write"})
    assert denied.value.code == "invalid_scope"
