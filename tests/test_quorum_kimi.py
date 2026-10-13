"""Bounded API exchange and optional peer voting behavior."""

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx2
import pytest

from scripts import quorum_core as core
from scripts import quorum_kimi as kimi
from scripts.quorum_models import PROJECTS, QuorumError


def install_transport(monkeypatch: pytest.MonkeyPatch, response: httpx2.Response) -> list[Any]:
    calls: list[Any] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(json.loads(request.content))
        assert request.url == kimi.ENDPOINT
        return response

    original = httpx2.AsyncClient

    def factory(**kwargs: Any) -> httpx2.AsyncClient:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return original(transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx2, "AsyncClient", factory)
    return calls


def test_one_bounded_request_preserves_only_review_and_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review = core.fixture("verify")
    calls = install_transport(
        monkeypatch,
        httpx2.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": review.model_dump_json(),
                            "reasoning_content": "do not persist",
                        },
                    }
                ],
                "usage": {"total_tokens": 33, "private_field": "do not persist"},
            },
        ),
    )
    result, usage = asyncio.run(kimi.request_review("review JSON", "synthetic-key"))
    assert result == review
    assert usage == {"total_tokens": 33}
    assert len(calls) == 1
    assert calls[0]["max_tokens"] == kimi.MAX_TOKENS
    assert "tools" not in calls[0]


@pytest.mark.parametrize("status", [302, 401, 429, 500])
def test_errors_do_not_retry_or_echo_body(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    calls = install_transport(monkeypatch, httpx2.Response(status, text="sensitive diagnostic"))
    with pytest.raises(QuorumError, match=r"^moonshot_request_refused$"):
        asyncio.run(kimi.request_review("review JSON", "synthetic-key"))
    assert len(calls) == 1


def test_truncated_output_is_not_a_vote(monkeypatch: pytest.MonkeyPatch) -> None:
    install_transport(
        monkeypatch,
        httpx2.Response(
            200,
            json={
                "choices": [{"finish_reason": "length", "message": {"content": "{}"}}],
            },
        ),
    )
    with pytest.raises(QuorumError, match="kimi_incomplete_output"):
        asyncio.run(kimi.request_review("review JSON", "synthetic-key"))


def test_missing_key_and_oversized_prompt_fail_before_network() -> None:
    with pytest.raises(QuorumError, match="moonshot_key_missing"):
        asyncio.run(kimi.request_review("review JSON", ""))
    with pytest.raises(QuorumError, match="kimi_prompt_too_large"):
        asyncio.run(kimi.request_review("a" * (kimi.MAX_PROMPT + 1), "synthetic-key"))


def test_peer_can_veto_but_cannot_erase_original_disagreement(tmp_path: Path) -> None:
    run = core.new_run(["engineering-os"], demo=True, runs=tmp_path)
    instance = core.Coordinator(run)

    async def stages() -> None:
        for stage in ("research", "verify", "rebuttal"):
            await instance.step("engineering-os", stage)

    asyncio.run(stages())
    peer = core.fixture("verify").model_dump()
    peer["votes"][0]["verdict"] = "dispute"
    target = run / "engineering-os" / "kimi.json"
    core.write_json(target, {"review": peer})
    assert instance.report()["projects"][0]["findings"][0]["status"] == "unresolved"
    peer["votes"][0]["verdict"] = "support"
    core.write_json(target, {"review": peer})
    assert instance.report()["projects"][0]["findings"][0]["status"] == "consensus_proposal"
    original = core.fixture("verify").model_dump()
    original["votes"][0]["verdict"] = "needs_test"
    core.write_json(run / "engineering-os" / "verify.json", original)
    assert instance.report()["projects"][0]["findings"][0]["status"] == "unresolved"


def test_schema_failure_keeps_usage_without_content(monkeypatch: pytest.MonkeyPatch) -> None:
    invalid = core.fixture("verify").model_dump()
    invalid["summary"] = "private response text " * 200
    install_transport(
        monkeypatch,
        httpx2.Response(
            200,
            json={
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(invalid)}}],
                "usage": {"total_tokens": 42},
            },
        ),
    )
    with pytest.raises(kimi.InvalidPeerResponseError) as caught:
        asyncio.run(kimi.request_review("review JSON", "synthetic-key"))
    assert str(caught.value) == "kimi_schema_invalid"
    assert caught.value.usage == {"total_tokens": 42}
    assert caught.value.categories == ["string_too_long"]
    assert "private response text" not in str(caught.value)


def test_required_peer_blocks_completion_and_proposal(tmp_path: Path) -> None:
    run = core.new_run(["engineering-os"], demo=True, runs=tmp_path)
    instance = core.Coordinator(run)
    instance.manifest["required_peers"] = ["kimi"]

    async def stages() -> None:
        for stage in ("research", "verify", "rebuttal"):
            await instance.step("engineering-os", stage)

    asyncio.run(stages())
    row = instance.report()["projects"][0]
    assert row["base_complete"] and not row["complete"]
    assert row["findings"][0]["status"] == "pending"
    core.write_json(
        run / "engineering-os" / "kimi.json", {"review": core.fixture("verify").model_dump()}
    )
    assert instance.report()["complete"]


def test_batch_visits_all_six_after_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = core.Coordinator(core.new_run(list(PROJECTS), demo=True, runs=tmp_path))
    seen = []

    async def fake_review(coordinator: core.Coordinator, project: str) -> dict[str, Any]:
        seen.append(project)
        if project == PROJECTS[0]:
            raise QuorumError("previous_stage_required")
        return {"status": "complete"}

    monkeypatch.setattr(kimi, "review_run", fake_review)
    results = asyncio.run(kimi.review_selected(instance))
    assert seen == list(PROJECTS)
    assert results[PROJECTS[0]]["status"] == "incomplete"
    assert results[PROJECTS[-1]]["status"] == "complete"


def test_new_live_runs_require_kimi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "snapshot", core.demo_packet)
    monkeypatch.setattr(core, "provider_versions", lambda: {})
    run = core.new_run(["engineering-os"], runs=tmp_path)
    assert core.Coordinator(run, live=True).manifest["required_peers"] == ["kimi"]
