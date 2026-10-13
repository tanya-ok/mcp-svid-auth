"""Exercise evidence, orchestration, provider failure and presentation boundaries."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import quorum
from scripts import quorum_core as core
from scripts import quorum_providers as providers
from scripts import quorum_tasks as tasks
from scripts.quorum_models import (
    PROJECTS,
    STAGES,
    Evidence,
    QuorumError,
    Review,
    validate_review,
)


def coordinator(tmp_path: Path) -> core.Coordinator:
    return core.Coordinator(core.new_run(["hipaa-fhir-mcp"], demo=True, runs=tmp_path))


def test_no_quorum_until_all_stages_complete(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)

    async def run() -> None:
        await instance.step("hipaa-fhir-mcp", "research")
        assert not instance.report()["complete"]
        assert instance.report()["projects"][0]["findings"][0]["status"] == "pending"
        await instance.step("hipaa-fhir-mcp", "verify")
        await instance.step("hipaa-fhir-mcp", "rebuttal")
        assert instance.report()["complete"]
        assert instance.report()["mode"] == "fixture"
        assert instance.report()["projects"][0]["findings"][0]["status"] == "consensus_proposal"
        before = (instance.run / "events.jsonl").read_text()
        assert (await instance.step("hipaa-fhir-mcp", "research"))["status"] == "already_complete"
        assert (instance.run / "events.jsonl").read_text() == before

    asyncio.run(run())


@pytest.mark.parametrize("stage", ["verify", "rebuttal"])
def test_out_of_order_stage_is_refused(tmp_path: Path, stage: str) -> None:
    with pytest.raises(QuorumError, match="previous_stage_required"):
        asyncio.run(coordinator(tmp_path).step("hipaa-fhir-mcp", stage))


@pytest.mark.parametrize(
    "project,stage", [("../escape", "research"), ("hipaa-fhir-mcp", "execute")]
)
def test_tool_arguments_cannot_be_commands(tmp_path: Path, project: str, stage: str) -> None:
    with pytest.raises(QuorumError):
        asyncio.run(coordinator(tmp_path).step(project, stage))


def test_packet_tampering_is_refused(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    path = instance.run / "hipaa-fhir-mcp/packet.json"
    path.write_text(path.read_text().replace("return True", "return False"))
    with pytest.raises(QuorumError, match="snapshot_changed"):
        instance.report()


@pytest.mark.parametrize(
    "evidence",
    [
        Evidence(path="src/absent.py", line=2, quote="return True"),
        Evidence(path="src/example.py", line=1, quote="return True"),
        Evidence(path="src/example.py", line=200, quote="return True"),
    ],
)
def test_fabricated_evidence_is_refused(evidence: Evidence) -> None:
    review = core.fixture("research")
    review.findings[0].evidence = [evidence]
    with pytest.raises(QuorumError):
        validate_review(review, core.demo_packet("hipaa-fhir-mcp"), "research", set())


def test_missing_and_duplicate_votes_are_refused() -> None:
    review = core.fixture("verify")
    review.votes *= 2
    with pytest.raises(QuorumError, match="incomplete_review_votes"):
        validate_review(review, core.demo_packet("hipaa-fhir-mcp"), "verify", {"F1"})
    review.votes = []
    with pytest.raises(QuorumError, match="incomplete_review_votes"):
        validate_review(review, core.demo_packet("hipaa-fhir-mcp"), "verify", {"F1"})


def test_disagreement_survives_rebuttal(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    for stage in STAGES:
        asyncio.run(instance.step("hipaa-fhir-mcp", stage))
    path = instance.run / "hipaa-fhir-mcp/verify.json"
    review = Review.model_validate_json(path.read_text())
    review.votes[0].verdict = "needs_test"
    path.write_text(review.model_dump_json())
    assert instance.report()["projects"][0]["findings"][0]["status"] == "unresolved"


def test_fixture_cannot_be_mislabeled_live(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    with pytest.raises(QuorumError, match="run_mode_mismatch"):
        core.Coordinator(instance.run, live=True)


def test_second_server_cannot_mutate_active_run(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    (instance.run / ".active").mkdir()
    with pytest.raises(QuorumError, match="run_busy"):
        asyncio.run(instance.step("hipaa-fhir-mcp", "research"))


def test_provider_failure_is_recorded_without_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = coordinator(tmp_path)
    instance.live = True
    instance.manifest["mode"] = "live"

    async def fail(*args: object, **kwargs: object) -> Review:
        raise QuorumError("provider_timeout")

    monkeypatch.setattr(core, "invoke", fail)
    with pytest.raises(QuorumError, match="provider_timeout"):
        asyncio.run(instance.step("hipaa-fhir-mcp", "research"))
    events = [json.loads(s) for s in (instance.run / "events.jsonl").read_text().splitlines()]
    assert events[-1]["outcome"] == "provider_timeout"
    assert not instance.report()["complete"]
    assert not (instance.run / ".active").exists()


def test_snapshot_excludes_untracked_files_and_escaping_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "hipaa-fhir-mcp"
    (root / "src").mkdir(parents=True)
    (root / "README.md").write_text("Synthetic project")
    (root / "src/safe.ts").write_text("export const safe = true;")
    (root / "src/untracked.ts").write_text("Untracked context must stay private")
    (root / "src/link.ts").symlink_to(tmp_path / "outside")
    (tmp_path / "outside").write_text("not allowed")

    def fake_git(root: Path, *args: str) -> str:
        if args[0] == "ls-files":
            return "README.md\0src/safe.ts\0src/link.ts\0tests/denylist.txt\0"
        return "abc" if args[0] == "rev-parse" else ""

    monkeypatch.setattr(core, "git", fake_git)
    monkeypatch.setitem(
        core.PROJECT_FILES, "hipaa-fhir-mcp", {"README.md", "src/safe.ts", "src/link.ts"}
    )
    packet = core.snapshot("hipaa-fhir-mcp", tmp_path)
    assert {s.path for s in packet.sources} == {"README.md", "src/safe.ts"}
    assert packet.omitted == ["src/link.ts"]


def test_every_project_has_a_focused_source_selection() -> None:
    assert set(core.PROJECT_FILES) == set(PROJECTS)
    assert core.PROJECT_FILES["it-grc"] == {"src/it_grc/grc_push.py", "src/it_grc/grc_client.py"}


def test_engineering_snapshot_excludes_vaults_and_private_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "engineering-os"
    names = [
        "dashboard/src/beads.ts",
        "dashboard/dashboard.json",
        "user-vault-template/facts.md",
        "src/unrelated.ts",
    ]
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("Synthetic content")

    def fake_git(root: Path, *args: str) -> str:
        return "\0".join(names) if args[0] == "ls-files" else "abc"

    monkeypatch.setattr(core, "git", fake_git)
    packet = core.snapshot("engineering-os", tmp_path)
    assert [s.path for s in packet.sources] == ["dashboard/src/beads.ts"]
    assert "tracker-neutral" in core.prompt_for(packet, "research", {})
    assert "Return at most one finding" in core.prompt_for(packet, "research", {})
    for stage in ("verify", "rebuttal"):
        prompt = core.prompt_for(packet, stage, {})
        assert "Return at most one finding" not in prompt
        assert "findings=[]" in prompt


def test_privacy_uses_local_denylist_without_echo(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/denylist.txt").write_text("synthetic-private-marker\n")
    with pytest.raises(QuorumError, match=r"^private_content_refused$"):
        core.privacy("SYNTHETIC-PRIVATE-MARKER", tmp_path)


def test_report_escapes_untrusted_html(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    asyncio.run(instance.step("hipaa-fhir-mcp", "research"))
    report = instance.report()
    report["projects"][0]["findings"][0]["title"] = "<script>alert(1)</script>"
    quorum.render(instance.run, report)
    page = (instance.run / "index.html").read_text()
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "Synthetic demonstration" in page
    assert "Content-Security-Policy" in page


@pytest.mark.parametrize(
    "code,timeout,expected",
    [
        ("import time; time.sleep(10)", 0.1, "provider_timeout"),
        ("print('x'*300000)", 2, "provider_output_too_large"),
        ("raise SystemExit(7)", 2, "provider_nonzero_exit"),
    ],
)
def test_real_child_failures_are_bounded(
    tmp_path: Path, code: str, timeout: float, expected: str
) -> None:
    with pytest.raises(QuorumError, match=expected):
        asyncio.run(
            providers.bounded_process(
                [sys.executable, "-c", code], "", tmp_path, timeout, os.environ.copy()
            )
        )


def test_adapter_commands_restrict_capabilities(tmp_path: Path) -> None:
    claude = providers.commands("claude", "/example/claude", tmp_path)
    assert claude[claude.index("--tools") + 1] == "WebSearch,WebFetch"
    assert "--safe-mode" in claude and "--strict-mcp-config" in claude
    source_only = providers.commands("claude", "/example/claude", tmp_path, web_tools=False)
    assert source_only[source_only.index("--tools") + 1] == ""
    codex = providers.commands("codex", "/example/codex", tmp_path)
    assert codex[codex.index("--sandbox") + 1] == "read-only"
    assert "features.shell_tool=false" in codex
    assert "--ignore-user-config" in codex


def test_actual_stdio_mcp_cycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Use the real default run directory because the subprocess resolves its own configuration.
    run = core.new_run(["hipaa-fhir-mcp"], demo=True)
    assert asyncio.run(quorum.drive(run, live=False, timeout=10))
    report = json.loads((run / "report.json").read_text())
    assert report["complete"] and report["mode"] == "fixture"


def test_fixture_cannot_create_beads_tasks(tmp_path: Path) -> None:
    with pytest.raises(QuorumError, match="live_review_required"):
        tasks.promote(coordinator(tmp_path), "hipaa-fhir-mcp", "F1")


def test_explicit_promotion_is_idempotent_and_filters_private_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = coordinator(tmp_path / "runs")
    for stage in STAGES:
        asyncio.run(instance.step("hipaa-fhir-mcp", stage))
    # A unit test of promotion with fake beads, not live provider evidence.
    instance.live = True
    instance.manifest["mode"] = "live"
    monkeypatch.setattr(tasks, "ROOT", tmp_path / "root")
    (tmp_path / "hipaa-fhir-mcp/.beads").mkdir(parents=True)
    issues: list[dict[str, Any]] = [{"id": "private-1", "labels": ["personal"], "owner": "private"}]
    creates = []

    def fake_bead(root: Path, *args: str) -> str:
        if args[0] == "export":
            assert args[1:] == ("--no-memories", "--quiet")
            return "\n".join(json.dumps(i) for i in issues)
        assert args[0] == "create"
        creates.append(args)
        issues.append(
            {
                "id": "fhir-test",
                "owner": "private",
                "created_by": "private",
                "assignee": "private",
                "dependencies": [{"id": "fhir-dependency", "created_by": "private"}],
                "external_ref": args[args.index("--external-ref") + 1],
            }
        )
        return "fhir-test\n"

    monkeypatch.setattr(tasks, "bead", fake_bead)
    assert tasks.promote(instance, "hipaa-fhir-mcp", "F1") == "fhir-test"
    assert tasks.promote(instance, "hipaa-fhir-mcp", "F1") == "fhir-test"
    assert len(creates) == 1
    exported = (tmp_path / "hipaa-fhir-mcp/.beads/issues.jsonl").read_text()
    assert "private" not in exported and "owner" not in exported


def test_incomplete_proposal_cannot_create_beads_task(tmp_path: Path) -> None:
    instance = coordinator(tmp_path)
    asyncio.run(instance.step("hipaa-fhir-mcp", "research"))
    instance.live = True
    instance.manifest["mode"] = "live"
    with pytest.raises(QuorumError, match="proposal_not_ready"):
        tasks.promote(instance, "hipaa-fhir-mcp", "F1")


def test_roadmap_checks_the_target_projects_private_terms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".beads").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/denylist.txt").write_text("synthetic-private-term\n")
    monkeypatch.setattr(
        tasks, "bead", lambda *args: json.dumps({"id": "test", "notes": "synthetic-private-term"})
    )
    with pytest.raises(QuorumError, match="private_export_refused"):
        tasks.export_public(tmp_path)
    assert not (tmp_path / ".beads/issues.jsonl").exists()
