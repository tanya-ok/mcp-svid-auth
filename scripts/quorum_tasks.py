"""Explicitly promote one reviewed proposal to a local beads investigation task."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from scripts.quorum_core import ROOT, Coordinator, privacy
from scripts.quorum_models import PROJECTS, QuorumError, digest


def bead(root: Path, *args: str) -> str:
    executable = shutil.which("bd")
    if executable is None:
        raise QuorumError("beads_unavailable")
    result = subprocess.run(  # noqa: S603 - fixed executable, argument list, no shell
        [executable, "--sandbox", *args],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise QuorumError("beads_operation_failed")
    return result.stdout


def promote(coordinator: Coordinator, project: str, finding_id: str) -> str:
    lock = coordinator.run / ".active"
    try:
        lock.mkdir()
    except FileExistsError:
        raise QuorumError("run_busy") from None
    try:
        return _promote(coordinator, project, finding_id)
    finally:
        lock.rmdir()


def _promote(coordinator: Coordinator, project: str, finding_id: str) -> str:
    if not coordinator.live or coordinator.manifest["mode"] != "live" or project not in PROJECTS:
        raise QuorumError("live_review_required")
    report = coordinator.report()
    entry = next((p for p in report["projects"] if p["project"] == project), None)
    if entry is None:
        raise QuorumError("unknown_project")
    finding = next((f for f in entry["findings"] if f["id"] == finding_id), None)
    if not entry["complete"] or finding is None or finding["status"] != "consensus_proposal":
        raise QuorumError("proposal_not_ready")
    packet_hash = coordinator.manifest["packets"][project]
    reference = "quorum:" + digest(packet_hash + json.dumps(finding, sort_keys=True))[:24]
    root = ROOT.parent / project
    existing: list[dict[str, Any]] = [
        json.loads(line) for line in bead(root, "export", "--no-memories", "--quiet").splitlines()
    ]
    duplicate = next((item for item in existing if item.get("external_ref") == reference), None)
    if duplicate is not None:
        export_public(root)
        return str(duplicate["id"])
    body = (
        "Explicitly selected review proposal, not a verified defect.\n"
        + "Source revision: "
        + entry["revision"]
        + "\n"
        + "Snapshot: "
        + packet_hash
        + "\n"
        + "Local run: "
        + coordinator.run.name
        + "\n\n"
        + finding["claim"]
        + "\n\nProposed work: "
        + finding["improvement"]
        + "\n\nEvidence:\n"
        + "\n".join(f"{e['path']}:{e['line']}: {e['quote']}" for e in finding["evidence"])
    )
    privacy(body)
    issue = bead(
        root,
        "create",
        "Investigate: " + finding["title"],
        "--type",
        "task",
        "--priority",
        str(finding["priority"]),
        "--description",
        body,
        "--acceptance",
        "Reproduce independently before implementation. " + finding["acceptance"],
        "--labels",
        "quorum,review-proposal",
        "--external-ref",
        reference,
        "--silent",
    ).strip()
    coordinator.event(project, "promote", "local_task_created")
    export_public(root)
    return issue


def export_public(root: Path) -> None:
    items = []
    for line in bead(root, "export", "--no-memories", "--quiet").splitlines():
        item = json.loads(line)
        if "personal" in (item.get("labels") or []):
            continue
        items.append(_strip_actors(item))
    output = "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in items)
    privacy(output)
    denylist = root / "tests/denylist.txt"
    if denylist.exists():
        terms = [
            line.strip().casefold()
            for line in denylist.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if any(term in output.casefold() for term in terms):
            raise QuorumError("private_export_refused")
    if "@" in output:
        raise QuorumError("private_export_refused")
    temporary = root / ".beads/issues.quorum.tmp"
    temporary.write_text(output)
    temporary.replace(root / ".beads/issues.jsonl")


def _strip_actors(value: Any) -> Any:
    """Public task structure does not need local actor identities, even in dependencies."""
    if isinstance(value, dict):
        private_keys = {"owner", "created_by", "updated_by", "assignee", "actor", "author"}
        return {key: _strip_actors(item) for key, item in value.items() if key not in private_keys}
    if isinstance(value, list):
        return [_strip_actors(item) for item in value]
    return value
