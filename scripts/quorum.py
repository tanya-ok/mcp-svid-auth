"""Local MCP review orchestration and an inspectable development record."""

from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver import MCPServer

from scripts.quorum_core import ROOT, RUNS, Coordinator, new_run, privacy, write_json
from scripts.quorum_models import PROJECTS, STAGES, QuorumError
from scripts.quorum_tasks import promote


def server(coordinator: Coordinator) -> MCPServer:
    app = MCPServer("portfolio-quorum", version="0.1.0", log_level="ERROR")

    @app.tool()
    async def review_step(project: str, stage: str) -> dict[str, str]:
        """Run the next bounded review stage; arbitrary prompts and commands are not accepted."""
        try:
            return await coordinator.step(project, stage)
        except QuorumError as exc:
            return {"status": "failed", "code": str(exc)}
        except (ValueError, OSError):
            return {"status": "failed", "code": "invalid_local_state"}

    @app.tool()
    def review_status() -> dict[str, Any]:
        """Read proposals, disagreement and provenance. Never mutate code or task databases."""
        return coordinator.report()

    return app


def resolve_run(name: str) -> Path:
    if not name or Path(name).name != name or name in {".", ".."}:
        raise QuorumError("invalid_run_id")
    run = RUNS / name
    if run.is_symlink() or not run.is_dir():
        raise QuorumError("run_not_found")
    return run


def finding_card(finding: dict[str, Any], reviews: dict[str, Any]) -> str:
    content = (
        "<article><h3>"
        + html.escape(finding["title"])
        + "</h3><p class=tag>"
        + html.escape(finding["status"].replace("_", " "))
        + "</p>"
    )
    for stage, label in (
        ("verify", "Codex challenge"),
        ("rebuttal", "Claude response"),
        ("kimi", "Kimi independent peer"),
    ):
        vote = next(
            (
                v
                for v in reviews.get(stage, {}).get("votes", [])
                if v["finding_id"] == finding["id"]
            ),
            None,
        )
        if vote:
            content += (
                "<details><summary>"
                + label
                + ": "
                + html.escape(vote["verdict"].replace("_", " "))
                + "</summary><p>"
                + html.escape(vote["reason"])
                + "</p></details>"
            )
    content += (
        "<details><summary>Research claim and proposal</summary><p>"
        + html.escape(finding["claim"])
        + "</p><p>"
        + html.escape(finding["improvement"])
        + "</p></details></article>"
    )
    return content


def render(run: Path, report: dict[str, Any]) -> None:
    privacy(json.dumps(report, ensure_ascii=False))
    write_json(run / "report.json", report)
    mode = report["mode"]
    rows = [
        "# Portfolio review",
        "",
        f"Mode: {mode}. Complete: {report['complete']}.",
        "",
        report["notice"],
        "",
    ]
    cards = []
    for project in report["projects"]:
        name = project["project"]
        rows.extend(
            [
                f"## {name}",
                "",
                f"Revision: {project['revision']}. "
                f"Dirty: {project['dirty']}. Files: {project['included_files']}.",
                "",
            ]
        )
        entries = []
        phases_to_show = list(STAGES)
        if "kimi" in project.get("required_peers", []) or "kimi" in project["reviews"]:
            phases_to_show.append("kimi")
        phases = (
            "<p class=tag>"
            + " / ".join(
                html.escape(
                    stage + ": " + ("complete" if stage in project["reviews"] else "pending")
                )
                for stage in phases_to_show
            )
            + "</p>"
        )
        last = project.get("last_event")
        if last:
            phases += (
                "<p>Latest event: " + html.escape(last["stage"] + " / " + last["outcome"]) + "</p>"
            )
        for finding in project["findings"]:
            rows.extend(
                [
                    f"### {finding['id']}: {finding['title']}",
                    "",
                    f"P{finding['priority']} / {finding['status']}",
                    "",
                    finding["claim"],
                    "",
                    "Proposal: " + finding["improvement"],
                    "",
                    "Acceptance: " + finding["acceptance"],
                    "",
                ]
            )
            for evidence in finding["evidence"]:
                rows.append(f"- `{evidence['path']}:{evidence['line']}`: {evidence['quote']}")
            entries.append(finding_card(finding, project["reviews"]))
        for stage, review in project["reviews"].items():
            rows.extend(["", f"### {stage}", "", review["summary"], ""])
            for vote in review["votes"]:
                rows.append(f"- {vote['finding_id']}: {vote['verdict']}. {vote['reason']}")
            rows.extend(["", "Limitations:", "", *["- " + x for x in review["limitations"]]])
        if project["omitted"]:
            rows.extend(["", "Omitted files:", "", *["- " + p for p in project["omitted"]]])
        cards.append(
            "<section><h2>"
            + ("Synthetic input: " if mode != "live" else "")
            + html.escape(name)
            + "</h2><p>"
            + ("Review complete" if project["complete"] else "Review incomplete")
            + " · "
            + str(project["included_files"])
            + " source files; "
            + str(len(project["omitted"]))
            + " omitted</p>"
            + phases
            + ("".join(entries) or "<p>No findings available yet.</p>")
            + "</section>"
        )
    text = "\n".join(rows) + "\n"
    privacy(text)
    (run / "report.md").write_text(text)
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Portfolio review</title><style>
body{margin:0;background:#f6f4ee;color:#28302c;font:17px/1.6 system-ui,sans-serif}
main{max-width:960px;margin:auto;padding:clamp(20px,5vw,64px)}
h1{font-size:clamp(32px,6vw,52px);line-height:1.1}h2{font-size:25px}
section{margin:32px 0;padding:24px;background:white;border:1px solid #d8ddd5;border-radius:16px}
article{border-top:1px solid #ddd;padding-top:16px;overflow-wrap:anywhere}
.tag{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:#59624c}
a{color:#425c45}p{max-width:78ch}footer{font-size:14px}
details{margin:14px 0}summary{cursor:pointer;font-weight:600}
</style><main><p class="tag">Development evidence / local review</p>
<h1>Independent perspectives.<br>Traceable decisions.</h1>"""
    page += "<p><strong>" + html.escape(mode.upper()) + "</strong> / "
    page += "Complete" if report["complete"] else "Incomplete"
    page += "</p><p>Consensus is a proposal. Source citations are checked mechanically; "
    page += "behavior, research links and acceptance tests still need independent verification.</p>"
    page += "<p class=tag>Claude research &gt; Codex challenge &gt; "
    page += "Claude rebuttal &gt; Kimi peer (when required) &gt; Human selection</p>"
    if mode != "live":
        page += "<p><strong>Synthetic demonstration. No model reviewed these projects.</strong></p>"
    page += "".join(cards)
    page += "<footer>Full evidence, votes and coverage: <a href=report.md>review record</a> / "
    page += "<a href=report.json>structured report</a>. No task is created automatically."
    page += "</footer></main></html>"
    (run / "index.html").write_text(page)


async def drive(run: Path, *, live: bool, timeout: float) -> bool:
    args = ["-m", "scripts.quorum", "serve", "--run", run.name, "--timeout", str(timeout)]
    if live:
        args.append("--live")
    params = StdioServerParameters(
        command=sys.executable, args=args, cwd=str(ROOT), env=os.environ.copy()
    )
    coordinator = Coordinator(run, live=live, timeout=timeout)
    all_complete = True
    async with stdio_client(params) as streams, ClientSession(*streams) as session:
        await session.initialize()
        available = await session.list_tools()
        if {t.name for t in available.tools} != {"review_step", "review_status"}:
            raise QuorumError("unexpected_mcp_tools")
        for project in coordinator.manifest["packets"]:
            for stage in STAGES:
                print(f"{project}: {stage}", flush=True)
                result = await session.call_tool(
                    "review_step",
                    {"project": project, "stage": stage},
                    read_timeout_seconds=timeout + 30,
                )
                if not isinstance(result, types.CallToolResult) or result.is_error:
                    raise QuorumError("mcp_step_failed")
                payload = result.structured_content
                if payload is None or payload.get("status") == "failed":
                    print("Stage incomplete; see the safe event record.", flush=True)
                    render(run, coordinator.report())
                    all_complete = False
                    break
            else:
                if "kimi" in coordinator.manifest.get("required_peers", []):
                    from scripts import quorum_kimi  # noqa: PLC0415 - lazy peer adapter

                    peer = await quorum_kimi.review_selected(coordinator, project)
                    if peer[project]["status"] not in {"complete", "already_complete"}:
                        all_complete = False
            render(run, coordinator.report())
    return all_complete and bool(coordinator.report()["complete"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["prepare", "demo", "smoke", "run", "serve", "report", "accept"]
    )
    parser.add_argument("--project", choices=["all", *PROJECTS], default="all")
    parser.add_argument("--run")
    parser.add_argument("--finding", help="Explicitly selected proposal ID, used only by accept")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Permit sending prepared source packets to installed model providers",
    )
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout <= 900:
            raise QuorumError("invalid_timeout")
        if args.command in {"prepare", "demo", "smoke"}:
            if args.command == "smoke" and not args.live:
                raise QuorumError("live_opt_in_required")
            projects = list(PROJECTS) if args.project == "all" else [args.project]
            if args.command == "smoke":
                projects = [PROJECTS[0]]
            run = new_run(
                projects, demo=args.command != "prepare", provider_smoke=args.command == "smoke"
            )
            print("Run: " + run.name)
            if args.command == "prepare":
                render(run, Coordinator(run, live=True).report())
                print("Prepared locally. No model has been called.")
                return 0
        else:
            run = resolve_run(args.run or "")
        if args.command == "serve":
            server(Coordinator(run, live=args.live, timeout=args.timeout)).run()
            return 0
        if args.command == "accept":
            print(promote(Coordinator(run, live=args.live), args.project, args.finding or ""))
            return 0
        if args.command == "report":
            render(run, Coordinator(run, live=args.live).report())
            return 0
        complete = asyncio.run(drive(run, live=args.live, timeout=args.timeout))
        print("Report: " + str(run / "index.html"))
        return 0 if complete else 1
    except (QuorumError, ValueError, OSError):
        print(
            "Review refused or incomplete; check inputs, login and local run events.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Review interrupted; completed stages are retained.", file=sys.stderr)
        raise SystemExit(130) from None


if __name__ == "__main__":
    raise SystemExit(main())
