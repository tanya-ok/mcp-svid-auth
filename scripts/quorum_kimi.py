"""Optional bounded Moonshot peer review of an existing completed quorum run."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
from pydantic import ValidationError

from scripts.quorum import render, resolve_run
from scripts.quorum_core import Coordinator, privacy, prompt_for, write_json
from scripts.quorum_models import PROJECTS, QuorumError, Review, digest, validate_review

ENDPOINT = "https://api.moonshot.ai/v1/chat/completions"
MAX_PROMPT = 300_000
MAX_RESPONSE = 250_000
MAX_TOKENS = 8192
MODEL = "kimi-k2.6"


class InvalidPeerResponseError(QuorumError):
    """Safe validation categories and usage, never response text or credentials."""

    def __init__(self, usage: dict[str, int], categories: list[str]) -> None:
        super().__init__("kimi_schema_invalid")
        self.usage = usage
        self.categories = categories


async def request_review(prompt: str, key: str) -> tuple[Review, dict[str, int]]:
    """Exactly one request, no retries, redirects, tools or environment proxies."""
    if not key:
        raise QuorumError("moonshot_key_missing")
    if len(prompt.encode()) > MAX_PROMPT:
        raise QuorumError("kimi_prompt_too_large")
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        "max_tokens": MAX_TOKENS,
        "thinking": {"type": "disabled"},
    }
    try:
        async with asyncio.timeout(180):
            async with (
                httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=180) as client,
                client.stream(
                    "POST", ENDPOINT, headers={"Authorization": "Bearer " + key}, json=payload
                ) as response,
            ):
                if response.status_code != 200:
                    raise QuorumError("moonshot_request_refused")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE:
                        raise QuorumError("kimi_response_too_large")
        envelope = json.loads(data)
        choice = envelope["choices"][0]
        if choice["finish_reason"] != "stop":
            raise QuorumError("kimi_incomplete_output")
        usage = {
            k: v
            for k, v in envelope.get("usage", {}).items()
            if k in {"prompt_tokens", "completion_tokens", "total_tokens"}
            and type(v) is int
            and v >= 0
        }
        try:
            review = Review.model_validate_json(choice["message"]["content"])
        except ValidationError as exc:
            allowed = {"string_too_long", "too_long", "missing", "extra_forbidden", "json_invalid"}
            categories = sorted(
                {e["type"] if e["type"] in allowed else "schema_mismatch" for e in exc.errors()}
            )
            raise InvalidPeerResponseError(usage, categories) from None
        return review, usage
    except (httpx2.HTTPError, TimeoutError):
        raise QuorumError("moonshot_transport_failed") from None
    except (ValueError, TypeError, KeyError, IndexError):
        raise QuorumError("invalid_kimi_result") from None


async def review_run(coordinator: Coordinator, project: str) -> dict[str, Any]:
    if not coordinator.live or coordinator.manifest["mode"] != "live":
        raise QuorumError("live_opt_in_required")
    packet = coordinator.packet(project)
    lock = coordinator.run / ".active"
    try:
        lock.mkdir()
    except FileExistsError:
        raise QuorumError("run_busy") from None
    try:
        report = coordinator.report()
        row = next(p for p in report["projects"] if p["project"] == project)
        if not row.get("base_complete", row["complete"]):
            raise QuorumError("previous_stage_required")
        target = coordinator.run / project / "kimi.json"
        if target.exists():
            return {"status": "already_complete"}
        prompt = (
            "You are Kimi, an additional independent peer. Assess each original finding "
            "against the code and the disagreements. Do not decide by majority. "
            "Return findings=[] and one vote per original finding. No tools or web access "
            "are available. Do not claim to run tests. Keep the answer concise.\n"
            "Output a JSON OBJECT INSTANCE, not the schema. Use exactly these top-level "
            "keys: summary (under 1200 characters), findings (empty array), votes "
            "(one object per finding), limitations (array of short strings). "
            "Each vote has finding_id, verdict (support/dispute/needs_test), reason "
            "(under 1000 characters) and evidence (1-3 objects with path,line,quote). "
            "Quotes must be exact and under 300 characters each.\n"
            + prompt_for(packet, "verify", row["reviews"])
            + "\nRequired JSON schema:\n"
            + json.dumps(Review.model_json_schema())
        )
        privacy(prompt)
        key = os.environ.get("MOONSHOT_API_KEY") or os.environ.get("KIMI_API_KEY", "")
        try:
            review, usage = await request_review(prompt, key)
        except InvalidPeerResponseError as exc:
            write_json(
                coordinator.run / project / "kimi-failure.json",
                {
                    "time": datetime.now(UTC).isoformat(),
                    "code": "kimi_schema_invalid",
                    "categories": exc.categories,
                    "usage": exc.usage,
                },
            )
            raise
        validate_review(review, packet, "verify", {f["id"] for f in row["findings"]})
        privacy(review.model_dump_json())
        record = {
            "provider": "moonshot",
            "model": MODEL,
            "time": datetime.now(UTC).isoformat(),
            "prompt_sha256": digest(prompt),
            "implementation_sha256": digest(Path(__file__).read_text()),
            "max_tokens": MAX_TOKENS,
            "usage": usage,
            "review": review.model_dump(),
        }
        write_json(target, record)
        return {"status": "complete", "usage": usage}
    finally:
        lock.rmdir()


async def review_selected(coordinator: Coordinator, project: str = "all") -> dict[str, Any]:
    """Visit every selected project once; one failure never hides the others."""
    projects = list(coordinator.manifest["packets"]) if project == "all" else [project]
    results = {}
    for name in projects:
        try:
            results[name] = await review_run(coordinator, name)
        except QuorumError as exc:
            results[name] = {"status": "incomplete", "code": str(exc)}
        render(coordinator.run, coordinator.report())
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--project", choices=["all", *PROJECTS], default="all")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    try:
        coordinator = Coordinator(resolve_run(args.run), live=args.live)
        result = asyncio.run(review_selected(coordinator, args.project))
        render(coordinator.run, coordinator.report())
        print(json.dumps(result))
        return (
            0
            if all(v["status"] in {"complete", "already_complete"} for v in result.values())
            else 1
        )
    except (QuorumError, ValueError, OSError):
        print("Kimi review incomplete. Check key availability, API access and input limits.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
