"""Bounded review contracts; provider output is data, never an instruction."""

from __future__ import annotations

import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROJECTS = (
    "mcp-svid-auth",
    "hipaa-fhir-mcp",
    "mcp-spiffe-bridge",
    "ecs-contract",
    "it-grc",
    "engineering-os",
)
STAGES = ("research", "verify", "rebuttal")


class Contract(BaseModel):
    """Reject coercion and undeclared fields at every persisted boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class Source(Contract):
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    text: str = Field(max_length=60_000)


class Packet(Contract):
    project: str
    revision: str
    dirty: bool
    sources: list[Source] = Field(min_length=1, max_length=100)
    omitted: list[str]


class Evidence(Contract):
    path: str = Field(min_length=1, max_length=240)
    line: int = Field(ge=1)
    quote: str = Field(min_length=1, max_length=500)


class Finding(Contract):
    id: str = Field(pattern=r"^F[1-5]$")
    title: str = Field(min_length=1, max_length=160)
    priority: int = Field(ge=0, le=4)
    claim: str = Field(min_length=1, max_length=1600)
    evidence: list[Evidence] = Field(min_length=1, max_length=5)
    sources: list[str] = Field(max_length=6)
    improvement: str = Field(min_length=1, max_length=1600)
    acceptance: str = Field(min_length=1, max_length=1600)


class Vote(Contract):
    finding_id: str = Field(pattern=r"^F[1-5]$")
    verdict: Literal["support", "dispute", "needs_test"]
    reason: str = Field(min_length=1, max_length=1600)
    evidence: list[Evidence] = Field(min_length=1, max_length=5)


class Review(Contract):
    summary: str = Field(min_length=1, max_length=2400)
    findings: list[Finding] = Field(max_length=5)
    votes: list[Vote] = Field(max_length=5)
    limitations: list[str] = Field(min_length=1, max_length=12)


class QuorumError(Exception):
    """Only fixed, safe error codes are exposed to a client."""


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_evidence(evidence: Evidence, packet: Packet) -> None:
    source = next((s for s in packet.sources if s.path == evidence.path), None)
    if source is None:
        raise QuorumError("unknown_evidence_file")
    lines = source.text.splitlines()
    if evidence.line > len(lines) or evidence.quote not in lines[evidence.line - 1]:
        raise QuorumError("evidence_quote_mismatch")


def validate_review(review: Review, packet: Packet, stage: str, ids: set[str]) -> None:
    if stage == "research":
        if review.votes or len({f.id for f in review.findings}) != len(review.findings):
            raise QuorumError("invalid_research_contract")
    elif (
        review.findings
        or {v.finding_id for v in review.votes} != ids
        or len(review.votes) != len(ids)
    ):
        raise QuorumError("incomplete_review_votes")
    for finding in review.findings:
        for url in finding.sources:
            if not re.fullmatch(r"https://[^\s<>]+", url):
                raise QuorumError("invalid_source_url")
        for evidence in finding.evidence:
            check_evidence(evidence, packet)
    for vote in review.votes:
        for evidence in vote.evidence:
            check_evidence(evidence, packet)
