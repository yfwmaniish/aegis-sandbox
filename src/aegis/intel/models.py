"""Schemas for the threat-intel layer: similarity matches and generated rules."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SimilarMatch(BaseModel):
    analysis_id: str
    sample_sha256: str
    filename: str | None = None
    file_type: str = "unknown"
    score: float = Field(ge=0, le=100)
    tlsh_distance: int | None = None
    shared_indicators: list[str] = Field(default_factory=list)
    shared_hosts: list[str] = Field(default_factory=list)
    same_package: bool = False
    same_imphash: bool = False
    reasons: list[str] = Field(default_factory=list)
    risk_score: float | None = None


class SimilarResult(BaseModel):
    target_sha256: str
    corpus_size: int = 0
    count: int = 0
    matches: list[SimilarMatch] = Field(default_factory=list)
    note: str | None = None


class YaraRule(BaseModel):
    name: str
    text: str
    string_count: int = 0


class SigmaRule(BaseModel):
    title: str
    logsource: str
    yaml: str


class RuleBundle(BaseModel):
    generated_at: datetime = Field(default_factory=_utcnow)
    sample_sha256: str
    file_type: str = "unknown"
    yara: YaraRule
    sigma: SigmaRule
    attack_tags: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
