"""Schemas for the corpus catch-rate scoreboard (batch analysis roll-up)."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class LabelCount(BaseModel):
    label: str
    count: int


class RiskBucket(BaseModel):
    label: str
    min: float
    max: float
    count: int


class ScanRow(BaseModel):
    filename: str | None = None
    sha256: str = ""
    file_type: str = "unknown"
    size: int = 0
    risk_score: float = 0.0
    verdict: str = "CLEAN"
    indicator_count: int = 0
    indicator_ids: list[str] = Field(default_factory=list)
    top_capabilities: list[str] = Field(default_factory=list)
    analysis_id: str | None = None
    # VirusTotal cross-reference (populated only when a VT key is supplied).
    vt_found: bool | None = None
    vt_malicious: int | None = None
    vt_missed: bool | None = None       # VT clean/unknown but Aegis flagged it
    error: str | None = None


class Scoreboard(BaseModel):
    generated_at: datetime = Field(default_factory=_utcnow)
    total: int = 0
    flagged: int = 0                     # Aegis risk >= flag threshold
    clean: int = 0
    flagged_pct: float = 0.0
    flag_threshold: float = 25.0
    verdict_counts: list[LabelCount] = Field(default_factory=list)
    file_type_counts: list[LabelCount] = Field(default_factory=list)
    risk_histogram: list[RiskBucket] = Field(default_factory=list)
    top_capabilities: list[LabelCount] = Field(default_factory=list)
    top_indicators: list[LabelCount] = Field(default_factory=list)
    # Present only when VT cross-referencing was run.
    vt_checked: int | None = None
    vt_missed_count: int | None = None   # Aegis-caught but VT-missed (the money metric)
    rows: list[ScanRow] = Field(default_factory=list)
