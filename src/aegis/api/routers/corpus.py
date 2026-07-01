"""Corpus-level endpoints: the catch-rate scoreboard over all analyzed samples."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.deps import get_current_user, get_db
from aegis.core.enums import AnalysisState
from aegis.db.models import Analysis, Sample, StaticReportRow, User

router = APIRouter(prefix="/v1/corpus", tags=["corpus"])


@router.get("/scoreboard")
def get_scoreboard(
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Aggregate every completed analysis into a catch-rate scoreboard: flagged vs.
    clean, risk distribution, file-type and capability breakdowns, and the most common
    behaviour drivers. Dedupes by sample (keeps the latest analysis per sample)."""
    from aegis.corpus import build_scoreboard, row_from_report

    rows = db.execute(
        select(StaticReportRow, Analysis, Sample)
        .join(Analysis, Analysis.id == StaticReportRow.analysis_id)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(Analysis.state == AnalysisState.COMPLETED.value)
        .order_by(StaticReportRow.created_at.desc())
        .limit(limit)
    ).all()

    seen: set[str] = set()
    scan_rows = []
    for sr, analysis, sample in rows:
        if sample.sha256 in seen:  # one row per sample (latest wins, desc order)
            continue
        seen.add(sample.sha256)
        scan_rows.append(row_from_report(
            sr.report, sha256=sample.sha256, filename=sample.original_filename,
            risk=analysis.risk_score, analysis_id=str(analysis.id),
        ))

    return build_scoreboard(scan_rows).model_dump(mode="json")
