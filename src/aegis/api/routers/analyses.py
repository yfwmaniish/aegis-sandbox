"""Analysis lifecycle + results endpoints (TRD §7.1)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.deps import get_current_user, get_db
from aegis.api.schemas import (
    AnalysisCreate,
    AnalysisOut,
    FindingOut,
    FindingsPage,
    IOCOut,
    IOCsPage,
    TimelineEntry,
    TimelinePage,
)
from aegis.db.models import (
    AIUnderstandingRow,
    Analysis,
    AuditLog,
    DynamicReportRow,
    Finding,
    IOCRow,
    Sample,
    StaticReportRow,
    User,
)
from aegis.db.persistence import append_audit
from aegis.worker.tasks import enqueue_static_analysis

router = APIRouter(prefix="/v1/analyses", tags=["analyses"])


def _get_analysis_or_404(db: Session, analysis_id: uuid.UUID) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="analysis not found")
    return analysis


@router.post("", response_model=AnalysisOut, status_code=status.HTTP_201_CREATED)
def create_analysis(
    payload: AnalysisCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create an analysis for a sample and dispatch it (FR-3)."""
    sample = db.get(Sample, payload.sample_id)
    if sample is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="sample not found")

    analysis = Analysis(sample_id=sample.id, profile=payload.profile.value)
    db.add(analysis)
    db.flush()
    append_audit(db, actor=user.username, action="analysis_created",
                 analysis_id=analysis.id, detail={"profile": payload.profile.value})
    db.commit()
    db.refresh(analysis)

    # Inline mode runs synchronously here; dispatch mode hands off to Celery.
    enqueue_static_analysis(str(analysis.id))

    db.refresh(analysis)
    return analysis


@router.get("/{analysis_id}", response_model=AnalysisOut)
def get_analysis(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return _get_analysis_or_404(db, analysis_id)


@router.get("/{analysis_id}/findings", response_model=FindingsPage)
def get_findings(
    analysis_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _get_analysis_or_404(db, analysis_id)
    base = select(Finding).where(Finding.analysis_id == analysis_id)
    if severity:
        base = base.where(Finding.severity == severity)
    total = db.execute(
        select(func.count()).select_from(base.subquery())
    ).scalar_one()
    rows = db.execute(
        base.order_by(Finding.severity, Finding.confidence.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return FindingsPage(
        total=total, limit=limit, offset=offset,
        items=[FindingOut.model_validate(r) for r in rows],
    )


@router.get("/{analysis_id}/iocs", response_model=IOCsPage)
def get_iocs(
    analysis_id: uuid.UUID,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    type: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _get_analysis_or_404(db, analysis_id)
    base = select(IOCRow).where(IOCRow.analysis_id == analysis_id)
    if type:
        base = base.where(IOCRow.type == type)
    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
    rows = db.execute(
        base.order_by(IOCRow.confidence.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return IOCsPage(
        total=total, limit=limit, offset=offset,
        items=[IOCOut.model_validate(r) for r in rows],
    )


@router.get("/{analysis_id}/report")
def get_report(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the full versioned static report blob (evidence-traceable, NFR-17)."""
    _get_analysis_or_404(db, analysis_id)
    row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="report not available yet (analysis not completed)",
        )
    return row.report


@router.get("/{analysis_id}/dynamic")
def get_dynamic_report(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the dynamic (detonation) report: normalized event stream, behaviour
    roll-ups and runtime findings. 409 until a detonation run has completed."""
    _get_analysis_or_404(db, analysis_id)
    row = db.execute(
        select(DynamicReportRow).where(DynamicReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no dynamic report (analysis was static-only or has not detonated)",
        )
    return row.report


@router.post("/{analysis_id}/understanding", status_code=status.HTTP_201_CREATED)
def generate_understanding(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate (and store) a Claude-written understanding of the analysis: what the
    sample is, its behaviour workflow, ATT&CK mapping, risk, and defensive actions.
    Requires ANTHROPIC_API_KEY; human-review-required (FR-13 / TR-REP-03)."""
    _get_analysis_or_404(db, analysis_id)
    static_row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if static_row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="analysis has no report yet (not completed)",
        )
    dyn_row = db.execute(
        select(DynamicReportRow).where(DynamicReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()

    from aegis.ai import generate_understanding as _generate

    result = _generate(static_row.report, dyn_row.report if dyn_row else None)
    if not result.available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=result.reason or "AI understanding unavailable",
        )

    payload = result.understanding.model_dump(mode="json")
    existing = db.execute(
        select(AIUnderstandingRow).where(AIUnderstandingRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if existing is not None:
        existing.understanding = payload
        existing.model = result.model
        existing.prompt_version = result.prompt_version
        existing.generated_by = user.username
    else:
        db.add(AIUnderstandingRow(
            analysis_id=analysis_id, model=result.model,
            prompt_version=result.prompt_version, review_required=result.review_required,
            generated_by=user.username, understanding=payload,
        ))
    append_audit(db, actor=user.username, action="ai_understanding_generated",
                 analysis_id=analysis_id, detail={"model": result.model})
    db.commit()
    return {
        "model": result.model, "prompt_version": result.prompt_version,
        "review_required": result.review_required, "understanding": payload,
    }


@router.get("/{analysis_id}/understanding")
def get_understanding(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the stored AI understanding (409 if none generated yet)."""
    _get_analysis_or_404(db, analysis_id)
    row = db.execute(
        select(AIUnderstandingRow).where(AIUnderstandingRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no AI understanding generated yet (POST to generate)",
        )
    return {
        "model": row.model, "prompt_version": row.prompt_version,
        "review_required": row.review_required, "generated_at": row.created_at,
        "understanding": row.understanding,
    }


@router.get("/{analysis_id}/timeline", response_model=TimelinePage)
def get_timeline(
    analysis_id: uuid.UUID,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Lifecycle + audit timeline for the analysis (state transitions, SR-2)."""
    _get_analysis_or_404(db, analysis_id)
    base = select(AuditLog).where(AuditLog.analysis_id == analysis_id)
    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
    rows = db.execute(
        base.order_by(AuditLog.created_at).limit(limit).offset(offset)
    ).scalars().all()
    return TimelinePage(
        total=total, limit=limit, offset=offset,
        items=[TimelineEntry.model_validate(r) for r in rows],
    )


@router.get("/{analysis_id}/similar", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def get_similar(analysis_id: uuid.UUID, user: User = Depends(get_current_user)):
    """Similarity search (FR-11) — implemented in the intel phase (embeddings/Qdrant)."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="similarity search not implemented in the static-analysis phase",
    )


@router.get("/{analysis_id}/rules", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def get_rules(analysis_id: uuid.UUID, user: User = Depends(get_current_user)):
    """YARA/Sigma rule suggestions (FR-12) — implemented in the intel phase."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="rule suggestion not implemented in the static-analysis phase",
    )
