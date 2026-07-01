"""Analysis lifecycle + results endpoints (TRD §7.1)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.deps import get_current_user, get_db
from aegis.core.enums import AnalysisProfile, AnalysisState
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

    # Detonation profiles can take minutes; in inline mode run them in a background
    # thread so the request returns immediately and the client polls the state.
    # Static-only stays synchronous (fast, and keeps the create->completed contract).
    detonates = payload.profile != AnalysisProfile.STATIC_ONLY
    enqueue_static_analysis(str(analysis.id), allow_background=detonates)

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


@router.get("/{analysis_id}/visualizations")
def get_visualizations(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Deterministic visualization bundle (capability radar, permission heatmap,
    MITRE ATT&CK matrix, behaviour graph) derived from the stored reports. Computed on
    the fly — no LLM/API key needed. 409 until the static report exists."""
    _get_analysis_or_404(db, analysis_id)
    static_row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if static_row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="report not available yet (analysis not completed)",
        )
    dyn_row = db.execute(
        select(DynamicReportRow).where(DynamicReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()

    from aegis.insights import build_visualizations

    viz = build_visualizations(static_row.report, dyn_row.report if dyn_row else None)
    return viz.model_dump(mode="json")


@router.get("/{analysis_id}/report.html", response_class=HTMLResponse)
def export_report_html(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Render a self-contained HTML analyst report (print-to-PDF friendly) bundling the
    verdict, findings, IOCs, visualizations, dynamic run, AI narrative, generated rules
    and similar samples. 409 until the static report exists."""
    analysis = _get_analysis_or_404(db, analysis_id)
    static_row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if static_row is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="report not available yet (analysis not completed)")
    dyn_row = db.execute(
        select(DynamicReportRow).where(DynamicReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    ai_row = db.execute(
        select(AIUnderstandingRow).where(AIUnderstandingRow.analysis_id == analysis_id)
    ).scalar_one_or_none()

    from aegis.insights import build_visualizations
    from aegis.intel import CorpusItem, find_similar, generate_rules
    from aegis.report import build_report_html

    dynamic = dyn_row.report if dyn_row else None
    viz = build_visualizations(static_row.report, dynamic)
    rules = generate_rules(static_row.report, sha256=analysis.sample.sha256,
                           risk=analysis.risk_score)

    rows = db.execute(
        select(StaticReportRow, Analysis, Sample)
        .join(Analysis, Analysis.id == StaticReportRow.analysis_id)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(Analysis.state == AnalysisState.COMPLETED.value)
        .order_by(StaticReportRow.created_at.desc())
        .limit(500)
    ).all()
    corpus = [
        CorpusItem(analysis_id=str(a.id), sha256=s.sha256, filename=s.original_filename,
                   file_type=s.file_type, risk_score=a.risk_score, report=sr.report)
        for sr, a, s in rows if a.id != analysis_id
    ]
    similar = find_similar(static_row.report, corpus,
                           target_sha256=analysis.sample.sha256)

    doc = build_report_html(
        static=static_row.report, viz=viz, dynamic=dynamic,
        understanding=ai_row.understanding if ai_row else None,
        rules=rules, similar=similar, sha256=analysis.sample.sha256,
        filename=analysis.sample.original_filename, risk=analysis.risk_score,
        target_os=analysis.target_os,
    )
    return HTMLResponse(content=doc)


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


@router.get("/{analysis_id}/similar")
def get_similar(
    analysis_id: uuid.UUID,
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Rank the corpus for samples similar to this one (FR-11): shared behaviour
    indicators, network endpoints, package/imphash and TLSH distance. 409 until the
    static report exists."""
    analysis = _get_analysis_or_404(db, analysis_id)
    target_static = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if target_static is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="report not available yet (analysis not completed)")
    target_sha = analysis.sample.sha256

    from aegis.intel import CorpusItem, find_similar

    rows = db.execute(
        select(StaticReportRow, Analysis, Sample)
        .join(Analysis, Analysis.id == StaticReportRow.analysis_id)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(Analysis.state == AnalysisState.COMPLETED.value)
        .order_by(StaticReportRow.created_at.desc())
        .limit(500)
    ).all()
    corpus = [
        CorpusItem(analysis_id=str(a.id), sha256=s.sha256, filename=s.original_filename,
                   file_type=s.file_type, risk_score=a.risk_score, report=sr.report)
        for sr, a, s in rows if a.id != analysis_id
    ]
    result = find_similar(target_static.report, corpus, target_sha256=target_sha, limit=limit)
    return result.model_dump(mode="json")


@router.get("/{analysis_id}/rules")
def get_rules(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate portable YARA + Sigma detection rules from this analysis (FR-12).
    Deterministic; no LLM. 409 until the static report exists."""
    analysis = _get_analysis_or_404(db, analysis_id)
    static_row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if static_row is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="report not available yet (analysis not completed)")

    from aegis.intel import generate_rules

    bundle = generate_rules(static_row.report, sha256=analysis.sample.sha256,
                            risk=analysis.risk_score)
    return bundle.model_dump(mode="json")


@router.get("/{analysis_id}/virustotal")
def get_virustotal(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Look the sample up on VirusTotal by SHA-256 (the file is never uploaded) and
    compare VT's multi-engine verdict with Aegis's. Requires VIRUSTOTAL_API_KEY; returns
    an 'unavailable' result (not an error) when unset so the UI can prompt for a key."""
    analysis = _get_analysis_or_404(db, analysis_id)
    from aegis.core.config import get_settings
    from aegis.intel.virustotal import build_comparison, lookup_virustotal

    settings = get_settings()
    n_ind = db.execute(
        select(func.count()).select_from(
            select(Finding).where(Finding.analysis_id == analysis_id).subquery()
        )
    ).scalar_one()
    vt = lookup_virustotal(analysis.sample.sha256, settings.virustotal_api_key)
    comparison = build_comparison(analysis.sample.sha256, vt,
                                  risk=analysis.risk_score, indicator_count=n_ind)
    return comparison.model_dump(mode="json")


def _export_static_or_409(db: Session, analysis_id: uuid.UUID):
    analysis = _get_analysis_or_404(db, analysis_id)
    static_row = db.execute(
        select(StaticReportRow).where(StaticReportRow.analysis_id == analysis_id)
    ).scalar_one_or_none()
    if static_row is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="report not available yet (analysis not completed)")
    return analysis, static_row


@router.get("/{analysis_id}/export/stix")
def export_stix(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export the analysis as a STIX 2.1 bundle (malware SDO, IOC + YARA indicators,
    ATT&CK attack-patterns, relationships). Deterministic ids. 409 until completed."""
    from fastapi.responses import JSONResponse

    from aegis.intel import to_stix_bundle

    analysis, static_row = _export_static_or_409(db, analysis_id)
    bundle = to_stix_bundle(static_row.report, sha256=analysis.sample.sha256,
                            filename=analysis.sample.original_filename, risk=analysis.risk_score)
    return JSONResponse(bundle, headers={
        "Content-Disposition": f'attachment; filename="aegis_{analysis.sample.sha256[:12]}_stix.json"'})


@router.get("/{analysis_id}/export/misp")
def export_misp(
    analysis_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export the analysis as a MISP event (attributes + ATT&CK galaxy tags + YARA).
    409 until completed."""
    from fastapi.responses import JSONResponse

    from aegis.intel import to_misp_event

    analysis, static_row = _export_static_or_409(db, analysis_id)
    event = to_misp_event(static_row.report, sha256=analysis.sample.sha256,
                          filename=analysis.sample.original_filename, risk=analysis.risk_score)
    return JSONResponse(event, headers={
        "Content-Disposition": f'attachment; filename="aegis_{analysis.sample.sha256[:12]}_misp.json"'})
