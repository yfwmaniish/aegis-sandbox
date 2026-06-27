"""The static analysis pipeline — pure orchestration, no Celery coupling.

``execute_static_analysis`` is the function the Celery task wraps and that the API
calls directly in inline mode. It drives the analysis through the state machine,
fetches the sample from object storage, runs the engine, persists the report/findings/
IOCs, and records an audit transition at every step (SR-2 / NFR-7: a detector failure
moves the analysis to ``failed_processing`` rather than crashing the worker).
"""

from __future__ import annotations

import uuid

import structlog

from aegis.core.config import get_settings
from aegis.core.enums import AnalysisState
from aegis.core.state import AnalysisStateMachine, InvalidTransition
from aegis.db.base import session_scope
from aegis.db.models import Analysis
from aegis.db.persistence import persist_static_report, record_transition
from aegis.orchestrator.router import is_routable, route_environment
from aegis.static import analyze_bytes
from aegis.static.models import FileType
from aegis.storage import get_object_store

log = structlog.get_logger(__name__)


def execute_static_analysis(analysis_id: str) -> dict:
    """Run the static pipeline for one analysis. Returns a small result summary."""
    settings = get_settings()
    aid = uuid.UUID(analysis_id)

    with session_scope() as session:
        analysis = session.get(Analysis, aid)
        if analysis is None:
            raise KeyError(f"analysis {analysis_id} not found")
        sample = analysis.sample

        sm = AnalysisStateMachine(
            analysis_id, AnalysisState(analysis.state), retries=analysis.retries
        )

        def move(to: AnalysisState, *, reason: str = "", actor: str = "worker") -> None:
            t = sm.transition(to, reason=reason, actor=actor)
            analysis.state = to
            analysis.retries = sm.retries
            record_transition(session, t)

        try:
            if sm.state == AnalysisState.CREATED:
                move(AnalysisState.QUEUED, reason="picked up by worker")
            move(AnalysisState.PROCESSING, reason="static-only pipeline")

            data = get_object_store().get(settings.s3_bucket_samples, sample.sha256)
            report = analyze_bytes(
                data,
                filename=sample.original_filename,
                string_min_len=settings.static_string_min_len,
                string_max_count=settings.static_string_max_count,
            )

            # Backfill sample fields the engine now knows authoritatively.
            sample.file_type = report.file_type.value
            sample.tlsh = report.hashes.tlsh
            if report.file_type != FileType.UNKNOWN and is_routable(report.file_type):
                analysis.target_os = route_environment(report.file_type).value

            score = persist_static_report(session, analysis, report)

            move(AnalysisState.REPORTING, reason="assembling report")
            move(AnalysisState.COMPLETED, reason="static analysis complete")
            analysis.error = None
            log.info("static_analysis_completed", analysis_id=analysis_id,
                     file_type=report.file_type.value, risk_score=score,
                     findings=len(report.indicators), iocs=len(report.iocs))
            return {
                "analysis_id": analysis_id,
                "state": analysis.state,
                "file_type": report.file_type.value,
                "risk_score": score,
                "findings": len(report.indicators),
                "iocs": len(report.iocs),
            }
        except InvalidTransition:
            raise
        except Exception as exc:  # noqa: BLE001 - failure is captured, not propagated as a crash
            log.error("static_analysis_failed", analysis_id=analysis_id, error=str(exc))
            try:
                move(AnalysisState.FAILED_PROCESSING, reason=str(exc))
            except InvalidTransition:
                analysis.state = AnalysisState.FAILED_PROCESSING
            analysis.error = f"{type(exc).__name__}: {exc}"
            return {"analysis_id": analysis_id, "state": analysis.state, "error": analysis.error}
