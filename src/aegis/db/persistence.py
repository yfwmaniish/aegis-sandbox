"""Mapping helpers: static engine output → ORM rows, and audit-log chaining.

Keeping this conversion in one place means the worker task stays a thin orchestration
shell and the persistence rules (risk scoring, evidence fan-out, audit hashing) are
unit-testable on their own.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.state import StateTransition
from aegis.db.models import Analysis, AuditLog, Finding, IOCRow, StaticReportRow
from aegis.static.models import StaticReport

_SEVERITY_WEIGHT = {"low": 1.0, "medium": 3.0, "high": 6.0, "critical": 10.0}


def compute_risk_score(report: StaticReport) -> float:
    """Aggregate indicators into a 0–100 risk score.

    Weighted sum of ``severity_weight * confidence`` squashed through saturation so a
    handful of high-severity hits dominates, but no single finding pins the score to
    100. Deterministic and explainable (each indicator is persisted alongside)."""
    raw = sum(
        _SEVERITY_WEIGHT.get(i.severity.value, 1.0) * i.confidence for i in report.indicators
    )
    # Saturating curve: 0 -> 0, ~15 weighted points -> ~75, asymptotic to 100.
    score = 100.0 * (1.0 - 1.0 / (1.0 + raw / 8.0))
    return round(score, 1)


def persist_static_report(session: Session, analysis: Analysis, report: StaticReport) -> float:
    """Write the static report blob, findings and IOCs for ``analysis``; returns the
    computed risk score (also set on the analysis row)."""
    session.add(StaticReportRow(
        analysis_id=analysis.id,
        schema_version=report.schema_version,
        file_type=report.file_type.value,
        overall_entropy=report.entropy.overall,
        packing_likelihood=report.entropy.packing_likelihood,
        report=json.loads(report.model_dump_json()),
    ))

    for ind in report.indicators:
        session.add(Finding(
            analysis_id=analysis.id,
            detector=f"static.{report.file_type.value}",
            detector_version=report.schema_version,
            type=ind.id,
            title=ind.title,
            severity=ind.severity.value,
            confidence=ind.confidence,
            observed_facts=ind.observed_facts,
            inference=ind.inference,
            evidence_refs=ind.evidence,
        ))

    for ioc in report.iocs:
        session.add(IOCRow(
            analysis_id=analysis.id,
            type=ioc.type,
            value=ioc.value[:2048],
            confidence=ioc.confidence,
            source=ioc.source,
        ))

    score = compute_risk_score(report)
    analysis.risk_score = score
    return score


def _hash_entry(prev_hash: str | None, payload: dict) -> str:
    blob = (prev_hash or "") + json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def append_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    analysis_id=None,
    from_state: str | None = None,
    to_state: str | None = None,
    detail: dict | None = None,
) -> AuditLog:
    """Append a hash-chained audit entry (tamper-evident, FR-14.3)."""
    last = session.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = last.entry_hash if last else None

    payload = {
        "actor": actor,
        "action": action,
        "analysis_id": str(analysis_id) if analysis_id else None,
        "from_state": from_state,
        "to_state": to_state,
        "detail": detail or {},
    }
    entry = AuditLog(
        analysis_id=analysis_id,
        actor=actor,
        action=action,
        from_state=from_state,
        to_state=to_state,
        detail=detail,
        prev_hash=prev_hash,
        entry_hash=_hash_entry(prev_hash, payload),
    )
    session.add(entry)
    return entry


def record_transition(session: Session, transition: StateTransition) -> AuditLog:
    """Persist a state-machine transition as an audit entry (SR-2)."""
    return append_audit(
        session,
        actor=transition.actor,
        action="state_transition",
        # The state machine carries the id as a string; the column wants a UUID.
        analysis_id=uuid.UUID(transition.analysis_id),
        from_state=transition.from_state.value,
        to_state=transition.to_state.value,
        detail={"reason": transition.reason},
    )
