"""ORM models — the PostgreSQL metadata schema (TRD §6.1, SRS §6).

Scope reflects the current build (static analysis + lifecycle): users/RBAC, samples,
analyses, the static report blob, generic findings, IOCs and the audit log. Each
entity has an immutable UUID primary key (DR-1) and FK referential integrity (DR-2).
Detector-specific finding tables (evasion/android/…) are represented by the single
polymorphic ``findings`` table keyed by ``detector`` + ``type``, which keeps the
schema open for the dynamic-analysis detectors without a migration per detector.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.core.enums import AnalysisState, Role, Severity, TargetOS
from aegis.db.base import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(String(32), default=Role.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Sample(Base, TimestampMixin):
    __tablename__ = "samples"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    # SHA256 is the canonical identity; unique so re-submission dedupes (FR-1.4 / TR-ING-03).
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    tlsh: Mapped[str | None] = mapped_column(String(140))
    file_type: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str | None] = mapped_column(String(128))
    submitter: Mapped[str | None] = mapped_column(String(150))
    # Pointer into object storage (quarantine bucket), never the bytes themselves.
    storage_ref: Mapped[str | None] = mapped_column(String(512))

    analyses: Mapped[list[Analysis]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )


class Analysis(Base, TimestampMixin):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    sample_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_os: Mapped[str | None] = mapped_column(String(16))
    profile: Mapped[str] = mapped_column(String(32), default="static_only", nullable=False)
    state: Mapped[AnalysisState] = mapped_column(
        String(32), default=AnalysisState.CREATED, nullable=False, index=True
    )
    risk_score: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)
    retries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    sample: Mapped[Sample] = relationship(back_populates="analyses")
    static_report: Mapped[StaticReportRow | None] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", uselist=False
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    iocs: Mapped[list[IOCRow]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class StaticReportRow(Base, TimestampMixin):
    __tablename__ = "static_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    file_type: Mapped[str] = mapped_column(String(16), nullable=False)
    overall_entropy: Mapped[float | None] = mapped_column(Float)
    packing_likelihood: Mapped[str | None] = mapped_column(String(16))
    # Full versioned StaticReport, stored verbatim for evidence traceability (NFR-17).
    report: Mapped[dict] = mapped_column(JSON, nullable=False)

    analysis: Mapped[Analysis] = relationship(back_populates="static_report")


class Finding(Base, TimestampMixin):
    """Generic, schema-versioned finding (TRD §6.3). Covers static indicators now and
    dynamic detectors later, distinguished by ``detector`` + ``type``."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(32), default="1.0", nullable=False)
    type: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(String(16), default=Severity.LOW, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    observed_facts: Mapped[list] = mapped_column(JSON, default=list)
    inference: Mapped[str | None] = mapped_column(Text)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)

    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class IOCRow(Base, TimestampMixin):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="static", nullable=False)

    analysis: Mapped[Analysis] = relationship(back_populates="iocs")


class AuditLog(Base, TimestampMixin):
    """Tamper-evident audit trail (FR-14.2/14.3, SR-2). ``prev_hash``/``entry_hash``
    chain entries so deletions/edits are detectable."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), index=True
    )
    actor: Mapped[str] = mapped_column(String(150), default="system", nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(32))
    to_state: Mapped[str | None] = mapped_column(String(32))
    detail: Mapped[dict | None] = mapped_column(JSON)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str | None] = mapped_column(String(64))


Index("ix_findings_analysis_severity", Finding.analysis_id, Finding.severity)
Index("ix_iocs_analysis_type", IOCRow.analysis_id, IOCRow.type)


__all__ = [
    "User",
    "Sample",
    "Analysis",
    "StaticReportRow",
    "Finding",
    "IOCRow",
    "AuditLog",
    "TargetOS",
]
