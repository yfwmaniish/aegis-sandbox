"""Pydantic request/response models for the ``/v1`` API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.enums import AnalysisProfile, Role

# ── Auth ─────────────────────────────────────────────────────────────────────


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=150)
    password: str = Field(min_length=8, max_length=256)
    email: str | None = None
    role: Role = Role.ANALYST


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    username: str
    email: str | None
    role: Role
    is_active: bool


# ── Samples ──────────────────────────────────────────────────────────────────


class SampleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    sha256: str
    sha1: str | None
    md5: str | None
    file_type: str
    size: int
    original_filename: str | None
    source: str | None
    created_at: datetime


# ── Analyses ─────────────────────────────────────────────────────────────────


class AnalysisCreate(BaseModel):
    sample_id: uuid.UUID
    profile: AnalysisProfile = AnalysisProfile.STATIC_ONLY


class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    sample_id: uuid.UUID
    target_os: str | None
    profile: str
    state: str
    risk_score: float | None
    error: str | None
    retries: int
    created_at: datetime
    updated_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    detector: str
    detector_version: str
    type: str
    title: str
    severity: str
    confidence: float
    observed_facts: list
    inference: str | None
    evidence_refs: list


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    type: str
    value: str
    confidence: float
    source: str


class TimelineEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    actor: str
    action: str
    from_state: str | None
    to_state: str | None
    detail: dict | None
    created_at: datetime


class Page(BaseModel):
    """Pagination envelope (TR §7.2: pagination for timeline/IOC endpoints)."""

    total: int
    limit: int
    offset: int


class FindingsPage(Page):
    items: list[FindingOut]


class IOCsPage(Page):
    items: list[IOCOut]


class TimelinePage(Page):
    items: list[TimelineEntry]
