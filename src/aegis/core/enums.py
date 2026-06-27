"""Platform-wide enumerations (analysis lifecycle, target OS, roles, profiles)."""

from __future__ import annotations

from enum import Enum


class AnalysisState(str, Enum):
    """Analysis lifecycle states (SRS §7.1 / TRD §8).

    Happy path:
    ``created → queued → provisioning → running → collecting → processing →
    reporting → completed``.
    """

    CREATED = "created"
    QUEUED = "queued"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    COLLECTING = "collecting"
    PROCESSING = "processing"
    REPORTING = "reporting"
    COMPLETED = "completed"

    # Terminal/failure exits.
    FAILED_PROVISIONING = "failed_provisioning"
    FAILED_RUNTIME = "failed_runtime"
    FAILED_PROCESSING = "failed_processing"
    TERMINATED_POLICY = "terminated_policy"


class TargetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"


class AnalysisProfile(str, Enum):
    """Detonation profile. ``static_only`` skips dynamic detonation entirely; the
    others select an environment image set. ``hardened`` is the evasion-resistant
    profile used for dual-profile comparison (PRD FR-5)."""

    STATIC_ONLY = "static_only"
    STANDARD = "standard"
    HARDENED = "hardened"


class Role(str, Enum):
    """RBAC roles (SRS §2.2, FR-14.1)."""

    ANALYST = "analyst"
    DETECTION_ENGINEER = "detection_engineer"
    RESEARCHER = "researcher"
    ADMIN = "admin"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
