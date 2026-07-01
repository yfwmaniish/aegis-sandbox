"""Assemble a :class:`DynamicReport` from collected raw telemetry.

The orchestrator backend hands back raw artifacts (Frida JSONL, logcat, dumpsys); this
module normalizes them into the canonical event stream, rolls up behaviour, and runs
the dynamic detectors. Kept separate from any backend so it's testable with fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.dynamic import detectors
from aegis.dynamic.models import DynamicEnvironment, DynamicReport, NormalizedEvent
from aegis.dynamic.normalize import (
    parse_dumpsys_permissions,
    parse_frida_events,
    parse_logcat,
    parse_sinkhole,
    parse_strace,
)

# A modest cap on how many full events to embed in the report (the complete stream is
# persisted/indexed separately to bound DB/payload size).
_MAX_EMBEDDED_EVENTS = 2000


def build_report(
    *,
    package: str | None,
    profile: str,
    environment: DynamicEnvironment,
    frida_jsonl: str = "",
    logcat: str = "",
    dumpsys: str = "",
    strace: str = "",
    sinkhole: str = "",
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    exit_reason: str = "finished",
    raw_refs: list[str] | None = None,
    collector_errors: dict[str, str] | None = None,
) -> DynamicReport:
    """Normalize raw telemetry into a summarized, detector-scored dynamic report."""
    events: list[NormalizedEvent] = []
    errors = dict(collector_errors or {})

    for name, fn in (("frida", lambda: parse_frida_events(frida_jsonl)),
                     ("logcat", lambda: parse_logcat(logcat)),
                     ("strace", lambda: parse_strace(strace)),
                     ("sinkhole", lambda: parse_sinkhole(sinkhole))):
        try:
            events.extend(fn())
        except Exception as exc:  # noqa: BLE001 - one collector failing must not abort
            errors[name] = f"{type(exc).__name__}: {exc}"

    events.sort(key=lambda e: e.timestamp)

    requested, granted = ([], [])
    if dumpsys:
        try:
            requested, granted = parse_dumpsys_permissions(dumpsys)
        except Exception as exc:  # noqa: BLE001
            errors["dumpsys"] = f"{type(exc).__name__}: {exc}"

    started = started_at or (events[0].timestamp if events else None)
    ended = ended_at or (events[-1].timestamp if events else None)
    runtime = (ended - started).total_seconds() if (started and ended) else 0.0

    report = DynamicReport(
        package=package,
        profile=profile,
        environment=environment,
        started_at=started,
        ended_at=ended,
        runtime_seconds=round(max(runtime, 0.0), 2),
        exit_reason=exit_reason,
        requested_permissions=requested,
        granted_permissions=granted,
        events=events[:_MAX_EMBEDDED_EVENTS],
        raw_refs=raw_refs or [],
        collector_errors=errors,
    )
    report.summarize()
    report.indicators = detectors.detect(report)
    report.indicators.sort(key=lambda i: (_sev_rank(i.severity), -i.confidence))
    return report


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_rank(sev) -> int:
    return _SEV_ORDER.get(getattr(sev, "value", str(sev)), 99)


def _now() -> datetime:
    return datetime.now(UTC)
