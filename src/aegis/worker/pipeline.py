"""The analysis pipeline — static triage, then (optional) dynamic detonation.

``execute_analysis`` is what the Celery task wraps / the API calls inline. It always
runs the static pass first (it identifies the file and, for APKs, the package to
detonate). If the analysis profile asks for detonation *and* a sandbox backend is
configured, it then drives the orchestrator through the full lifecycle
(provision → stage → execute → collect → teardown), normalizes the telemetry, runs the
dynamic detectors, and folds runtime findings into the combined risk score.

Every step records a state-machine transition (SR-2), and a detonation failure degrades
to ``failed_runtime`` with the static results preserved (NFR-7) — it never crashes the
worker. Teardown/rollback is guaranteed via ``finally`` (TR-DYN-03).
"""

from __future__ import annotations

import uuid

import structlog

from aegis.core.config import get_settings
from aegis.core.enums import AnalysisProfile, AnalysisState
from aegis.core.state import AnalysisStateMachine, InvalidTransition
from aegis.db.base import session_scope
from aegis.db.models import Analysis
from aegis.db.persistence import (
    compute_risk,
    persist_dynamic_report,
    persist_static_report,
    record_transition,
)
from aegis.dynamic.analyze import build_report
from aegis.dynamic.models import DynamicEnvironment
from aegis.orchestrator import EnvironmentSpec, ExecutionBudget, get_backend, route_environment
from aegis.orchestrator.router import is_routable
from aegis.static import analyze_bytes
from aegis.static.models import FileType
from aegis.storage import get_object_store

log = structlog.get_logger(__name__)


def execute_analysis(analysis_id: str) -> dict:
    """Run the full pipeline (static + optional dynamic) for one analysis."""
    settings = get_settings()
    store = get_object_store()
    aid = uuid.UUID(analysis_id)

    with session_scope() as session:
        analysis = session.get(Analysis, aid)
        if analysis is None:
            raise KeyError(f"analysis {analysis_id} not found")
        sample = analysis.sample
        profile = _profile(analysis.profile)

        sm = AnalysisStateMachine(analysis_id, AnalysisState(analysis.state), retries=analysis.retries)

        def move(to: AnalysisState, *, reason: str = "", actor: str = "worker") -> None:
            t = sm.transition(to, reason=reason, actor=actor)
            analysis.state = to
            analysis.retries = sm.retries
            record_transition(session, t)

        dyn_indicators: list = []
        try:
            if sm.state == AnalysisState.CREATED:
                move(AnalysisState.QUEUED, reason="picked up by worker")

            # ── Static triage (always) ──
            data = store.get(settings.s3_bucket_samples, sample.sha256)
            static_report = analyze_bytes(
                data,
                filename=sample.original_filename,
                string_min_len=settings.static_string_min_len,
                string_max_count=settings.static_string_max_count,
            )
            sample.file_type = static_report.file_type.value
            sample.tlsh = static_report.hashes.tlsh
            if static_report.file_type != FileType.UNKNOWN and is_routable(static_report.file_type):
                analysis.target_os = route_environment(static_report.file_type).value
            persist_static_report(session, analysis, static_report)

            # ── Dynamic detonation (optional) ──
            if _should_detonate(settings, profile, static_report.file_type):
                dyn_indicators = _detonate(
                    settings, store, session, analysis, static_report, profile, move
                )
            else:
                move(AnalysisState.PROCESSING, reason="static-only pipeline")

            analysis.risk_score = compute_risk(static_report.indicators + dyn_indicators)
            move(AnalysisState.REPORTING, reason="assembling report")
            move(AnalysisState.COMPLETED, reason="analysis complete")
            analysis.error = None
            log.info("analysis_completed", analysis_id=analysis_id,
                     file_type=static_report.file_type.value, risk=analysis.risk_score,
                     static_findings=len(static_report.indicators), dynamic_findings=len(dyn_indicators))
            return {
                "analysis_id": analysis_id, "state": analysis.state,
                "file_type": static_report.file_type.value, "risk_score": analysis.risk_score,
                "static_findings": len(static_report.indicators),
                "dynamic_findings": len(dyn_indicators),
            }
        except InvalidTransition:
            raise
        except Exception as exc:  # noqa: BLE001 - failure captured, not a worker crash
            log.error("analysis_failed", analysis_id=analysis_id, error=str(exc))
            fail = (AnalysisState.FAILED_RUNTIME if sm.state in {
                AnalysisState.PROVISIONING, AnalysisState.RUNNING, AnalysisState.COLLECTING
            } else AnalysisState.FAILED_PROCESSING)
            try:
                move(fail, reason=str(exc))
            except InvalidTransition:
                analysis.state = fail
            analysis.error = f"{type(exc).__name__}: {exc}"
            return {"analysis_id": analysis_id, "state": analysis.state, "error": analysis.error}


def _detonate(settings, store, session, analysis, static_report, profile, move) -> list:
    """Drive the orchestrator through one detonation; returns dynamic indicators."""
    backend_cls = _load_backend(settings.sandbox_backend)
    orch = backend_cls(settings, store)
    target_os = route_environment(static_report.file_type)
    spec = EnvironmentSpec(
        target_os=target_os, profile=profile, image=settings.genymotion_device,
        labels={"network_policy": settings.dynamic_network_policy},
    )

    move(AnalysisState.PROVISIONING, reason="provisioning sandbox")
    sess = orch.provision(str(analysis.id), spec)
    try:
        move(AnalysisState.RUNNING, reason="detonating sample")
        orch.stage_sample(sess, sample_ref(analysis, store, settings))
        budget = ExecutionBudget(
            max_runtime_seconds=settings.dynamic_max_runtime_seconds,
            network_policy=settings.dynamic_network_policy,
        )
        det = orch.execute(sess, budget)

        move(AnalysisState.COLLECTING, reason="collecting telemetry")
        coll = orch.collect(sess)

        move(AnalysisState.PROCESSING, reason="normalizing + detecting")
        raw = _load_raw(store, coll.raw_refs)
        package = (static_report.apk.package if static_report.apk else None) or sess.extra.get("package")
        dyn_report = build_report(
            package=package,
            profile=profile.value,
            environment=DynamicEnvironment(
                backend=settings.sandbox_backend, device=sess.extra.get("device_name"),
                image=settings.genymotion_device, network_policy=settings.dynamic_network_policy,
            ),
            frida_jsonl=raw["frida"], logcat=raw["logcat"], dumpsys=raw["dumpsys"],
            exit_reason=det.exit_reason, raw_refs=coll.raw_refs,
        )
        return persist_dynamic_report(session, analysis, dyn_report)
    finally:
        roll = orch.teardown(sess)
        record_transition_audit(session, analysis, roll)


def _should_detonate(settings, profile: AnalysisProfile, file_type: FileType) -> bool:
    return (
        profile != AnalysisProfile.STATIC_ONLY
        and bool(settings.sandbox_backend)
        and file_type == FileType.APK  # only APKs are directly installable for now
    )


def _load_backend(name: str):
    # Import backends so they self-register, then resolve by name.
    import aegis.orchestrator.fake  # noqa: F401
    if name == "genymotion":
        import aegis.orchestrator.genymotion  # noqa: F401
    return get_backend(name)


def sample_ref(analysis, store, settings) -> str:
    ref = analysis.sample.storage_ref
    if ref:
        return ref
    return store.ref(settings.s3_bucket_samples, analysis.sample.sha256)


def _load_raw(store, refs: list[str]) -> dict[str, str]:
    out = {"frida": "", "logcat": "", "dumpsys": ""}
    for ref in refs:
        _, _, rest = ref.partition("://")
        bucket, _, key = rest.partition("/")
        try:
            text = store.get(bucket, key).decode("utf-8", "replace")
        except KeyError:
            continue
        if ref.endswith("frida.jsonl"):
            out["frida"] = text
        elif ref.endswith("logcat.txt"):
            out["logcat"] = text
        elif ref.endswith("dumpsys.txt"):
            out["dumpsys"] = text
    return out


def record_transition_audit(session, analysis, roll) -> None:
    from aegis.db.persistence import append_audit

    append_audit(
        session, actor="worker", action="sandbox_teardown", analysis_id=analysis.id,
        detail={"rolled_back": roll.rolled_back, "verified": roll.verified, "detail": roll.detail},
    )


def _profile(value: str) -> AnalysisProfile:
    try:
        return AnalysisProfile(value)
    except ValueError:
        return AnalysisProfile.STATIC_ONLY


# Back-compat alias (older imports/tasks referenced the static-only name).
execute_static_analysis = execute_analysis
