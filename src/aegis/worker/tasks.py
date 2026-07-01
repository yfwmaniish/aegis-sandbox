"""Celery task definitions and the dispatch helper used by the control plane."""

from __future__ import annotations

import threading

import structlog

from aegis.core.config import get_settings
from aegis.worker.pipeline import execute_static_analysis

log = structlog.get_logger(__name__)


def _register_tasks():
    """Bind the pipeline to a Celery task. Done lazily so importing this module in a
    pure-inline environment doesn't require a configured broker connection."""
    from aegis.worker.celery_app import celery_app

    @celery_app.task(
        name="aegis.static_analysis",
        bind=True,
        max_retries=2,
        default_retry_delay=10,
        autoretry_for=(ConnectionError, TimeoutError),
        retry_backoff=True,
    )
    def run_static_analysis(self, analysis_id: str) -> dict:  # noqa: ANN001
        return execute_static_analysis(analysis_id)

    return run_static_analysis


run_static_analysis = _register_tasks()


def _run_inline_safe(analysis_id: str) -> None:
    """Run the pipeline and swallow exceptions (execute_analysis already records the
    failure state in the DB; here we only guard the background thread from dying noisily)."""
    try:
        execute_static_analysis(analysis_id)
    except Exception:  # noqa: BLE001 - thread boundary; state already persisted
        log.exception("inline_analysis_thread_failed", analysis_id=analysis_id)


def enqueue_static_analysis(analysis_id: str, *, allow_background: bool = False) -> str | None:
    """Run (inline) or dispatch (Celery) the static analysis for ``analysis_id``.

    Inline mode normally runs synchronously and returns ``None``. When
    ``allow_background`` is set (used for detonation profiles, which can take minutes),
    inline mode instead runs the pipeline in a daemon thread and returns immediately so
    the HTTP request doesn't block — the caller polls the analysis state. Dispatch mode
    returns the Celery task id. Selection is via ``AEGIS_INLINE_TASKS`` (TR §3.1)."""
    settings = get_settings()
    if settings.inline_tasks:
        if allow_background:
            threading.Thread(
                target=_run_inline_safe, args=(analysis_id,),
                name=f"aegis-analysis-{analysis_id[:8]}", daemon=True,
            ).start()
            return None
        execute_static_analysis(analysis_id)
        return None
    async_result = run_static_analysis.delay(analysis_id)
    return async_result.id
