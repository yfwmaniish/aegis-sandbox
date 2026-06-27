"""Celery task definitions and the dispatch helper used by the control plane."""

from __future__ import annotations

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


def enqueue_static_analysis(analysis_id: str) -> str | None:
    """Run (inline) or dispatch (Celery) the static analysis for ``analysis_id``.

    Inline mode runs synchronously and returns ``None``; dispatch mode returns the
    Celery task id. Selection is via ``AEGIS_INLINE_TASKS`` (TR §3.1)."""
    settings = get_settings()
    if settings.inline_tasks:
        execute_static_analysis(analysis_id)
        return None
    async_result = run_static_analysis.delay(analysis_id)
    return async_result.id
