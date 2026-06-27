"""Celery application (broker + result backend = Redis).

Priority queues (normal/high) and retry/dead-letter handling per TRD §3.1. The actual
task body lives in :mod:`aegis.worker.tasks`; this module only configures the app.
"""

from __future__ import annotations

from celery import Celery

from aegis.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "aegis",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["aegis.worker.tasks"],
)

celery_app.conf.update(
    task_acks_late=True,                 # redeliver if a worker dies mid-task
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,        # fair dispatch for long analysis tasks
    task_default_queue="normal",
    task_queues={
        "high": {"exchange": "high", "routing_key": "high"},
        "normal": {"exchange": "normal", "routing_key": "normal"},
    },
    task_track_started=True,
    result_expires=86_400,
    task_always_eager=settings.inline_tasks,  # run inline if tasks aren't dispatched
)
