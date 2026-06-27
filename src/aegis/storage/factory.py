"""Object store selection based on configuration."""

from __future__ import annotations

import contextlib
from functools import lru_cache

from aegis.core.config import get_settings
from aegis.storage.base import ObjectStore


@lru_cache
def get_object_store() -> ObjectStore:
    s = get_settings()
    if s.storage_backend == "s3":
        from aegis.storage.s3 import S3ObjectStore

        store = S3ObjectStore(
            endpoint=s.s3_endpoint,
            access_key=s.s3_access_key,
            secret_key=s.s3_secret_key,
            region=s.s3_region,
        )
    else:
        from aegis.storage.local import LocalObjectStore

        store = LocalObjectStore(s.local_storage_dir)

    # Make sure the canonical buckets exist up front (best-effort).
    for bucket in (s.s3_bucket_samples, s.s3_bucket_artifacts):
        with contextlib.suppress(Exception):
            store.ensure_bucket(bucket)
    return store
