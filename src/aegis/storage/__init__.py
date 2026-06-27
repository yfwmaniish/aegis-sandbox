"""Object storage abstraction for samples and artifacts.

The control plane and worker depend on the :class:`ObjectStore` interface only. A
filesystem backend serves dev/test; the S3/MinIO backend is used in deployment
(quarantine bucket, write-once finalized evidence — TR-SEC-02). Pick via
``STORAGE_BACKEND``.
"""

from aegis.storage.base import ObjectStore
from aegis.storage.factory import get_object_store

__all__ = ["ObjectStore", "get_object_store"]
