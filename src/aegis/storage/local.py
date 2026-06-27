"""Filesystem-backed object store for dev/test (no MinIO required).

Layout: ``<root>/<bucket>/<key>``. Refs still use the ``s3://bucket/key`` form so the
rest of the system is storage-backend agnostic.
"""

from __future__ import annotations

from pathlib import Path

from aegis.storage.base import ObjectStore


class LocalObjectStore(ObjectStore):
    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, bucket: str, key: str) -> Path:
        # ``key`` may contain '/'; keep it as a nested path but stay under the bucket.
        p = (self.root / bucket / key).resolve()
        bucket_root = (self.root / bucket).resolve()
        if not str(p).startswith(str(bucket_root)):
            raise ValueError("key escapes bucket root")
        return p

    def ensure_bucket(self, bucket: str) -> None:
        (self.root / bucket).mkdir(parents=True, exist_ok=True)

    def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> str:
        path = self._path(bucket, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return self.ref(bucket, key)

    def get(self, bucket: str, key: str) -> bytes:
        path = self._path(bucket, key)
        if not path.exists():
            raise KeyError(self.ref(bucket, key))
        return path.read_bytes()

    def exists(self, bucket: str, key: str) -> bool:
        return self._path(bucket, key).exists()
