"""Object store interface."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ObjectStore(ABC):
    @abstractmethod
    def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> str:
        """Store ``data`` and return an opaque storage reference (e.g. ``s3://b/key``)."""

    @abstractmethod
    def get(self, bucket: str, key: str) -> bytes:
        """Fetch object bytes; raises :class:`KeyError` if absent."""

    @abstractmethod
    def exists(self, bucket: str, key: str) -> bool:
        ...

    @abstractmethod
    def ensure_bucket(self, bucket: str) -> None:
        """Create the bucket/prefix if it does not yet exist."""

    @staticmethod
    def ref(bucket: str, key: str) -> str:
        return f"s3://{bucket}/{key}"
