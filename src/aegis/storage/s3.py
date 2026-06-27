"""S3 / MinIO object store (boto3). Used in deployment.

``boto3`` is imported lazily so dev/test environments that only use the local backend
need not install it.
"""

from __future__ import annotations

from aegis.storage.base import ObjectStore


class S3ObjectStore(ObjectStore):
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
    ):
        import boto3  # lazy: optional dependency

        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

    def ensure_bucket(self, bucket: str) -> None:
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=bucket)
        except ClientError:
            self._client.create_bucket(Bucket=bucket)

    def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> str:
        extra = {"ContentType": content_type} if content_type else {}
        self._client.put_object(Bucket=bucket, Key=key, Body=data, **extra)
        return self.ref(bucket, key)

    def get(self, bucket: str, key: str) -> bytes:
        from botocore.exceptions import ClientError

        try:
            resp = self._client.get_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            raise KeyError(self.ref(bucket, key)) from exc
        return resp["Body"].read()

    def exists(self, bucket: str, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError:
            return False
