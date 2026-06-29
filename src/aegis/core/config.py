"""Central configuration, loaded from environment / ``.env`` (NFR-1, TR-SEC: secrets
come from the environment / a vault, never hardcoded).

A single :class:`Settings` object is shared by the API, worker and CLI. The
SQLAlchemy URL is derived from the discrete Postgres vars, but can be overridden by
``DATABASE_URL`` (e.g. ``sqlite+pysqlite:///./aegis.db`` for local/test runs).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: str = Field(default="dev", alias="AEGIS_ENV")

    # API / auth
    api_host: str = Field(default="0.0.0.0", alias="AEGIS_API_HOST")
    api_port: int = Field(default=8000, alias="AEGIS_API_PORT")
    jwt_secret: str = Field(default="dev-insecure-change-me", alias="AEGIS_JWT_SECRET")
    jwt_alg: str = Field(default="HS256", alias="AEGIS_JWT_ALG")
    jwt_ttl_minutes: int = Field(default=60, alias="AEGIS_JWT_TTL_MINUTES")

    # Database — explicit URL wins; otherwise build a Postgres URL from parts.
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_db: str = Field(default="aegis", alias="POSTGRES_DB")
    postgres_user: str = Field(default="aegis", alias="POSTGRES_USER")
    postgres_password: str = Field(default="aegis", alias="POSTGRES_PASSWORD")

    # Redis / Celery
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    # Run analysis tasks inline in the API process instead of dispatching to Celery.
    # Convenient for dev/test (no broker/worker needed); set false in deployment.
    inline_tasks: bool = Field(default=True, alias="AEGIS_INLINE_TASKS")

    # Object storage (MinIO / S3). ``local`` writes under ``local_storage_dir`` for
    # dev/test without MinIO; ``s3`` uses the S3_* settings below.
    storage_backend: str = Field(default="local", alias="STORAGE_BACKEND")
    local_storage_dir: str = Field(default="./data/objstore", alias="LOCAL_STORAGE_DIR")
    s3_endpoint: str = Field(default="http://localhost:9000", alias="S3_ENDPOINT")
    s3_region: str = Field(default="us-east-1", alias="S3_REGION")
    s3_access_key: str = Field(default="aegis", alias="S3_ACCESS_KEY")
    s3_secret_key: str = Field(default="aegis-secret", alias="S3_SECRET_KEY")
    s3_bucket_samples: str = Field(default="aegis-samples", alias="S3_BUCKET_SAMPLES")
    s3_bucket_artifacts: str = Field(default="aegis-artifacts", alias="S3_BUCKET_ARTIFACTS")

    # Search / vector
    opensearch_url: str = Field(default="http://localhost:9200", alias="OPENSEARCH_URL")
    qdrant_url: str = Field(default="http://localhost:6333", alias="QDRANT_URL")

    # LLM (Claude) — AI-assisted understanding/reporting. Key from the environment,
    # never hardcoded (TR-SEC). When unset, the feature degrades gracefully.
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    llm_model: str = Field(default="claude-opus-4-8", alias="AEGIS_LLM_MODEL")
    llm_max_tokens: int = Field(default=8000, alias="AEGIS_LLM_MAX_TOKENS")

    @property
    def llm_enabled(self) -> bool:
        return bool(self.anthropic_api_key)

    # Dynamic detonation. ``sandbox_backend`` selects the orchestrator: "" disables
    # dynamic (static-only), "genymotion" uses a real device, "fake" replays canned
    # telemetry (tests/demos). Only profiles other than static_only detonate.
    sandbox_backend: str = Field(default="", alias="SANDBOX_BACKEND")
    genymotion_device: str = Field(default="aegis-android", alias="GENYMOTION_DEVICE")
    dynamic_max_runtime_seconds: int = Field(default=120, alias="DYNAMIC_MAX_RUNTIME_SECONDS")
    dynamic_network_policy: str = Field(default="sinkhole", alias="DYNAMIC_NETWORK_POLICY")

    # Static analysis limits
    static_max_file_mb: int = Field(default=200, alias="STATIC_MAX_FILE_MB")
    static_string_min_len: int = Field(default=5, alias="STATIC_STRING_MIN_LEN")
    static_string_max_count: int = Field(default=50_000, alias="STATIC_STRING_MAX_COUNT")

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def static_max_file_bytes(self) -> int:
        return self.static_max_file_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Process-wide singleton settings (cached)."""
    return Settings()
