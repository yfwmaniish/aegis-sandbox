# Single image for both API and worker — selected by the compose `command`.
# Debian base so the native static-analysis deps (androguard, tlsh, cryptography)
# get manylinux wheels and the analyzers all run, including APK.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Build deps for any sdist that lacks a wheel (e.g. python-tlsh).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libmagic1 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip \
    && pip install ".[static,api,worker]"

COPY alembic.ini ./
COPY migrations ./migrations

# Non-root runtime user (least privilege; the detonation backend is separate anyway).
RUN useradd --create-home --uid 10001 aegis
USER aegis

EXPOSE 8000

# Default command runs the API; the worker service overrides this in compose.
CMD ["uvicorn", "aegis.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
