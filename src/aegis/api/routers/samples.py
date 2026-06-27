"""Sample ingestion endpoints (FR-1 / TR-ING)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.deps import get_current_user, get_db
from aegis.api.schemas import SampleOut
from aegis.core.config import get_settings
from aegis.db.models import Sample, User
from aegis.db.persistence import append_audit
from aegis.static.common.hashing import sha256_hex
from aegis.static.dispatch import detect_file_type

router = APIRouter(prefix="/v1/samples", tags=["samples"])


@router.post("", response_model=SampleOut, status_code=status.HTTP_201_CREATED)
def upload_sample(
    file: UploadFile = File(...),
    source: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a sample. Computes SHA256 before persisting (TR-ING-02), dedupes by hash
    (TR-ING-03), and stores the bytes in the quarantine object store."""
    settings = get_settings()
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty upload")
    if len(data) > settings.static_max_file_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"file exceeds {settings.static_max_file_mb} MB limit",
        )

    sha256 = sha256_hex(data)
    file_type = detect_file_type(data, file.filename)

    existing = db.execute(select(Sample).where(Sample.sha256 == sha256)).scalar_one_or_none()
    if existing is not None:
        # Idempotent re-submission: return the known sample (FR-1.4 allows re-analysis
        # via a separate POST /v1/analyses against this sample id).
        return existing

    # Lazy import so the API doesn't require boto3 unless storage is actually used.
    from aegis.storage import get_object_store

    store = get_object_store()
    storage_ref = store.put(settings.s3_bucket_samples, sha256, data,
                            content_type=file.content_type)

    sample = Sample(
        sha256=sha256,
        file_type=file_type.value,
        size=len(data),
        original_filename=file.filename,
        source=source,
        submitter=user.username,
        storage_ref=storage_ref,
    )
    # md5/sha1 are computed by the engine during analysis; sha256 is authoritative here.
    db.add(sample)
    db.flush()
    append_audit(db, actor=user.username, action="sample_uploaded",
                 detail={"sha256": sha256, "file_type": file_type.value, "size": len(data)})
    db.commit()
    db.refresh(sample)
    return sample


@router.get("/{sample_id}", response_model=SampleOut)
def get_sample(
    sample_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sample = db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="sample not found")
    return sample
