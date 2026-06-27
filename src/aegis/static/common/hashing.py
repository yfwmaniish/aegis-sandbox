"""Content hashing: cryptographic digests + optional fuzzy hash (TLSH).

SHA256 is the canonical sample identifier across the whole platform (SRS FR-1.2).
MD5/SHA1 are kept for cross-referencing against external feeds that still use them.
TLSH is a locality-sensitive hash: similar files yield similar hashes, which feeds
similarity/clustering (FR-11). TLSH is optional — if the wheel isn't present we just
omit it rather than fail the analysis.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(slots=True)
class FileHashes:
    sha256: str
    sha1: str
    md5: str
    tlsh: str | None = None


def compute_hashes(data: bytes) -> FileHashes:
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return FileHashes(sha256=sha256, sha1=sha1, md5=md5, tlsh=tlsh_hash(data))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tlsh_hash(data: bytes) -> str | None:
    """Fuzzy hash via python-tlsh. Returns ``None`` if the lib is missing or the
    input is too small/uniform for TLSH to produce a digest (it needs >= 50 bytes
    of sufficient variance)."""
    try:
        import tlsh  # type: ignore
    except ImportError:
        return None
    try:
        digest = tlsh.hash(data)
    except (ValueError, TypeError):
        return None
    # TLSH returns "TNULL" (or "" on some builds) when it can't hash the input.
    if not digest or digest == "TNULL":
        return None
    return digest
