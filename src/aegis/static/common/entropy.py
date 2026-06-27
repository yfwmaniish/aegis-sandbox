"""Shannon entropy and packing/obfuscation heuristics.

Entropy is the workhorse signal for "is this region compressed/encrypted/packed".
A uniformly random byte stream approaches 8.0 bits/byte; English text sits around
4.5; long runs of one value approach 0. Packed/encrypted payloads and high-entropy
PE/ELF sections are a classic packing marker (Program Doc §6.1 "entropy, obfuscation
markers"; PRD FR-2 "entropy/packing indicators").
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Above this, a section/region is "high entropy" — likely compressed/encrypted/packed.
HIGH_ENTROPY_THRESHOLD = 7.0
# Below this, a region is suspiciously uniform (padding, zeroed, or trivially encoded).
LOW_ENTROPY_THRESHOLD = 1.0


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte for ``data`` (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


@dataclass(slots=True)
class EntropyBand:
    """Entropy of one fixed-size window, for spotting packed regions inside a file."""

    offset: int
    size: int
    entropy: float


def chunked_entropy(data: bytes, chunk_size: int = 4096) -> list[EntropyBand]:
    """Entropy per ``chunk_size`` window — reveals a packed blob inside an otherwise
    normal file (e.g. a high-entropy overlay appended to a clean stub)."""
    bands: list[EntropyBand] = []
    for offset in range(0, len(data), chunk_size):
        window = data[offset : offset + chunk_size]
        bands.append(EntropyBand(offset=offset, size=len(window), entropy=shannon_entropy(window)))
    return bands


def is_high_entropy(value: float, threshold: float = HIGH_ENTROPY_THRESHOLD) -> bool:
    return value >= threshold


def packing_likelihood(overall_entropy: float, high_entropy_section_ratio: float) -> str:
    """Coarse packed/not-packed verdict from whole-file entropy and the fraction of
    executable-ish sections that are high entropy. Returns ``low``/``medium``/``high``.

    Kept intentionally explainable rather than ML-driven (Program Doc §7
    "Explainability: each finding linked to concrete evidence")."""
    if overall_entropy >= HIGH_ENTROPY_THRESHOLD and high_entropy_section_ratio >= 0.5:
        return "high"
    if overall_entropy >= 6.5 or high_entropy_section_ratio >= 0.34:
        return "medium"
    return "low"
