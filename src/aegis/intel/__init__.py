"""Threat-intel layer: sample similarity (FR-11) and detection-rule generation (FR-12)."""

from __future__ import annotations

from aegis.intel.export import to_misp_event, to_stix_bundle
from aegis.intel.models import RuleBundle, SimilarMatch, SimilarResult
from aegis.intel.rules import generate_rules
from aegis.intel.similarity import CorpusItem, find_similar

__all__ = [
    "CorpusItem",
    "RuleBundle",
    "SimilarMatch",
    "SimilarResult",
    "find_similar",
    "generate_rules",
    "to_misp_event",
    "to_stix_bundle",
]
