"""Static analysis engine.

Format-aware parsers (PE/ELF/APK) plus common feature extractors (hashing,
entropy, strings, IOCs). Produces a versioned :class:`StaticReport` (see
``models.py``). The engine is deliberately dependency-light at import time:
heavy format libraries are imported lazily inside each analyzer so a missing
optional dependency only disables that one analyzer (TR-STA-02: parser errors
isolated per module, non-fatal where possible).
"""

from aegis.static.models import STATIC_SCHEMA_VERSION, StaticReport
from aegis.static.runner import analyze_bytes, analyze_file

__all__ = [
    "STATIC_SCHEMA_VERSION",
    "StaticReport",
    "analyze_file",
    "analyze_bytes",
]
