"""Scan a folder of samples through the static engine into scoreboard rows.

Parse-only: like the rest of the static path, samples are never executed — they're read
and analyzed. Used by ``aegis scan <folder>`` and available programmatically. Optional
VirusTotal cross-referencing is hash-only (never uploads a file).
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from aegis.corpus.models import ScanRow
from aegis.corpus.scoreboard import row_from_report

# Skip obvious non-samples to keep folder scans clean.
_SKIP_SUFFIXES = {".txt", ".md", ".json", ".log", ".csv", ".yml", ".yaml", ".html"}


def iter_sample_paths(root: Path, *, recursive: bool = False) -> list[Path]:
    it: Iterable[Path] = root.rglob("*") if recursive else root.iterdir()
    return sorted(p for p in it if p.is_file() and p.suffix.lower() not in _SKIP_SUFFIXES)


def scan_path(path: Path, *, string_min_len: int = 5, vt_api_key: str | None = None) -> ScanRow:
    """Analyze a single file into a :class:`ScanRow` (never executes it)."""
    from aegis.static import analyze_file

    try:
        report = analyze_file(str(path), string_min_len=string_min_len)
    except Exception as exc:  # noqa: BLE001 - one bad file must not abort the batch
        return ScanRow(filename=path.name, error=f"{type(exc).__name__}: {exc}")

    rep = report.model_dump(mode="json")
    risk = _risk_from_report(rep)
    vt = None
    if vt_api_key:
        from aegis.intel.virustotal import lookup_virustotal
        vt = lookup_virustotal(rep["hashes"]["sha256"], vt_api_key)
        time.sleep(16)  # free-tier VT: 4 lookups/min — stay under the limit
    return row_from_report(rep, sha256=rep["hashes"]["sha256"], filename=path.name,
                           risk=risk, vt=vt)


def scan_folder(root: Path, *, recursive: bool = False, string_min_len: int = 5,
                vt_api_key: str | None = None) -> list[ScanRow]:
    return [scan_path(p, string_min_len=string_min_len, vt_api_key=vt_api_key)
            for p in iter_sample_paths(root, recursive=recursive)]


def _risk_from_report(report: dict) -> float:
    """Compute the same combined risk score the pipeline persists, from indicators."""
    from aegis.db.persistence import compute_risk
    from aegis.static.models import SuspiciousIndicator

    inds = [SuspiciousIndicator.model_validate(i) for i in (report.get("indicators") or [])]
    return compute_risk(inds)
