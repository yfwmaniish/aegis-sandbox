"""Static analysis entry point — orchestrates the whole static pass.

``analyze_bytes`` is the single function the worker/task layer calls. It runs the
format-independent extractors (hashing, entropy, strings, IOCs) unconditionally, then
routes to exactly one format analyzer based on magic bytes. Every stage is wrapped so
a failure in one module is recorded in ``analyzer_errors`` and the rest of the report
still completes (TR-STA-02 / NFR-7: non-critical parser failure never aborts output).
"""

from __future__ import annotations

from pathlib import Path

from aegis.static.common.entropy import chunked_entropy, packing_likelihood, shannon_entropy
from aegis.static.common.hashing import compute_hashes
from aegis.static.common.iocs import IOC, extract_iocs
from aegis.static.common.strings import DEFAULT_MAX_COUNT, DEFAULT_MIN_LEN, extract_strings
from aegis.static.dispatch import detect_file_type, mime_for
from aegis.static.models import (
    EntropySummary,
    FileType,
    HashSummary,
    IOCEntry,
    StaticReport,
    StringSummary,
)

_ENTROPY_CHUNK = 4096


def analyze_file(
    path: str | Path,
    *,
    string_min_len: int = DEFAULT_MIN_LEN,
    string_max_count: int = DEFAULT_MAX_COUNT,
) -> StaticReport:
    """Read ``path`` and run the static analysis pipeline over its contents."""
    p = Path(path)
    data = p.read_bytes()
    return analyze_bytes(
        data,
        filename=p.name,
        string_min_len=string_min_len,
        string_max_count=string_max_count,
    )


def analyze_bytes(
    data: bytes,
    *,
    filename: str | None = None,
    string_min_len: int = DEFAULT_MIN_LEN,
    string_max_count: int = DEFAULT_MAX_COUNT,
) -> StaticReport:
    """Run the static analysis pipeline over ``data`` and return a :class:`StaticReport`."""
    hashes = compute_hashes(data)
    file_type = detect_file_type(data, filename)

    # Build the report shell first so later stages can record isolated errors on it.
    report = StaticReport(
        file_type=file_type,
        detected_mime=mime_for(file_type),
        size=len(data),
        hashes=HashSummary(sha256=hashes.sha256, sha1=hashes.sha1, md5=hashes.md5, tlsh=hashes.tlsh),
        entropy=EntropySummary(overall=0.0),
    )

    _run_entropy(report, data)
    iocs = _run_strings_and_iocs(report, data, string_min_len, string_max_count)

    # Route to the format analyzer (exactly one populates its sub-block).
    if file_type == FileType.PE:
        _run_with("pe", report, lambda: _populate_pe(report, data))
    elif file_type == FileType.ELF:
        _run_with("elf", report, lambda: _populate_elf(report, data))
    elif file_type == FileType.APK:
        _run_with("apk", report, lambda: _populate_apk(report, data, iocs))

    _finalize_iocs(report, iocs)
    report.indicators.sort(key=lambda i: (_sev_rank(i.severity), -i.confidence))
    return report


# ── Stage helpers ────────────────────────────────────────────────────────────


def _run_entropy(report: StaticReport, data: bytes) -> None:
    try:
        overall = shannon_entropy(data)
        bands = chunked_entropy(data, _ENTROPY_CHUNK)
        high = sum(1 for b in bands if b.entropy >= 7.0)
        ratio = (high / len(bands)) if bands else 0.0
        report.entropy = EntropySummary(
            overall=round(overall, 3),
            packing_likelihood=packing_likelihood(overall, ratio),
            high_entropy_regions=high,
        )
    except Exception as exc:  # noqa: BLE001
        report.add_error("entropy", exc)


def _run_strings_and_iocs(
    report: StaticReport, data: bytes, min_len: int, max_count: int
) -> list[IOC]:
    iocs: list[IOC] = []
    try:
        extracted = extract_strings(data, min_len=min_len, max_count=max_count)
        report.strings = StringSummary(
            count=extracted.count,
            truncated=extracted.truncated,
            interesting=extracted.interesting,
        )
        iocs = extract_iocs("\n".join(extracted.all()), source="strings")
    except Exception as exc:  # noqa: BLE001
        report.add_error("strings", exc)
    return iocs


def _run_with(module: str, report: StaticReport, fn) -> None:
    """Run a format analyzer, recording any failure as an isolated module error."""
    try:
        report.analyzers_run.append(module)
        fn()
    except Exception as exc:  # noqa: BLE001
        report.add_error(module, exc)


def _populate_pe(report: StaticReport, data: bytes) -> None:
    from aegis.static import pe

    feats, indicators, imphash = pe.analyze(data)
    report.pe = feats
    report.indicators.extend(indicators)
    if imphash:
        report.hashes.imphash = imphash


def _populate_elf(report: StaticReport, data: bytes) -> None:
    from aegis.static import elf

    feats, indicators = elf.analyze(data)
    report.elf = feats
    report.indicators.extend(indicators)


def _populate_apk(report: StaticReport, data: bytes, iocs: list[IOC]) -> None:
    from aegis.static import apk

    feats, indicators, apk_iocs = apk.analyze(data)
    report.apk = feats
    report.indicators.extend(indicators)
    iocs.extend(apk_iocs)


def _finalize_iocs(report: StaticReport, iocs: list[IOC]) -> None:
    # Dedupe across sources, keeping the highest-confidence provenance.
    best: dict[tuple[str, str], IOC] = {}
    for ioc in iocs:
        k = ioc.key()
        if k not in best or ioc.confidence > best[k].confidence:
            best[k] = ioc
    report.iocs = [
        IOCEntry(type=i.type, value=i.value, confidence=i.confidence, source=i.source)
        for i in sorted(best.values(), key=lambda i: (-i.confidence, i.type, i.value))
    ]


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_rank(severity) -> int:
    return _SEV_ORDER.get(getattr(severity, "value", str(severity)), 99)
