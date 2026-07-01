"""Aggregate many analyses into a catch-rate scoreboard.

Turns a set of static reports (from a folder scan or the stored corpus) into headline
numbers: how many samples Aegis flagged, the risk distribution, file-type and capability
breakdowns, and — when VirusTotal cross-referencing is enabled — the count Aegis caught
that VirusTotal missed. Pure and deterministic given its inputs.
"""

from __future__ import annotations

from collections import Counter

from aegis.corpus.models import LabelCount, RiskBucket, ScanRow, Scoreboard

FLAG_THRESHOLD = 25.0  # risk >= this counts as "flagged" (MEDIUM or worse)

_VERDICT_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]
_RISK_BUCKETS = [
    ("clean (0-25)", 0.0, 25.0),
    ("low (25-50)", 25.0, 50.0),
    ("high (50-70)", 50.0, 70.0),
    ("critical (70-100)", 70.0, 100.01),
]


def verdict_for(risk: float | None) -> str:
    r = risk or 0
    if r >= 70:
        return "CRITICAL"
    if r >= 50:
        return "HIGH"
    if r >= 25:
        return "MEDIUM"
    if r > 0:
        return "LOW"
    return "CLEAN"


def row_from_report(
    report: dict, *, sha256: str, filename: str | None, risk: float | None,
    analysis_id: str | None = None, vt=None,
) -> ScanRow:
    """Build one scoreboard row from a static report dict (+ optional VT result)."""
    from aegis.insights import build_visualizations

    try:
        viz = build_visualizations(report, None)
        caps = [a.label for a in sorted(viz.capability_radar, key=lambda a: a.score,
                reverse=True) if a.score >= 40][:4]
    except Exception:  # noqa: BLE001 - a viz failure must not sink the row
        caps = []

    indicators = report.get("indicators") or []
    row = ScanRow(
        filename=filename, sha256=sha256, file_type=report.get("file_type", "unknown"),
        size=int(report.get("size") or 0), risk_score=round(risk or 0.0, 1),
        verdict=verdict_for(risk), indicator_count=len(indicators),
        indicator_ids=[i.get("id") for i in indicators if i.get("id")],
        top_capabilities=caps, analysis_id=analysis_id,
    )
    if vt is not None:
        row.vt_found = vt.found
        row.vt_malicious = vt.malicious if vt.found else None
        flagged = (risk or 0) >= FLAG_THRESHOLD
        if vt.available:
            row.vt_missed = flagged and (not vt.found or (vt.malicious + vt.suspicious) == 0)
    return row


def build_scoreboard(rows: list[ScanRow], *, threshold: float = FLAG_THRESHOLD) -> Scoreboard:
    scored = [r for r in rows if r.error is None]
    total = len(scored)
    flagged = sum(1 for r in scored if r.risk_score >= threshold)

    verdicts = Counter(r.verdict for r in scored)
    verdict_counts = [LabelCount(label=v, count=verdicts.get(v, 0))
                      for v in _VERDICT_ORDER if verdicts.get(v, 0)]

    types = Counter(r.file_type for r in scored)
    file_type_counts = [LabelCount(label=t, count=c) for t, c in types.most_common()]

    buckets = [RiskBucket(label=lab, min=lo, max=hi,
                          count=sum(1 for r in scored if lo <= r.risk_score < hi))
               for lab, lo, hi in _RISK_BUCKETS]

    caps = Counter(cap for r in scored for cap in r.top_capabilities)
    top_capabilities = [LabelCount(label=c, count=n) for c, n in caps.most_common(8)]

    inds = Counter(iid for r in scored for iid in r.indicator_ids)
    top_indicators = [LabelCount(label=i, count=n) for i, n in inds.most_common(10)]

    vt_rows = [r for r in scored if r.vt_missed is not None]
    vt_checked = len(vt_rows) or None
    vt_missed_count = sum(1 for r in vt_rows if r.vt_missed) if vt_rows else None

    return Scoreboard(
        total=total, flagged=flagged, clean=total - flagged,
        flagged_pct=round(100.0 * flagged / total, 1) if total else 0.0,
        flag_threshold=threshold, verdict_counts=verdict_counts,
        file_type_counts=file_type_counts, risk_histogram=buckets,
        top_capabilities=top_capabilities, top_indicators=top_indicators,
        vt_checked=vt_checked, vt_missed_count=vt_missed_count, rows=scored,
    )
