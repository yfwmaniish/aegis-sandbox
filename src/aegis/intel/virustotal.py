"""VirusTotal comparison — hash-only lookup (FR: external corroboration).

Looks a sample up on VirusTotal **by its SHA-256 only** — the file itself is never
uploaded — and normalizes the multi-engine result so the UI can put VT's verdict next to
Aegis's. Two outcomes matter for the "even VirusTotal couldn't detect it" story:

* VT has **no record** of the hash (never submitted) → 404, and
* VT knows it but **0 engines flag it** (rated clean).

Both are surfaced explicitly. Requires ``VIRUSTOTAL_API_KEY``; degrades gracefully to an
"unavailable" result when unset or on any network/rate-limit error, so it never breaks
an analysis.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

_VT_API = "https://www.virustotal.com/api/v3/files/"
_GUI = "https://www.virustotal.com/gui/file/"


class VTEngineHit(BaseModel):
    engine: str
    category: str  # malicious | suspicious | undetected | harmless | ...
    result: str | None = None


class VTResult(BaseModel):
    available: bool = False        # key configured + lookup attempted without transport error
    found: bool = False            # VT has a record of this hash
    reason: str | None = None
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    scan_date: str | None = None
    permalink: str | None = None
    detections: list[VTEngineHit] = Field(default_factory=list)


class VTComparison(BaseModel):
    sha256: str
    vt: VTResult
    aegis_risk: float | None = None
    aegis_verdict: str = "UNKNOWN"
    aegis_indicators: int = 0
    headline: str = ""
    contrast: bool = False  # True when MalwareTotal flags what VT does not — the pitch case


def _aegis_verdict(risk: float | None) -> str:
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


def parse_vt_response(sha256: str, payload: dict) -> VTResult:
    """Normalize a VT v3 file object into :class:`VTResult`."""
    attr = (payload.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    results = attr.get("last_analysis_results") or {}
    hits = [
        VTEngineHit(engine=name, category=r.get("category", ""), result=r.get("result"))
        for name, r in results.items()
        if r.get("category") in ("malicious", "suspicious")
    ]
    hits.sort(key=lambda h: (h.category != "malicious", h.engine.lower()))
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected + int(stats.get("timeout", 0))
    scan_epoch = attr.get("last_analysis_date")
    scan_date = None
    if scan_epoch:
        from datetime import UTC, datetime
        with_ = datetime.fromtimestamp(int(scan_epoch), tz=UTC)
        scan_date = with_.strftime("%Y-%m-%d")
    return VTResult(
        available=True, found=True, malicious=malicious, suspicious=suspicious,
        harmless=harmless, undetected=undetected, total_engines=total,
        scan_date=scan_date, permalink=_GUI + sha256, detections=hits[:20],
    )


def lookup_virustotal(sha256: str, api_key: str | None, *, timeout: float = 12.0) -> VTResult:
    """Look up ``sha256`` on VirusTotal (hash only). Never uploads the file."""
    if not api_key:
        return VTResult(available=False, reason="VirusTotal not configured "
                        "(set VIRUSTOTAL_API_KEY). Only the SHA-256 is ever sent.")
    import httpx

    try:
        resp = httpx.get(_VT_API + sha256, headers={"x-apikey": api_key}, timeout=timeout)
    except httpx.HTTPError as exc:
        return VTResult(available=False, reason=f"VirusTotal request failed: {exc}")

    if resp.status_code == 404:
        return VTResult(available=True, found=False, permalink=_GUI + sha256,
                        reason="VirusTotal has no record of this sample (never submitted).")
    if resp.status_code == 401:
        return VTResult(available=False, reason="VirusTotal rejected the API key (401).")
    if resp.status_code == 429:
        return VTResult(available=False, reason="VirusTotal rate limit reached (free tier: "
                        "4 lookups/min). Try again shortly.")
    if resp.status_code != 200:
        return VTResult(available=False, reason=f"VirusTotal returned HTTP {resp.status_code}.")
    try:
        return parse_vt_response(sha256, resp.json())
    except Exception as exc:  # noqa: BLE001
        return VTResult(available=False, reason=f"could not parse VirusTotal response: {exc}")


def build_comparison(sha256: str, vt: VTResult, *, risk: float | None,
                     indicator_count: int) -> VTComparison:
    """Combine the VT result with Aegis's verdict into a headline comparison."""
    verdict = _aegis_verdict(risk)
    aegis_flags = (risk or 0) >= 25
    contrast = False

    if not vt.available:
        headline = f"MalwareTotal: {verdict} ({(risk or 0):.0f}/100). {vt.reason or 'VirusTotal unavailable.'}"
    elif not vt.found:
        headline = (f"VirusTotal: no record of this file — Aegis: {verdict} ({(risk or 0):.0f}/100)")
        contrast = aegis_flags
    else:
        vt_flagged = vt.malicious + vt.suspicious
        headline = (f"VirusTotal: {vt.malicious}/{vt.total_engines} engines flagged — "
                    f"MalwareTotal: {verdict} ({(risk or 0):.0f}/100)")
        contrast = aegis_flags and vt_flagged == 0

    return VTComparison(
        sha256=sha256, vt=vt, aegis_risk=risk, aegis_verdict=verdict,
        aegis_indicators=indicator_count, headline=headline, contrast=contrast,
    )
