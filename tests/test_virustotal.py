"""Tests for the VirusTotal comparison (hash-only lookup + verdict comparison)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx  # noqa: E402

from aegis.intel.virustotal import (  # noqa: E402
    build_comparison,
    lookup_virustotal,
    parse_vt_response,
)

_SHA = "a" * 64


class _FakeResp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _vt_payload(malicious=40, suspicious=2, undetected=30, harmless=0):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                "undetected": undetected, "harmless": harmless, "timeout": 0},
        "last_analysis_results": {
            "Kaspersky": {"category": "malicious", "result": "Trojan.AndroidOS.Spy"},
            "ESET": {"category": "malicious", "result": "Android/Spy.Agent"},
            "CleanAV": {"category": "undetected", "result": None},
            "Sus1": {"category": "suspicious", "result": "heuristic"},
        },
        "last_analysis_date": 1_700_000_000,
    }}}


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parse_vt_response_stats_and_detections():
    r = parse_vt_response(_SHA, _vt_payload())
    assert r.available and r.found
    assert r.malicious == 40 and r.suspicious == 2 and r.total_engines == 72
    # Only malicious/suspicious engines are surfaced, malicious first.
    engines = [d.engine for d in r.detections]
    assert "Kaspersky" in engines and "CleanAV" not in engines
    assert r.detections[0].category == "malicious"
    assert r.permalink and r.permalink.endswith(_SHA)
    assert r.scan_date  # formatted from epoch


# ── HTTP handling (mocked) ───────────────────────────────────────────────────

def test_lookup_no_key_is_graceful():
    r = lookup_virustotal(_SHA, None)
    assert r.available is False and "not configured" in (r.reason or "").lower()


def test_lookup_200(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResp(200, _vt_payload(malicious=5)))
    r = lookup_virustotal(_SHA, "KEY")
    assert r.found and r.malicious == 5


def test_lookup_404_unknown(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResp(404))
    r = lookup_virustotal(_SHA, "KEY")
    assert r.available is True and r.found is False
    assert "no record" in (r.reason or "").lower()


def test_lookup_429_rate_limited(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResp(429))
    r = lookup_virustotal(_SHA, "KEY")
    assert r.available is False and "rate limit" in (r.reason or "").lower()


# ── comparison / the pitch cases ─────────────────────────────────────────────

def test_contrast_when_vt_unknown_but_aegis_flags():
    vt = lookup_virustotal(_SHA, None)  # unavailable
    vt.available, vt.found = True, False  # simulate VT "no record"
    vt.reason = None
    c = build_comparison(_SHA, vt, risk=88.0, indicator_count=6)
    assert c.contrast is True
    assert c.aegis_verdict == "CRITICAL"
    assert "no record" in c.headline.lower()


def test_contrast_when_vt_clean_but_aegis_flags():
    vt = parse_vt_response(_SHA, _vt_payload(malicious=0, suspicious=0, undetected=72))
    c = build_comparison(_SHA, vt, risk=60.0, indicator_count=4)
    assert c.contrast is True
    assert "0/72" in c.headline


def test_no_contrast_when_both_flag():
    vt = parse_vt_response(_SHA, _vt_payload(malicious=40))
    c = build_comparison(_SHA, vt, risk=80.0, indicator_count=5)
    assert c.contrast is False


def test_no_contrast_when_aegis_clean():
    vt = parse_vt_response(_SHA, _vt_payload(malicious=0, suspicious=0, undetected=72))
    c = build_comparison(_SHA, vt, risk=5.0, indicator_count=0)
    assert c.contrast is False
    assert c.aegis_verdict == "LOW"
