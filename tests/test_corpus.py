"""Tests for the corpus catch-rate scoreboard."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.corpus.models import ScanRow  # noqa: E402
from aegis.corpus.scan import iter_sample_paths  # noqa: E402
from aegis.corpus.scoreboard import build_scoreboard, row_from_report, verdict_for  # noqa: E402
from aegis.intel.virustotal import VTResult  # noqa: E402


def _apk_report(ip="45.155.205.10") -> dict:
    return {
        "file_type": "apk", "size": 1_000_000, "hashes": {"sha256": "a" * 64},
        "apk": {"package": "com.evil", "permissions": ["android.permission.SEND_SMS"],
                "dangerous_permissions": ["android.permission.SEND_SMS"], "suspicious_apis": []},
        "indicators": [
            {"id": "apk.sms_capability", "severity": "high"},
            {"id": "net.hardcoded_ip_c2", "severity": "high"},
        ],
        "iocs": [{"type": "ipv4", "value": ip}],
    }


def test_verdict_thresholds():
    assert verdict_for(85) == "CRITICAL"
    assert verdict_for(60) == "HIGH"
    assert verdict_for(30) == "MEDIUM"
    assert verdict_for(10) == "LOW"
    assert verdict_for(0) == "CLEAN"


def test_row_from_report_captures_signals():
    r = row_from_report(_apk_report(), sha256="a" * 64, filename="evil.apk", risk=72.0)
    assert r.verdict == "CRITICAL"
    assert r.indicator_count == 2
    assert "net.hardcoded_ip_c2" in r.indicator_ids
    assert any("Network" in c for c in r.top_capabilities)


def test_row_vt_missed_flag():
    # VT knows the file but 0 engines flag it, while Aegis flags it -> vt_missed.
    vt_clean = VTResult(available=True, found=True, malicious=0, suspicious=0, total_engines=70)
    r = row_from_report(_apk_report(), sha256="a" * 64, filename="x.apk", risk=80.0, vt=vt_clean)
    assert r.vt_missed is True
    # VT flags it too -> not "missed".
    vt_hit = VTResult(available=True, found=True, malicious=30, suspicious=1, total_engines=70)
    r2 = row_from_report(_apk_report(), sha256="a" * 64, filename="x.apk", risk=80.0, vt=vt_hit)
    assert r2.vt_missed is False
    # VT has no record + Aegis flags -> missed.
    vt_unknown = VTResult(available=True, found=False)
    r3 = row_from_report(_apk_report(), sha256="a" * 64, filename="x.apk", risk=80.0, vt=vt_unknown)
    assert r3.vt_missed is True


def test_build_scoreboard_aggregates():
    rows = [
        ScanRow(sha256="1", file_type="apk", risk_score=80, verdict="CRITICAL",
                indicator_ids=["net.hardcoded_ip_c2"], top_capabilities=["Network / C2"]),
        ScanRow(sha256="2", file_type="apk", risk_score=55, verdict="HIGH",
                indicator_ids=["net.hardcoded_ip_c2"], top_capabilities=["Network / C2"]),
        ScanRow(sha256="3", file_type="pe", risk_score=10, verdict="LOW", indicator_ids=[]),
        ScanRow(sha256="4", file_type="pe", risk_score=0, verdict="CLEAN", indicator_ids=[]),
        ScanRow(sha256="5", filename="bad", error="boom"),  # excluded from scoring
    ]
    b = build_scoreboard(rows)
    assert b.total == 4  # errored row excluded
    assert b.flagged == 2 and b.clean == 2
    assert b.flagged_pct == 50.0
    vc = {c.label: c.count for c in b.verdict_counts}
    assert vc["CRITICAL"] == 1 and vc["HIGH"] == 1
    tc = {c.label: c.count for c in b.file_type_counts}
    assert tc["apk"] == 2 and tc["pe"] == 2
    # risk histogram buckets: 1 critical(70-100), 1 high(50-70), 1 low(25-50)? 10 is clean.
    hist = {x.label.split(" ")[0]: x.count for x in b.risk_histogram}
    assert hist["critical"] == 1 and hist["high"] == 1 and hist["clean"] == 2
    ti = {c.label: c.count for c in b.top_indicators}
    assert ti["net.hardcoded_ip_c2"] == 2
    assert b.vt_checked is None  # no VT cross-ref supplied


def test_iter_sample_paths_skips_noise(tmp_path):
    (tmp_path / "sample.bin").write_bytes(b"\x00" * 100)
    (tmp_path / "notes.txt").write_text("skip me")
    (tmp_path / "report.json").write_text("{}")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.elf").write_bytes(b"\x7fELF")
    flat = iter_sample_paths(tmp_path, recursive=False)
    assert [p.name for p in flat] == ["sample.bin"]
    rec = {p.name for p in iter_sample_paths(tmp_path, recursive=True)}
    assert "sample.bin" in rec and "nested.elf" in rec and "notes.txt" not in rec
