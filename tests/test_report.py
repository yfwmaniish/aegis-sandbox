"""Tests for the self-contained HTML report builder."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.insights import build_visualizations  # noqa: E402
from aegis.intel import generate_rules  # noqa: E402
from aegis.intel.models import SimilarResult  # noqa: E402
from aegis.report import build_report_html  # noqa: E402


def _report() -> dict:
    return {
        "file_type": "apk",
        "size": 1_500_000,
        "detected_mime": "application/vnd.android.package-archive",
        "hashes": {"sha256": "a" * 64, "tlsh": None},
        "entropy": {"overall": 7.1, "packing_likelihood": "medium"},
        "apk": {
            "package": "com.evil.spy",
            "permissions": ["android.permission.SEND_SMS", "android.permission.INTERNET"],
            "dangerous_permissions": ["android.permission.SEND_SMS"],
            "suspicious_apis": [], "activities": 1, "services": 1,
            "requests_accessibility": True, "requests_device_admin": False,
        },
        "indicators": [
            {"id": "apk.sms_capability", "severity": "high", "title": "SMS capability",
             "inference": "can send SMS", "evidence": ["SmsManager"]},
            {"id": "net.hardcoded_ip_c2", "severity": "critical", "title": "Hard-coded C2",
             "evidence": ["45.155.205.10"]},
        ],
        "iocs": [
            {"type": "ipv4", "value": "45.155.205.10", "confidence": 0.9, "source": "static"},
            {"type": "url", "value": "https://t.me/evilchan", "confidence": 0.8, "source": "static"},
        ],
    }


def _build(**over) -> str:
    rep = _report()
    viz = build_visualizations(rep, over.get("dynamic"))
    rules = generate_rules(rep, sha256="a" * 64, risk=82.0)
    similar = SimilarResult(target_sha256="a" * 64, corpus_size=0, count=0, matches=[],
                            note="No other samples in the corpus yet.")
    return build_report_html(
        static=rep, viz=viz, dynamic=over.get("dynamic"), understanding=over.get("understanding"),
        rules=rules, similar=similar, sha256="a" * 64, filename="evil.apk",
        risk=82.0, target_os="android",
    )


def test_report_is_self_contained_html():
    doc = _build()
    assert doc.startswith("<!doctype html>")
    assert doc.rstrip().endswith("</html>")
    # No external resource references — everything inlined.
    assert "http://" not in doc.split("<style>")[0]
    assert "<script" not in doc  # no JS dependency (only the print button's inline handler)
    assert 'src=' not in doc


def test_report_contains_all_sections():
    doc = _build()
    for token in ("Analysis Report", "CRITICAL", "Findings", "Hard-coded C2",
                  "Capability radar", "MITRE ATT&CK", "Behaviour", "<svg",
                  "Indicators of Compromise", "45.155.205.10", "rule Aegis_com_evil_spy",
                  "Sigma", "Similar samples"):
        assert token in doc, f"missing: {token}"


def test_report_includes_dynamic_and_ai_when_present():
    dynamic = {
        "package": "com.evil.spy", "runtime_seconds": 120.0, "exit_reason": "finished",
        "event_count": 42, "category_counts": {"network": 5, "sms": 1},
        "environment": {"backend": "avd", "network_policy": "airplane"},
        "network_peers": [{"host": "45.155.205.10", "port": 443}],
        "indicators": [], "used_permissions": [], "loaded_dex": [], "dropped_files": [],
    }
    understanding = {"understanding": {
        "summary": "Spyware masquerading as a wedding invite.",
        "classification": "Android spyware",
        "behavior_workflow": ["Requests SMS", "Exfiltrates to C2"],
        "recommended_actions": ["Block 45.155.205.10", "Uninstall"],
    }}
    doc = _build(dynamic=dynamic, understanding=understanding)
    assert "Dynamic detonation" in doc
    assert "airplane" in doc
    assert "AI analyst narrative" in doc
    assert "Spyware masquerading" in doc
    assert "Exfiltrates to C2" in doc


def test_html_is_escaped():
    rep = _report()
    rep["apk"]["package"] = "com.evil<script>alert(1)</script>"
    viz = build_visualizations(rep, None)
    rules = generate_rules(rep, sha256="a" * 64)
    similar = SimilarResult(target_sha256="a" * 64)
    doc = build_report_html(static=rep, viz=viz, dynamic=None, understanding=None,
                            rules=rules, similar=similar, sha256="a" * 64,
                            filename="x.apk", risk=10.0, target_os="android")
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc
