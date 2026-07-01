"""Tests for the deterministic visualization/insight layer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.insights import build_visualizations  # noqa: E402


def _apk_static() -> dict:
    return {
        "file_type": "apk",
        "entropy": {"packing_likelihood": "low"},
        "apk": {
            "package": "com.evil.spyware",
            "permissions": [
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.INTERNET",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
            ],
            "dangerous_permissions": ["android.permission.SEND_SMS"],
            "suspicious_apis": ["Landroid/telephony/SmsManager;->sendTextMessage"],
            "uses_native_libs": [],
        },
        "indicators": [
            {"id": "apk.sms_capability", "severity": "high"},
            {"id": "apk.overlay_plus_accessibility", "severity": "critical"},
            {"id": "apk.accessibility_service", "severity": "high"},
            {"id": "net.hardcoded_ip_c2", "severity": "high"},
            {"id": "net.telegram_channel", "severity": "high"},
        ],
        "iocs": [
            {"type": "ipv4", "value": "45.155.205.10"},
            {"type": "url", "value": "https://t.me/evilchannel"},
        ],
    }


def _apk_dynamic() -> dict:
    return {
        "indicators": [
            {"id": "dyn.sms_sent", "severity": "critical"},
            {"id": "dyn.runtime_c2", "severity": "high"},
        ],
        "category_counts": {"network": 3, "sms": 1},
        "network_peers": [{"host": "45.155.205.10", "port": 443}],
        "used_permissions": ["android.permission.SEND_SMS"],
        "loaded_dex": [],
        "dropped_files": [],
    }


def test_apk_visualizations_full():
    viz = build_visualizations(_apk_static(), _apk_dynamic())
    assert viz.file_type == "apk"
    assert viz.package == "com.evil.spyware"
    assert viz.has_dynamic is True

    radar = {a.key: a for a in viz.capability_radar}
    # SMS + C2 should both peg high given static + runtime signals.
    assert radar["sms_telephony"].score >= 80
    assert radar["network_c2"].score >= 80
    assert radar["persistence_control"].score >= 50
    assert "sent SMS at runtime" in radar["sms_telephony"].evidence

    heat = {c.key: c for c in viz.permission_heatmap}
    assert heat["sms"].count == 2 and heat["sms"].risk == "high"
    assert heat["overlay"].count == 1
    assert heat["network"].risk == "low"
    # Runtime-used permission is flagged.
    sms_perms = {p.permission: p for p in heat["sms"].permissions}
    assert sms_perms["SEND_SMS"].used_at_runtime is True
    assert sms_perms["SEND_SMS"].dangerous is True

    techs = {t.technique_id for t in viz.attack_matrix}
    assert "T1582" in techs           # SMS Control
    assert "T1437.001" in techs       # C2 web protocol
    assert "T1417.002" in techs       # overlay GUI input capture
    assert "T1639" in techs           # telegram exfil
    assert "T1626" in techs           # accessibility abuse

    kinds = {n.kind for n in viz.behavior_graph.nodes}
    assert {"sample", "capability", "host"} <= kinds
    host_labels = {n.label for n in viz.behavior_graph.nodes if n.kind == "host"}
    assert "45.155.205.10" in host_labels
    # Every edge references a real node.
    node_ids = {n.id for n in viz.behavior_graph.nodes}
    for e in viz.behavior_graph.edges:
        assert e.source in node_ids and e.target in node_ids


def test_static_only_apk_no_dynamic():
    viz = build_visualizations(_apk_static(), None)
    assert viz.has_dynamic is False
    radar = {a.key: a for a in viz.capability_radar}
    # Static SMS capability alone still scores, but lower than with runtime confirmation.
    assert 0 < radar["sms_telephony"].score < 100
    assert any(t.technique_id == "T1582" for t in viz.attack_matrix)


def test_pe_report_does_not_crash_and_maps_enterprise():
    pe = {
        "file_type": "pe",
        "entropy": {"packing_likelihood": "high"},
        "apk": None,
        "indicators": [
            {"id": "pe.packer_section", "severity": "medium"},
            {"id": "pe.suspicious_imports", "severity": "high"},
        ],
        "iocs": [{"type": "domain", "value": "evil.example.com"}],
    }
    viz = build_visualizations(pe, None)
    # No APK -> heatmap categories all empty.
    assert all(c.count == 0 and c.risk == "none" for c in viz.permission_heatmap)
    radar = {a.key: a for a in viz.capability_radar}
    assert radar["evasion_obfuscation"].score > 0
    techs = {t.technique_id for t in viz.attack_matrix}
    assert "T1027.002" in techs and "T1106" in techs
    # Domain IOC becomes a host node.
    assert any(n.label == "evil.example.com" for n in viz.behavior_graph.nodes)


def test_empty_report_is_safe():
    viz = build_visualizations({"file_type": "unknown"}, None)
    assert viz.capability_radar  # all axes present, scores 0
    assert all(a.score == 0 for a in viz.capability_radar)
    assert viz.attack_matrix == []
    assert len(viz.behavior_graph.nodes) == 1  # just the sample node
