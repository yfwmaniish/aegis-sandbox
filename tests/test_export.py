"""Tests for STIX 2.1 / MISP export."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.intel import to_misp_event, to_stix_bundle  # noqa: E402

_SHA = "9e48d8be8542010120db6ffd967b1d8ea2cdee794ce56c3b90b4cbdba2fe3f66"


def _report() -> dict:
    return {
        "file_type": "apk",
        "apk": {"package": "com.evil.spy"},
        "indicators": [
            {"id": "net.hardcoded_ip_c2", "severity": "high"},
            {"id": "net.telegram_channel", "severity": "high"},
        ],
        "iocs": [
            {"type": "ipv4", "value": "118.196.64.77"},
            {"type": "domain", "value": "mail-118.196.64.77-connect.cn"},
            {"type": "url", "value": "https://t.me/kodexhacks"},
            {"type": "url", "value": "http://schemas.android.com/apk/res/android"},  # noise
            {"type": "email", "value": "dr.neel.anju@gmail.com"},
            {"type": "url", "value": "https://evil.test/x\x00garbage"},  # embedded NUL
        ],
    }


# ── STIX ─────────────────────────────────────────────────────────────────────

def test_stix_bundle_structure():
    b = to_stix_bundle(_report(), sha256=_SHA, filename="evil.apk", risk=72.0)
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    types = {}
    for o in b["objects"]:
        types[o["type"]] = types.get(o["type"], 0) + 1
        assert o.get("spec_version") == "2.1" or o["type"] == "bundle"
    assert types["malware"] == 1
    assert types["indicator"] >= 5
    assert types["attack-pattern"] >= 1
    assert types["relationship"] >= 1
    # JSON-serializable.
    json.dumps(b)


def test_stix_patterns_and_hash_and_attack():
    b = to_stix_bundle(_report(), sha256=_SHA, filename="evil.apk", risk=72.0)
    patterns = [o["pattern"] for o in b["objects"]
                if o["type"] == "indicator" and o.get("pattern_type") == "stix"]
    joined = " ".join(patterns)
    assert f"[file:hashes.'SHA-256' = '{_SHA}']" in patterns
    assert "[ipv4-addr:value = '118.196.64.77']" in joined
    assert "[domain-name:value = 'mail-118.196.64.77-connect.cn']" in joined
    assert "[url:value = 'https://t.me/kodexhacks']" in joined
    assert "[email-addr:value = 'dr.neel.anju@gmail.com']" in joined
    # Namespace noise dropped; NUL-truncated url present without the junk.
    assert "schemas.android.com" not in joined
    assert "garbage" not in joined and "[url:value = 'https://evil.test/x']" in joined
    # A YARA indicator and ATT&CK attack-patterns exist.
    assert any(o.get("pattern_type") == "yara" for o in b["objects"] if o["type"] == "indicator")
    aps = {o["external_references"][0]["external_id"] for o in b["objects"] if o["type"] == "attack-pattern"}
    assert "T1437.001" in aps and "T1639" in aps


def test_stix_ids_are_deterministic():
    b1 = to_stix_bundle(_report(), sha256=_SHA, filename="a.apk", risk=50.0)
    b2 = to_stix_bundle(_report(), sha256=_SHA, filename="a.apk", risk=50.0)
    ids1 = sorted(o["id"] for o in b1["objects"] if o["type"] != "bundle")
    ids2 = sorted(o["id"] for o in b2["objects"] if o["type"] != "bundle")
    assert ids1 == ids2  # stable across exports


# ── MISP ─────────────────────────────────────────────────────────────────────

def test_misp_event_attributes_and_tags():
    ev = to_misp_event(_report(), sha256=_SHA, filename="evil.apk", risk=72.0)["Event"]
    assert ev["threat_level_id"] == 1  # high
    assert ev["analysis"] == 2
    types = {a["type"] for a in ev["Attribute"]}
    assert {"sha256", "ip-dst", "domain", "url", "email-src", "yara"} <= types
    vals = {a["value"] for a in ev["Attribute"]}
    assert _SHA in vals and "118.196.64.77" in vals
    assert "http://schemas.android.com/apk/res/android" not in vals  # noise dropped
    tagnames = " ".join(t["name"] for t in ev["Tag"])
    assert "T1437.001" in tagnames and "aegis:risk" in tagnames
    json.dumps({"Event": ev})


def test_misp_threat_level_scales_with_risk():
    low = to_misp_event(_report(), sha256=_SHA, filename="x", risk=10.0)["Event"]
    assert low["threat_level_id"] == 3
    clean = to_misp_event({"file_type": "pe", "indicators": [], "iocs": []},
                          sha256=_SHA, filename="x", risk=0.0)["Event"]
    assert clean["threat_level_id"] == 4
