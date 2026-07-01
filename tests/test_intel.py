"""Tests for the threat-intel layer: similarity + rule generation."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.intel import CorpusItem, find_similar, generate_rules  # noqa: E402


def _apk_report(pkg="com.evil.spy", ip="45.155.205.10", sha="a"*64) -> dict:
    return {
        "file_type": "apk",
        "size": 2_000_000,
        "hashes": {"sha256": sha, "tlsh": None},
        "apk": {"package": pkg, "suspicious_apis": ["Landroid/telephony/SmsManager;->sendTextMessage"]},
        "indicators": [
            {"id": "apk.sms_capability", "severity": "high"},
            {"id": "net.hardcoded_ip_c2", "severity": "high"},
            {"id": "net.telegram_channel", "severity": "high"},
        ],
        "iocs": [
            {"type": "ipv4", "value": ip},
            {"type": "url", "value": "https://t.me/evilchan"},
            {"type": "url", "value": "http://schemas.android.com/apk/res/android"},
        ],
        "strings": {"interesting": {"url": ["https://t.me/evilchan"]}},
    }


# ── Similarity ───────────────────────────────────────────────────────────────

def test_similar_ranks_related_high_and_excludes_self():
    target = _apk_report(sha="t"*64)
    clone = CorpusItem("aid-clone", "c"*64, "variant.apk", "apk", 90.0, _apk_report(sha="c"*64))
    unrelated = CorpusItem("aid-pe", "p"*64, "calc.exe", "pe", 3.0,
                           {"file_type": "pe", "size": 40000, "hashes": {}, "indicators": [], "iocs": []})
    itself = CorpusItem("aid-self", "t"*64, "target.apk", "apk", 88.0, target)

    res = find_similar(target, [clone, unrelated, itself], target_sha256="t"*64)
    assert res.corpus_size == 2  # self (same sha) excluded
    assert res.matches, "expected at least one match"
    top = res.matches[0]
    assert top.sample_sha256 == "c"*64
    assert top.score >= 60
    assert top.same_package is True
    assert "net.hardcoded_ip_c2" in top.shared_indicators
    assert "t.me" in top.shared_hosts
    # PE with no overlap should fall below threshold / rank last.
    assert all(m.sample_sha256 != "p"*64 for m in res.matches) or res.matches[-1].score < top.score


def test_similar_empty_corpus_note():
    res = find_similar(_apk_report(), [], target_sha256="z"*64)
    assert res.count == 0 and res.note


# ── Rule generation ──────────────────────────────────────────────────────────

def test_yara_rule_structure_and_content():
    rep = _apk_report()
    bundle = generate_rules(rep, sha256="d"*64, risk=88.0)
    y = bundle.yara.text
    assert y.startswith("rule Aegis_com_evil_spy")
    assert "condition:" in y and "of ($s*)" in y
    assert "45.155.205.10" in y
    assert "t.me/evilchan" in y
    # Benign namespace host must be filtered out of the atoms.
    assert "schemas.android.com" not in y
    assert bundle.yara.string_count > 0


def test_sigma_has_endpoints_and_attack_tags():
    rep = _apk_report()
    bundle = generate_rules(rep, sha256="e"*64)
    s = bundle.sigma.yaml
    assert "logsource:" in s and "detection:" in s and "condition:" in s
    assert "45.155.205.10" in s          # IP endpoint
    assert "t.me" in s                    # domain endpoint
    assert "schemas.android.com" not in s
    assert "attack.command_and_control" in bundle.attack_tags
    assert "attack.t1437.001" in bundle.attack_tags


def test_rules_hash_fallback_when_no_network():
    rep = {"file_type": "pe", "size": 1000, "hashes": {"sha256": "f"*64, "imphash": "1234"},
           "indicators": [{"id": "pe.packer_section", "severity": "medium"}], "iocs": []}
    bundle = generate_rules(rep, sha256="f"*64)
    assert "SHA256=" + "f"*64 in bundle.sigma.yaml       # hash-based sigma
    assert 'pe.imphash() == "1234"' in bundle.yara.text  # imphash pinned in yara
    assert 'import "pe"' in bundle.yara.text
