"""Archive-aware analysis tests (decompiled projects, embedded APKs, smali IOCs).

Mirrors the real GBWhatsApp 'Indian Army' sample: a .apk-named ZIP that is actually an
apktool/APKEditor project with C2 + spyware APIs hidden in decompressed smali.
"""

from __future__ import annotations

import zipfile
from io import BytesIO

import pytest

from aegis.static import analyze_bytes
from aegis.static.archive import scan_archive
from aegis.static.models import FileType


@pytest.fixture(scope="session")
def decompiled_project() -> bytes:
    buf = BytesIO()
    payload = (
        b".class public LX;\n"
        b"const-string v0, \"http://203.0.113.50/gate.php\"\n"
        b"const-string v1, \"https://t.me/evilactor\"\n"
        b"invoke-virtual {}, Landroid/telephony/SmsManager;->sendTextMessage\n"
        b"invoke-static {}, Ljava/lang/Runtime;->exec\n"
        b"new-instance v2, Ldalvik/system/DexClassLoader;\n"
        b"invoke-virtual {}, getDeviceId\n"
        b"invoke-virtual {}, getLastKnownLocation\n"
        b"invoke-virtual {}, Landroid/media/MediaRecorder;->start\n"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("original/com.legit.app.apk", b"PK\x03\x04" + b"\x00" * 64)
        zf.writestr("apktool.yml", b"version: 2.0\n")
        zf.writestr("smali/com/evil/Payload.smali", payload)
        for i in range(60):  # exceed the decompiled-project smali threshold
            zf.writestr(f"smali/com/x/C{i}.smali", b".class public LC;\n")
    return buf.getvalue()


class TestScanArchive:
    def test_finds_smali_iocs_and_apis(self, decompiled_project):
        scan = scan_archive(decompiled_project)
        assert scan.is_decompiled_project is True
        assert scan.embedded_apks == ["original/com.legit.app.apk"]
        assert scan.smali_count >= 60
        urls = {i.value for i in scan.iocs if i.type == "url"}
        assert "http://203.0.113.50/gate.php" in urls
        assert any("SmsManager" in a for a in scan.suspicious_apis)
        assert any("Runtime.exec" in a or "command exec" in a for a in scan.suspicious_apis)
        assert any("location" in a.lower() for a in scan.suspicious_apis)
        # bare-domain / file-path noise is filtered out for archive provenance
        assert all(i.type in {"url", "ip", "email", "btc_address"} for i in scan.iocs)


class TestArchivePipeline:
    def test_zip_project_is_flagged(self, decompiled_project):
        r = analyze_bytes(decompiled_project, filename="MarriageInvite_v2.apk")
        assert r.file_type == FileType.ZIP            # not mislabeled as APK
        ids = {i.id for i in r.indicators}
        assert "archive.decompiled_project" in ids
        assert "archive.embedded_apk" in ids
        assert "archive.spyware_capabilities" in ids
        assert "net.hardcoded_ip_c2" in ids           # C2 from smali now scored
        # severity-sorted, highest first
        assert r.indicators[0].severity.value in {"critical", "high"}

    def test_clean_zip_is_low_risk(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", b"just some notes, nothing to see")
            zf.writestr("data.json", b'{"hello": "world"}')
        r = analyze_bytes(buf.getvalue(), filename="bundle.zip")
        assert r.file_type == FileType.ZIP
        assert not any(i.severity.value in {"high", "critical"} for i in r.indicators)
