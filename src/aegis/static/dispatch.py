"""File-type detection via magic bytes (with optional extension hint).

The orchestrator routes by type (TRD §5.3: PE→Windows, ELF→Linux, APK→Android), so
detection must not trust the extension alone — malware lies about extensions. We
sniff magic bytes first and only use the extension as a tie-breaker. APK/JAR/ZIP all
share the ZIP magic, so APK is confirmed by looking for ``AndroidManifest.xml`` inside.
"""

from __future__ import annotations

import zipfile
from io import BytesIO

from aegis.static.models import FileType

_MZ = b"MZ"
_ELF = b"\x7fELF"
_DEX = b"dex\n"
_ZIP = b"PK\x03\x04"
_ZIP_EMPTY = b"PK\x05\x06"
_PDF = b"%PDF-"
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # legacy Office / MS compound file

_SCRIPT_EXTS = {
    ".js": "javascript", ".jse": "javascript", ".mjs": "javascript",
    ".vbs": "vbscript", ".vbe": "vbscript",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".hta": "hta", ".wsf": "wsf",
    ".sh": "shell",
}
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # 32-bit BE
    b"\xce\xfa\xed\xfe",  # 32-bit LE
    b"\xfe\xed\xfa\xcf",  # 64-bit BE
    b"\xcf\xfa\xed\xfe",  # 64-bit LE
    b"\xca\xfe\xba\xbe",  # universal/fat
}

_MIME = {
    FileType.PE: "application/vnd.microsoft.portable-executable",
    FileType.ELF: "application/x-elf",
    FileType.APK: "application/vnd.android.package-archive",
    FileType.DEX: "application/x-dex",
    FileType.MACHO: "application/x-mach-binary",
    FileType.ZIP: "application/zip",
    FileType.PDF: "application/pdf",
    FileType.OFFICE: "application/vnd.ms-office",
    FileType.SCRIPT: "text/x-script",
    FileType.UNKNOWN: "application/octet-stream",
}


def _zip_is_apk(data: bytes) -> bool:
    """An installable APK is defined by a root ``AndroidManifest.xml``. We deliberately
    do NOT trust the ``.apk`` extension: decompiled/repackaging project archives
    (apktool/APKEditor) are named ``.apk`` but have no root manifest — feeding those to
    the APK parser yields garbage, so they must route to the ZIP/archive analyzer."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return "AndroidManifest.xml" in names


def _zip_is_office(data: bytes) -> bool:
    """OOXML (docx/xlsm/pptm) is a ZIP with ``[Content_Types].xml`` and a word/xl/ppt part."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    if "[Content_Types].xml" not in names:
        return False
    return any(n.startswith(("word/", "xl/", "ppt/")) for n in names)


def _looks_textual(data: bytes) -> bool:
    """Heuristic: the sample is text (no NULs, mostly printable) in its first 4 KiB."""
    head = data[:4096]
    if not head or b"\x00" in head:
        return False
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(head) >= 0.90


# Content markers that identify a script even when the extension is missing/lying.
_SCRIPT_MARKERS = (
    (b"#!/", "shell"), (b"<?php", "php"),
    (b"@echo off", "batch"), (b"powershell", "powershell"),
    (b"WScript.", "vbscript"), (b"CreateObject(", "vbscript"),
    (b"<job", "wsf"), (b"<hta:application", "hta"),
)


def detect_script(data: bytes, filename: str | None) -> bool:
    """True if ``data`` is a script — by extension (confirmed textual) or by content."""
    if not _looks_textual(data):
        return False
    if filename:
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        if ext in _SCRIPT_EXTS:
            return True
    low = data[:8192].lower()
    return any(m in low for m, _ in _SCRIPT_MARKERS)


def detect_file_type(data: bytes, filename: str | None = None) -> FileType:
    """Return the :class:`FileType` for ``data`` using magic bytes (and the real ZIP
    contents to tell a true APK/Office doc from a generic/project archive)."""
    if data[:5] == _PDF or _PDF in data[:1024]:
        return FileType.PDF
    if data[:8] == _OLE:
        return FileType.OFFICE            # legacy OLE Office (also .msg/.msi — treated as doc)
    if len(data) >= 4:
        head4 = data[:4]
        if head4 in _MACHO_MAGICS:
            return FileType.MACHO
        if head4 == _ELF:
            return FileType.ELF
        if head4 == _DEX:
            return FileType.DEX
    if data[:2] == _MZ:
        return FileType.PE
    if data[:4] in (_ZIP, _ZIP_EMPTY):
        if _zip_is_apk(data):
            return FileType.APK
        if _zip_is_office(data):
            return FileType.OFFICE
        return FileType.ZIP
    if detect_script(data, filename):
        return FileType.SCRIPT
    return FileType.UNKNOWN


def mime_for(file_type: FileType) -> str:
    return _MIME.get(file_type, _MIME[FileType.UNKNOWN])
