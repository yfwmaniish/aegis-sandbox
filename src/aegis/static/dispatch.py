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


def detect_file_type(data: bytes, filename: str | None = None) -> FileType:
    """Return the :class:`FileType` for ``data`` using magic bytes (and the real ZIP
    contents to tell a true APK from a generic/project archive)."""
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
        return FileType.APK if _zip_is_apk(data) else FileType.ZIP
    return FileType.UNKNOWN


def mime_for(file_type: FileType) -> str:
    return _MIME.get(file_type, _MIME[FileType.UNKNOWN])
