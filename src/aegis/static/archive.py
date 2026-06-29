"""Archive-aware analysis for ZIP containers and (large/compressed) APKs.

The format-independent string/IOC pass runs over the *compressed* container bytes, so
anything inside compressed entries — DEX, smali, resources — is invisible (it yields
junk like ``0.tk``). This module decompresses the text-like entries up to a byte budget
and runs IOC extraction + an Android API scan over the *real* content. It also detects
repackaging/decompiled projects (apktool/APKEditor) and embedded APKs.

This is what makes the engine catch samples like a 176 MB "GBWhatsApp" mod whose C2
(`http://<ip>/track.sh`) and spyware APIs live only in decompiled smali, not in any
parseable manifest.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from io import BytesIO

from aegis.static.apk import _DEX_API_MARKERS
from aegis.static.common.iocs import IOC, extract_iocs

# Entries whose decompressed bytes are worth scanning for IOCs / API references.
_TEXT_EXT = (
    ".smali", ".xml", ".json", ".txt", ".properties", ".js", ".html", ".css",
    ".kt", ".java", ".cfg", ".ini", ".yml", ".yaml", ".dex", ".so", ".md",
)
# High-signal IOC types when the source is decompiled code (bare domains / file paths
# are noisy in smali, so we drop them for archive provenance).
_ARCHIVE_IOC_TYPES = {"url", "ip", "email", "btc_address"}

_DEFAULT_BUDGET = 256 * 1024 * 1024     # max decompressed bytes to scan
_PER_ENTRY_CAP = 4 * 1024 * 1024        # max bytes read from a single entry
_IOC_TEXT_CAP = 32 * 1024 * 1024        # max text concatenated for IOC extraction


@dataclass(slots=True)
class ArchiveScan:
    iocs: list[IOC] = field(default_factory=list)
    suspicious_apis: list[str] = field(default_factory=list)
    embedded_apks: list[str] = field(default_factory=list)
    is_decompiled_project: bool = False
    has_manifest: bool = False
    entries: int = 0
    dex_count: int = 0
    smali_count: int = 0
    native_libs: int = 0
    bytes_scanned: int = 0
    truncated: bool = False


def scan_archive(
    data: bytes,
    *,
    budget: int = _DEFAULT_BUDGET,
    per_entry_cap: int = _PER_ENTRY_CAP,
) -> ArchiveScan:
    """Decompress and scan the text/code entries of a ZIP/APK for IOCs + Android APIs."""
    scan = ArchiveScan()
    try:
        zf = zipfile.ZipFile(BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return scan

    names = zf.namelist()
    scan.entries = len(names)
    for n in names:
        low = n.lower()
        if low.endswith(".apk"):
            scan.embedded_apks.append(n)
        elif low.endswith(".so"):
            scan.native_libs += 1
        elif low.endswith(".dex"):
            scan.dex_count += 1
        elif low.endswith(".smali"):
            scan.smali_count += 1
        if n == "AndroidManifest.xml":
            scan.has_manifest = True

    # apktool/APKEditor signature: lots of smali, an apktool.yml, or an original/ tree.
    scan.is_decompiled_project = (
        scan.smali_count > 50
        or "apktool.yml" in names
        or any(n.startswith(("original/", "smali/", "smali_classes")) for n in names)
    )

    apis: set[str] = set()
    ioc_parts: list[str] = []
    ioc_bytes = 0

    for n in names:
        if scan.bytes_scanned >= budget:
            scan.truncated = True
            break
        if not n.lower().endswith(_TEXT_EXT):
            continue
        try:
            with zf.open(n) as fh:
                blob = fh.read(per_entry_cap)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            continue
        scan.bytes_scanned += len(blob)

        for marker, label in _DEX_API_MARKERS.items():
            if marker in blob:
                apis.add(label)

        if ioc_bytes < _IOC_TEXT_CAP and (b"http" in blob or b"://" in blob or b"@" in blob):
            chunk = blob[: _IOC_TEXT_CAP - ioc_bytes]
            ioc_parts.append(chunk.decode("latin-1", "ignore"))
            ioc_bytes += len(chunk)

    scan.suspicious_apis = sorted(apis)
    if ioc_parts:
        scan.iocs = [
            i for i in extract_iocs("\n".join(ioc_parts), source="archive")
            if i.type in _ARCHIVE_IOC_TYPES
        ]
    return scan
