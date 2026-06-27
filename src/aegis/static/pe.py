"""PE (Windows) static analyzer, backed by ``pefile``.

Extracts the structural features a malware analyst reaches for first — sections and
their entropy, the import table + imphash, exports, resources, Authenticode signing
state, TLS callbacks and the embedded PDB path — then raises a handful of explainable
heuristic indicators (packing, RWX sections, injection-capable imports, stomped
timestamps). Everything is best-effort: a malformed structure degrades one field, it
does not abort the analyzer (TR-STA-02).
"""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.static.common.entropy import (
    HIGH_ENTROPY_THRESHOLD,
)
from aegis.static.models import (
    ImportInfo,
    PEFeatures,
    SectionInfo,
    Severity,
    SuspiciousIndicator,
)

ANALYZER_NAME = "pe"

# Section characteristic bits (winnt.h).
_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000

# APIs that, taken together, signal process injection / dynamic code / persistence.
# Curated for explainability — each maps to a behaviour an analyst recognises.
_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "SetWindowsHookExA", "SetWindowsHookExW",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenUrlA",
    "WinHttpOpen", "HttpSendRequestA", "socket", "connect", "send", "recv",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "BCryptEncrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter", "Sleep", "SleepEx",
    "OpenProcess", "AdjustTokenPrivileges", "OpenProcessToken",
}

# Section names dropped by well-known packers.
_PACKER_SECTION_NAMES = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    "FSG!": "FSG", ".petite": "Petite", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
}


def _section_flags(characteristics: int) -> list[str]:
    flags = []
    if characteristics & _SCN_CNT_CODE:
        flags.append("CODE")
    if characteristics & _SCN_MEM_EXECUTE:
        flags.append("EXECUTE")
    if characteristics & _SCN_MEM_READ:
        flags.append("READ")
    if characteristics & _SCN_MEM_WRITE:
        flags.append("WRITE")
    return flags


def _clean_name(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("latin-1", "replace").strip()


def analyze(data: bytes) -> tuple[PEFeatures, list[SuspiciousIndicator], str | None]:
    """Parse ``data`` as a PE.

    Returns ``(features, indicators, imphash)``. The imphash is returned separately
    because it belongs on the shared :class:`HashSummary`, not the PE-only feature
    block. Raises only if ``pefile`` is unavailable or the file is not a parseable
    PE; the runner catches that and records it as an isolated module error."""
    import pefile  # lazy: optional dependency

    pe = pefile.PE(data=data, fast_load=False)
    feats = PEFeatures()
    indicators: list[SuspiciousIndicator] = []

    feats.is_dll = bool(pe.is_dll())
    feats.machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, str(pe.FILE_HEADER.Machine))
    try:
        feats.subsystem = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem)
        feats.entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        feats.image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    except AttributeError:
        pass

    # Compile timestamp — frequently zeroed or faked ("timestomped").
    ts = int(pe.FILE_HEADER.TimeDateStamp)
    if ts:
        try:
            dt = datetime.fromtimestamp(ts, tz=UTC)
            feats.timestamp = dt.isoformat()
            if dt > datetime.now(tz=UTC):
                indicators.append(SuspiciousIndicator(
                    id="pe.future_timestamp",
                    title="PE compile timestamp is in the future",
                    severity=Severity.LOW,
                    confidence=0.6,
                    observed_facts=[f"TimeDateStamp={feats.timestamp}"],
                    inference="Timestamp likely faked (timestomping) or build clock wrong.",
                    evidence=["FILE_HEADER.TimeDateStamp"],
                ))
        except (OverflowError, OSError, ValueError):
            feats.timestamp = str(ts)

    # ── Sections + entropy ──
    high_entropy_exec = 0
    exec_sections = 0
    for s in pe.sections:
        name = _clean_name(s.Name)
        flags = _section_flags(s.Characteristics)
        sec_entropy = float(s.get_entropy())
        feats.sections.append(SectionInfo(
            name=name,
            virtual_address=int(s.VirtualAddress),
            virtual_size=int(s.Misc_VirtualSize),
            raw_size=int(s.SizeOfRawData),
            entropy=round(sec_entropy, 3),
            flags=flags,
        ))
        if "EXECUTE" in flags:
            exec_sections += 1
            if sec_entropy >= HIGH_ENTROPY_THRESHOLD:
                high_entropy_exec += 1
        if "EXECUTE" in flags and "WRITE" in flags:
            indicators.append(SuspiciousIndicator(
                id="pe.rwx_section",
                title=f"Writable + executable section '{name}'",
                severity=Severity.MEDIUM,
                confidence=0.7,
                observed_facts=[f"section '{name}' is RWX (flags={'+'.join(flags)})"],
                inference="RWX sections are a common self-modifying / unpacking pattern.",
                evidence=[name],
            ))
        if name in _PACKER_SECTION_NAMES:
            indicators.append(SuspiciousIndicator(
                id="pe.packer_section",
                title=f"Known packer section '{name}' ({_PACKER_SECTION_NAMES[name]})",
                severity=Severity.MEDIUM,
                confidence=0.85,
                observed_facts=[f"section named '{name}'"],
                inference=f"Binary appears packed with {_PACKER_SECTION_NAMES[name]}.",
                evidence=[name],
            ))

    if exec_sections and high_entropy_exec:
        ratio = high_entropy_exec / exec_sections
        if ratio >= 0.5:
            indicators.append(SuspiciousIndicator(
                id="pe.high_entropy_code",
                title="High-entropy executable section(s)",
                severity=Severity.MEDIUM,
                confidence=0.65,
                observed_facts=[f"{high_entropy_exec}/{exec_sections} executable sections >= "
                                f"{HIGH_ENTROPY_THRESHOLD} bits/byte"],
                inference="Code sections look compressed/encrypted — likely packed.",
                evidence=[s.name for s in feats.sections if (s.entropy or 0) >= HIGH_ENTROPY_THRESHOLD],
            ))

    # ── Imports + imphash ──
    suspicious_seen: set[str] = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fn = imp.name.decode("latin-1", "replace")
                    funcs.append(fn)
                    if fn in _SUSPICIOUS_IMPORTS:
                        suspicious_seen.add(fn)
                elif imp.ordinal is not None:
                    funcs.append(f"ordinal_{imp.ordinal}")
            feats.imports.append(ImportInfo(library=lib, functions=funcs))
    try:
        imphash = pe.get_imphash() or None
    except Exception:  # noqa: BLE001 - imphash is best-effort, never fatal
        imphash = None

    if suspicious_seen:
        sev = Severity.HIGH if len(suspicious_seen) >= 5 else Severity.MEDIUM
        indicators.append(SuspiciousIndicator(
            id="pe.suspicious_imports",
            title=f"{len(suspicious_seen)} suspicious imported API(s)",
            severity=sev,
            confidence=min(0.9, 0.4 + 0.1 * len(suspicious_seen)),
            observed_facts=sorted(suspicious_seen),
            inference="Imports enable injection / dynamic code / anti-analysis behaviour.",
            evidence=sorted(suspicious_seen),
        ))

    # Very small import table is itself suspicious (packed binaries resolve at runtime).
    total_imports = sum(len(i.functions) for i in feats.imports)
    if total_imports and total_imports < 6:
        indicators.append(SuspiciousIndicator(
            id="pe.tiny_import_table",
            title=f"Unusually small import table ({total_imports} functions)",
            severity=Severity.LOW,
            confidence=0.5,
            observed_facts=[f"{total_imports} imported functions across {len(feats.imports)} libs"],
            inference="Few static imports often means APIs are resolved at runtime (packing).",
            evidence=[i.library for i in feats.imports],
        ))

    # ── Exports ──
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                feats.exports.append(exp.name.decode("latin-1", "replace"))

    # ── Resources (top-level type names) ──
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if rtype.name is not None:
                feats.resources.append(str(rtype.name))
            elif rtype.id is not None:
                feats.resources.append(
                    pefile.RESOURCE_TYPE.get(rtype.id, f"id_{rtype.id}")
                )

    # ── TLS callbacks (run before AddressOfEntryPoint — anti-analysis favourite) ──
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        try:
            cb = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            if cb:
                feats.tls_callbacks = 1
                indicators.append(SuspiciousIndicator(
                    id="pe.tls_callbacks",
                    title="TLS callbacks present",
                    severity=Severity.LOW,
                    confidence=0.55,
                    observed_facts=[f"AddressOfCallBacks=0x{cb:x}"],
                    inference="TLS callbacks execute before the entry point — used to evade "
                              "breakpoints on main().",
                    evidence=["DIRECTORY_ENTRY_TLS"],
                ))
        except AttributeError:
            pass

    # ── Authenticode signing presence ──
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        feats.is_signed = bool(sec_dir.VirtualAddress and sec_dir.Size)
    except (AttributeError, KeyError, IndexError):
        feats.is_signed = False

    # ── Debug PDB path ──
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            entry = getattr(dbg, "entry", None)
            pdb = getattr(entry, "PdbFileName", None)
            if pdb:
                feats.debug_pdb_path = pdb.rstrip(b"\x00").decode("latin-1", "replace")
                break

    pe.close()
    return feats, indicators, imphash
