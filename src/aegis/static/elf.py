"""ELF (Linux/Unix) static analyzer, backed by ``pyelftools`` (pure-Python).

Extracts the ELF header essentials (type/arch/endianness), the program interpreter,
section layout + entropy, the dynamic symbol imports, NEEDED shared libraries, and
RPATH/RUNPATH. Raises explainable indicators for stripping, RWX segments, text
relocations, writable RPATH-style hijack risk, and injection/anti-debug imports.
All extraction is defensive — a truncated section degrades that field only.
"""

from __future__ import annotations

import contextlib
from io import BytesIO

from aegis.static.common.entropy import HIGH_ENTROPY_THRESHOLD, shannon_entropy
from aegis.static.models import ELFFeatures, SectionInfo, Severity, SuspiciousIndicator

ANALYZER_NAME = "elf"

# ELF section flag bits (elf.h SHF_*).
_SHF_WRITE = 0x1
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4

# Imported libc/syscall symbols that frequently appear in droppers, backdoors and
# anti-analysis code. Curated for explainability.
_SUSPICIOUS_SYMBOLS = {
    "system", "popen", "execve", "execl", "execlp", "execvp", "fork", "vfork",
    "ptrace", "dlopen", "dlsym", "mprotect", "mmap", "memfd_create",
    "socket", "connect", "bind", "listen", "accept", "inet_addr",
    "setuid", "setgid", "seteuid", "chmod", "chown", "unlink",
    "prctl", "syscall", "personality", "getenv",
}


def _section_flags(sh_flags: int) -> list[str]:
    flags = []
    if sh_flags & _SHF_ALLOC:
        flags.append("ALLOC")
    if sh_flags & _SHF_WRITE:
        flags.append("WRITE")
    if sh_flags & _SHF_EXECINSTR:
        flags.append("EXECUTE")
    return flags


def analyze(data: bytes) -> tuple[ELFFeatures, list[SuspiciousIndicator]]:
    """Parse ``data`` as an ELF; returns features and heuristic indicators."""
    from elftools.elf.elffile import ELFFile  # lazy: optional dependency

    elf = ELFFile(BytesIO(data))
    feats = ELFFeatures()
    indicators: list[SuspiciousIndicator] = []

    feats.elf_type = elf.header["e_type"]
    feats.arch = elf.get_machine_arch()
    feats.endianness = "little" if elf.little_endian else "big"

    # Program interpreter (PT_INTERP) — its absence is a hint at a static binary.
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_INTERP":
            with contextlib.suppress(Exception):
                feats.interpreter = seg.get_interp_name()
        if seg["p_type"] == "PT_LOAD":
            f = seg["p_flags"]  # 1=X 2=W 4=R
            if (f & 0x1) and (f & 0x2):
                indicators.append(SuspiciousIndicator(
                    id="elf.rwx_segment",
                    title="Writable + executable PT_LOAD segment",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    observed_facts=[f"PT_LOAD p_flags=0x{f:x} (W+X)"],
                    inference="RWX segments enable self-modifying / unpacking code.",
                    evidence=["PT_LOAD"],
                ))

    # ── Sections + entropy ──
    has_symtab = False
    for sec in elf.iter_sections():
        name = sec.name or ""
        if name == ".symtab":
            has_symtab = True
        try:
            body = sec.data()
        except Exception:  # noqa: BLE001 - NOBITS/truncated sections
            body = b""
        ent = round(shannon_entropy(body), 3) if body else None
        flags = _section_flags(sec["sh_flags"])
        feats.sections.append(SectionInfo(
            name=name,
            virtual_address=int(sec["sh_addr"]),
            virtual_size=int(sec["sh_size"]),
            raw_size=len(body) if body else 0,
            entropy=ent,
            flags=flags,
        ))
        if "EXECUTE" in flags and ent is not None and ent >= HIGH_ENTROPY_THRESHOLD:
            indicators.append(SuspiciousIndicator(
                id="elf.high_entropy_code",
                title=f"High-entropy executable section '{name}'",
                severity=Severity.MEDIUM,
                confidence=0.6,
                observed_facts=[f"section '{name}' entropy={ent} (>= {HIGH_ENTROPY_THRESHOLD})"],
                inference="Executable section looks compressed/encrypted — likely packed (UPX et al).",
                evidence=[name],
            ))

    feats.is_stripped = not has_symtab
    if feats.is_stripped:
        indicators.append(SuspiciousIndicator(
            id="elf.stripped",
            title="Symbol table stripped",
            severity=Severity.LOW,
            confidence=0.4,
            observed_facts=["no .symtab section"],
            inference="Stripped binaries hinder static reversing (common but not malicious alone).",
            evidence=[".symtab"],
        ))

    # ── Dynamic: NEEDED libs, RPATH/RUNPATH, TEXTREL ──
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is not None:
        textrel = False
        for tag in dynamic.iter_tags():
            t = tag.entry.d_tag
            if t == "DT_NEEDED":
                feats.needed_libraries.append(tag.needed)
            elif t in ("DT_RPATH", "DT_RUNPATH"):
                val = getattr(tag, "rpath", None) or getattr(tag, "runpath", None)
                if val:
                    feats.rpath.append(val)
            elif t == "DT_TEXTREL" or t == "DT_FLAGS" and (tag.entry.d_val & 0x4):
                textrel = True
        feats.has_text_relocations = textrel
        if textrel:
            indicators.append(SuspiciousIndicator(
                id="elf.text_relocations",
                title="Text relocations present",
                severity=Severity.LOW,
                confidence=0.5,
                observed_facts=["DT_TEXTREL / DF_TEXTREL set"],
                inference="Writable code at load time — unusual for modern toolchains.",
                evidence=[".dynamic"],
            ))
        if feats.rpath:
            indicators.append(SuspiciousIndicator(
                id="elf.rpath_set",
                title="RPATH/RUNPATH set",
                severity=Severity.LOW,
                confidence=0.45,
                observed_facts=[f"rpath={feats.rpath}"],
                inference="Custom library search paths can enable .so hijacking.",
                evidence=feats.rpath,
            ))
    else:
        feats.is_static = True  # no .dynamic => statically linked

    # ── Imported (undefined) dynamic symbols ──
    suspicious_seen: set[str] = set()
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is not None:
        for sym in dynsym.iter_symbols():
            if sym.name and sym["st_shndx"] == "SHN_UNDEF":
                feats.imported_symbols.append(sym.name)
                if sym.name in _SUSPICIOUS_SYMBOLS:
                    suspicious_seen.add(sym.name)

    if suspicious_seen:
        sev = Severity.HIGH if len(suspicious_seen) >= 5 else Severity.MEDIUM
        indicators.append(SuspiciousIndicator(
            id="elf.suspicious_imports",
            title=f"{len(suspicious_seen)} suspicious imported symbol(s)",
            severity=sev,
            confidence=min(0.9, 0.4 + 0.1 * len(suspicious_seen)),
            observed_facts=sorted(suspicious_seen),
            inference="Symbols enable command execution / injection / anti-debug behaviour.",
            evidence=sorted(suspicious_seen),
        ))

    return feats, indicators
