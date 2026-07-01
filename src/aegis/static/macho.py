"""Mach-O static analysis (macOS/iOS) — header + load commands.

Dependency-free struct parsing: architecture(s), file type, linked dylibs, @rpath
entries, code-signature and encryption presence. Handles thin (32/64-bit, either
endianness) and fat/universal binaries. Bounds-checked so a malformed file degrades to
partial features rather than raising.
"""

from __future__ import annotations

import struct

from aegis.static.models import MachOFeatures, Severity, SuspiciousIndicator

_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64),
}
_FAT = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

_CPU = {
    7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
    0x0200000C: "arm64_32", 18: "ppc", 0x01000012: "ppc64",
}
_FILETYPE = {
    1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD", 6: "DYLIB",
    7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB", 10: "DSYM", 11: "KEXT_BUNDLE",
}

LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32

_DYLIB_CMDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB}


def _cstr(buf: bytes, off: int) -> str:
    end = buf.find(b"\x00", off)
    return buf[off:end if end >= 0 else len(buf)].decode("utf-8", "replace")


def _parse_fat(data: bytes) -> MachOFeatures:
    feats = MachOFeatures(magic="fat", is_fat=True)
    try:
        nfat = struct.unpack_from(">I", data, 4)[0]
    except struct.error:
        return feats
    archs: list[str] = []
    for i in range(min(nfat, 32)):
        base = 8 + i * 20
        try:
            cputype = struct.unpack_from(">i", data, base)[0]
        except struct.error:
            break
        archs.append(_CPU.get(cputype & 0xFFFFFFFF, f"cpu:{cputype}"))
    feats.archs = archs
    return feats


def _parse_thin(data: bytes, endian: str, bits: int) -> MachOFeatures:
    feats = MachOFeatures(magic=f"macho{bits}", is_fat=False)
    hdr = endian + ("IiiIIII" if bits == 32 else "IiiIIIII")
    try:
        fields = struct.unpack_from(hdr, data, 0)
    except struct.error:
        return feats
    cputype, _sub, filetype, ncmds = fields[1], fields[2], fields[3], fields[4]
    feats.archs = [_CPU.get(cputype & 0xFFFFFFFF, f"cpu:{cputype}")]
    feats.filetype = _FILETYPE.get(filetype, f"type:{filetype}")
    feats.ncmds = ncmds

    off = 28 if bits == 32 else 32
    dylibs: list[str] = []
    rpaths: list[str] = []
    for _ in range(min(ncmds, 4000)):
        try:
            cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        except struct.error:
            break
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        seg = data[off:off + cmdsize]
        if cmd in _DYLIB_CMDS:
            try:
                name_off = struct.unpack_from(endian + "I", seg, 8)[0]
                dylibs.append(_cstr(seg, name_off))
            except struct.error:
                pass
        elif cmd == LC_RPATH:
            try:
                path_off = struct.unpack_from(endian + "I", seg, 8)[0]
                rpaths.append(_cstr(seg, path_off))
            except struct.error:
                pass
        elif cmd == LC_CODE_SIGNATURE:
            feats.is_signed = True
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            try:
                cryptid = struct.unpack_from(endian + "I", seg, 16)[0]
                feats.is_encrypted = feats.is_encrypted or cryptid != 0
            except struct.error:
                pass
        elif cmd in (LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION):
            feats.min_os = feats.min_os or _min_os(seg, endian, cmd)
        off += cmdsize

    feats.linked_dylibs = dylibs
    feats.rpaths = rpaths
    return feats


def _min_os(seg: bytes, endian: str, cmd: int) -> str | None:
    try:
        off = 16 if cmd == LC_BUILD_VERSION else 8
        ver = struct.unpack_from(endian + "I", seg, off)[0]
        return f"{ver >> 16}.{(ver >> 8) & 0xFF}.{ver & 0xFF}"
    except struct.error:
        return None


def analyze(data: bytes) -> tuple[MachOFeatures, list[SuspiciousIndicator]]:
    magic = data[:4]
    if magic in _FAT:
        feats = _parse_fat(data)
    elif magic in _MAGICS:
        endian, bits = _MAGICS[magic]
        feats = _parse_thin(data, endian, bits)
    else:
        feats = MachOFeatures(magic="unknown")

    ind: list[SuspiciousIndicator] = []
    if not feats.is_fat and feats.filetype and not feats.is_signed:
        ind.append(SuspiciousIndicator(
            id="macho.unsigned", title="Mach-O binary is not code-signed",
            severity=Severity.MEDIUM, confidence=0.55,
            observed_facts=["no LC_CODE_SIGNATURE"],
            inference="Unsigned binaries are blocked by Gatekeeper by default; distributing "
                      "one implies side-loading outside the App Store / notarisation.",
            evidence=["LC_CODE_SIGNATURE absent"],
        ))
    if feats.is_encrypted:
        ind.append(SuspiciousIndicator(
            id="macho.encrypted", title="Mach-O has an encrypted segment",
            severity=Severity.MEDIUM, confidence=0.6,
            observed_facts=["LC_ENCRYPTION_INFO cryptid != 0"],
            inference="Segment encryption (beyond App Store FairPlay) is used to hinder "
                      "static analysis of the payload.",
            evidence=["LC_ENCRYPTION_INFO"],
        ))
    if feats.rpaths:
        ind.append(SuspiciousIndicator(
            id="macho.rpath_set", title="Mach-O sets @rpath entries",
            severity=Severity.LOW, confidence=0.4,
            observed_facts=feats.rpaths[:6],
            inference="Writable/relative @rpath entries can enable dylib hijacking.",
            evidence=feats.rpaths[:6],
        ))
    return feats, ind
