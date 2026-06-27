"""Deterministic, self-contained binary fixtures for the static engine tests.

We synthesise minimal-but-valid PE / ELF / APK structures in memory rather than
committing real malware or OS binaries. They are small and reproducible, so tests
are hermetic and safe to run anywhere.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO

import pytest


def _build_minimal_pe32() -> bytes:
    """A minimal but pefile-parseable PE32 executable: DOS stub + PE/COFF + optional
    header (16 data dirs) + one ``.text`` section."""
    pe_off = 0x40
    opt_size = 0xE0  # PE32 optional header incl. 16 data directories

    # DOS header: 'MZ', e_lfanew at 0x3c -> pe_off.
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    coff = struct.pack(
        "<2sHHIIIHH",
        b"PE", 0,            # signature "PE\0\0"
        0x014C,              # Machine = I386
        1,                   # NumberOfSections
        0x5A4A1B00,          # TimeDateStamp (fixed, in the past)
        0, 0,                # PointerToSymbolTable, NumberOfSymbols
        opt_size,            # SizeOfOptionalHeader
    )
    coff += struct.pack("<H", 0x0102)  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    opt = struct.pack(
        "<HBBIIIIIII",
        0x10B,               # Magic = PE32
        9, 0,                # linker version
        0x200,               # SizeOfCode
        0, 0,                # SizeOfInitializedData, SizeOfUninitializedData
        0x1000,              # AddressOfEntryPoint
        0x1000,              # BaseOfCode
        0x2000,              # BaseOfData (PE32 only)
        0x400000,            # ImageBase
    )
    opt += struct.pack(
        "<IIHHHHHHIIIIHH",
        0x1000,              # SectionAlignment
        0x200,               # FileAlignment
        6, 0,                # OS version
        0, 0,                # Image version
        6, 0,                # Subsystem version
        0,                   # Win32VersionValue
        0x2000,              # SizeOfImage
        0x200,               # SizeOfHeaders
        0,                   # CheckSum
        3, 0,                # Subsystem = WINDOWS_CUI, DllCharacteristics
    )
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap reserve/commit
    opt += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    opt += b"\x00" * (16 * 8)  # 16 empty data directories
    assert len(opt) == opt_size, len(opt)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,               # VirtualSize
        0x1000,              # VirtualAddress
        0x200,               # SizeOfRawData
        0x200,               # PointerToRawData
        0, 0, 0, 0,          # relocations / line numbers
        0x60000020,          # CODE | EXECUTE | READ
    )

    headers = bytes(dos) + coff + opt + section
    headers += b"\x00" * (0x200 - len(headers))  # pad to SizeOfHeaders
    body = b"\xCC" * 0x200                        # int3 padding as "code"
    return headers + body


def _build_minimal_elf64() -> bytes:
    """A minimal pyelftools-parseable ELF64 executable: header + one PT_LOAD program
    header + [NULL, .text, .shstrtab] sections. No symtab => 'stripped'."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text = b"\x90" * 16  # NOPs

    ehsize = 64
    phentsize = 56
    shentsize = 64

    ph_off = ehsize                 # 64
    text_off = ph_off + phentsize   # 120
    shstr_off = text_off + len(text)
    sh_off = shstr_off + len(shstrtab)
    # 8-byte align section header table.
    pad = (-sh_off) % 8
    sh_off += pad

    text_name = 1            # offset of ".text" in shstrtab
    shstr_name = 7           # offset of ".shstrtab"

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    elf_header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,        # e_type = ET_EXEC
        0x3E,     # e_machine = x86-64
        1,        # e_version
        0x400078, # e_entry
        ph_off,   # e_phoff
        sh_off,   # e_shoff
        0,        # e_flags
        ehsize,   # e_ehsize
        phentsize,# e_phentsize
        1,        # e_phnum
        shentsize,# e_shentsize
        3,        # e_shnum (NULL, .text, .shstrtab)
        2,        # e_shstrndx
    )

    program_header = struct.pack(
        "<IIQQQQQQ",
        1,        # p_type = PT_LOAD
        5,        # p_flags = R+X
        0,        # p_offset
        0x400000, # p_vaddr
        0x400000, # p_paddr
        0x400000 + sh_off,  # p_filesz (cover whole file-ish)
        0x400000 + sh_off,  # p_memsz
        0x1000,   # p_align
    )

    null_sh = b"\x00" * shentsize
    text_sh = struct.pack(
        "<IIQQQQIIQQ",
        text_name, 1,         # sh_name, sh_type=PROGBITS
        0x6,                  # sh_flags = ALLOC | EXECINSTR
        0x400078,             # sh_addr
        text_off,             # sh_offset
        len(text),            # sh_size
        0, 0,                 # sh_link, sh_info
        16, 0,                # sh_addralign, sh_entsize
    )
    shstr_sh = struct.pack(
        "<IIQQQQIIQQ",
        shstr_name, 3,        # sh_name, sh_type=STRTAB
        0,                    # sh_flags
        0,                    # sh_addr
        shstr_off,            # sh_offset
        len(shstrtab),        # sh_size
        0, 0,
        1, 0,
    )

    blob = bytearray()
    blob += elf_header
    blob += program_header
    blob += text
    blob += shstrtab
    blob += b"\x00" * pad
    blob += null_sh + text_sh + shstr_sh
    return bytes(blob)


def _build_fake_apk() -> bytes:
    """An APK-shaped ZIP: AndroidManifest.xml entry, classes.dex carrying suspicious
    API markers, and a native lib. Not a valid AXML/DEX — exercises the zip/dex byte
    scanners and magic detection, not androguard."""
    buf = BytesIO()
    dex = (
        b"dex\n035\x00" + b"\x00" * 32
        + b"Landroid/telephony/SmsManager;sendTextMessage"
        + b"Ldalvik/system/DexClassLoader;"
        + b"Landroid/accessibilityservice/AccessibilityService;"
        + b"Ljava/lang/Runtime;->exec"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00placeholder-binary-axml")
        zf.writestr("classes.dex", dex)
        zf.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 16)
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 32)
        zf.writestr("resources.arsc", b"\x00" * 8)
    return buf.getvalue()


@pytest.fixture(scope="session")
def minimal_pe() -> bytes:
    return _build_minimal_pe32()


@pytest.fixture(scope="session")
def minimal_elf() -> bytes:
    return _build_minimal_elf64()


@pytest.fixture(scope="session")
def fake_apk() -> bytes:
    return _build_fake_apk()
