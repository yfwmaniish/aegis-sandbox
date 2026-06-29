"""Magic-byte file-type detection tests."""

from __future__ import annotations

from aegis.static.dispatch import detect_file_type, mime_for
from aegis.static.models import FileType


def test_detect_pe(minimal_pe):
    assert detect_file_type(minimal_pe) == FileType.PE


def test_detect_elf(minimal_elf):
    assert detect_file_type(minimal_elf) == FileType.ELF


def test_detect_apk(fake_apk):
    # APK confirmed by AndroidManifest.xml + classes.dex inside the zip.
    assert detect_file_type(fake_apk) == FileType.APK


def test_detect_dex():
    assert detect_file_type(b"dex\n035\x00" + b"\x00" * 64) == FileType.DEX


def test_detect_macho():
    assert detect_file_type(b"\xcf\xfa\xed\xfe" + b"\x00" * 64) == FileType.MACHO


def test_plain_zip_is_not_apk():
    import zipfile
    from io import BytesIO

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"hello")
    assert detect_file_type(buf.getvalue()) == FileType.ZIP


def test_unknown():
    assert detect_file_type(b"not a real binary header") == FileType.UNKNOWN


def test_apk_extension_without_manifest_is_zip():
    # A .apk-named ZIP with no AndroidManifest.xml is NOT an installable APK — it is a
    # project/archive (e.g. apktool/APKEditor output) and must route to ZIP, not APK.
    import zipfile
    from io import BytesIO

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("original/com.example.apk", b"x")
        for i in range(60):
            zf.writestr(f"smali/com/x/C{i}.smali", b".class")
    assert detect_file_type(buf.getvalue(), filename="app.apk") == FileType.ZIP


def test_mime_mapping():
    assert "android" in mime_for(FileType.APK)
    assert mime_for(FileType.UNKNOWN) == "application/octet-stream"
