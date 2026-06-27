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


def test_extension_hint_for_apk():
    import zipfile
    from io import BytesIO

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("stuff.bin", b"x")
    # No manifest, but .apk extension -> APK.
    assert detect_file_type(buf.getvalue(), filename="app.apk") == FileType.APK


def test_mime_mapping():
    assert "android" in mime_for(FileType.APK)
    assert mime_for(FileType.UNKNOWN) == "application/octet-stream"
