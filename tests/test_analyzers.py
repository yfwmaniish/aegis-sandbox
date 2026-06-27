"""Format analyzer + end-to-end runner tests against the synthetic fixtures."""

from __future__ import annotations

import importlib.util

import pytest

from aegis.static import analyze_bytes
from aegis.static.models import STATIC_SCHEMA_VERSION, FileType


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


pe_required = pytest.mark.skipif(not _have("pefile"), reason="pefile not installed")
elf_required = pytest.mark.skipif(not _have("elftools"), reason="pyelftools not installed")
apk_required = pytest.mark.skipif(not _have("androguard"), reason="androguard not installed")


class TestPE:
    @pe_required
    def test_pe_features(self, minimal_pe):
        r = analyze_bytes(minimal_pe, filename="t.exe")
        assert r.file_type == FileType.PE
        assert r.pe is not None
        assert "I386" in (r.pe.machine or "")
        assert any(s.name == ".text" for s in r.pe.sections)
        assert "pe" in r.analyzers_run
        assert not r.analyzer_errors

    @pe_required
    def test_pe_section_entropy_present(self, minimal_pe):
        r = analyze_bytes(minimal_pe)
        text = next(s for s in r.pe.sections if s.name == ".text")
        assert text.entropy is not None
        assert "EXECUTE" in text.flags


class TestELF:
    @elf_required
    def test_elf_features(self, minimal_elf):
        r = analyze_bytes(minimal_elf, filename="t.elf")
        assert r.file_type == FileType.ELF
        assert r.elf is not None
        assert r.elf.elf_type == "ET_EXEC"
        assert r.elf.arch == "x64"
        assert r.elf.is_stripped is True  # no .symtab
        assert any(s.name == ".text" for s in r.elf.sections)
        assert not r.analyzer_errors

    @elf_required
    def test_elf_stripped_indicator(self, minimal_elf):
        r = analyze_bytes(minimal_elf)
        assert any(i.id == "elf.stripped" for i in r.indicators)


class TestAPKZip:
    """Tests for the zip/dex byte scanners that do NOT require androguard."""

    def test_apk_detected_and_dex_scanned(self, fake_apk):
        from aegis.static.apk import _scan_dex_apis

        apis, dex_count, native = _scan_dex_apis(fake_apk)
        assert dex_count == 2
        assert any("SmsManager" in a for a in apis)
        assert any("DexClassLoader" in a for a in apis)
        assert any("AccessibilityService" in a for a in apis)
        assert native == ["lib/arm64-v8a/libnative.so"]

    @apk_required
    def test_apk_full_analyze(self, fake_apk):
        # Only runs where androguard is available (e.g. the worker image).
        r = analyze_bytes(fake_apk, filename="app.apk")
        assert r.file_type == FileType.APK
        assert r.apk is not None
        assert r.apk.dex_count == 2


class TestRunnerContract:
    def test_schema_version_stamped(self, minimal_pe):
        r = analyze_bytes(minimal_pe)
        assert r.schema_version == STATIC_SCHEMA_VERSION

    def test_unknown_type_still_reports(self):
        r = analyze_bytes(b"just some random bytes, not a binary " * 4)
        assert r.file_type == FileType.UNKNOWN
        assert r.pe is None and r.elf is None and r.apk is None
        assert r.hashes.sha256  # core extractors still ran
        assert r.entropy.overall > 0

    def test_serialises_to_json(self, minimal_pe):
        r = analyze_bytes(minimal_pe)
        payload = r.model_dump_json()
        assert '"schema_version"' in payload
        assert '"file_type":"pe"' in payload

    def test_indicators_sorted_by_severity(self, minimal_pe):
        r = analyze_bytes(minimal_pe)
        ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        seq = [ranks[i.severity.value] for i in r.indicators]
        assert seq == sorted(seq)
