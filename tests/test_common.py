"""Unit tests for the format-independent extractors."""

from __future__ import annotations

import os

from aegis.static.common.entropy import (
    chunked_entropy,
    packing_likelihood,
    shannon_entropy,
)
from aegis.static.common.hashing import compute_hashes, sha256_hex
from aegis.static.common.iocs import extract_iocs
from aegis.static.common.strings import extract_strings


class TestEntropy:
    def test_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_uniform_is_zero(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_random_is_near_max(self):
        # 256 distinct bytes each once -> exactly 8.0 bits/byte.
        assert shannon_entropy(bytes(range(256))) == 8.0

    def test_text_is_mid_range(self):
        e = shannon_entropy(b"the quick brown fox jumps over the lazy dog" * 10)
        assert 3.0 < e < 5.5

    def test_chunked_bands(self):
        bands = chunked_entropy(b"A" * 5000, chunk_size=4096)
        assert len(bands) == 2
        assert bands[0].size == 4096 and bands[1].size == 904
        assert all(b.entropy == 0.0 for b in bands)

    def test_packing_likelihood(self):
        assert packing_likelihood(7.6, 0.8) == "high"
        assert packing_likelihood(6.6, 0.1) == "medium"
        assert packing_likelihood(4.0, 0.0) == "low"


class TestHashing:
    def test_known_sha256(self):
        # Well-known SHA256("") value.
        empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hex(b"") == empty
        assert compute_hashes(b"").sha256 == empty

    def test_all_digests_present(self):
        h = compute_hashes(b"aegis")
        assert len(h.sha256) == 64
        assert len(h.sha1) == 40
        assert len(h.md5) == 32

    def test_tlsh_optional(self):
        # tlsh may be absent (no wheel on Windows) -> None, never an error.
        h = compute_hashes(os.urandom(2048))
        assert h.tlsh is None or isinstance(h.tlsh, str)


class TestStrings:
    def test_extracts_ascii(self):
        data = b"\x00\x01hello world\x00\x02more text here\xff"
        out = extract_strings(data, min_len=4)
        assert "hello world" in out.ascii
        assert "more text here" in out.ascii

    def test_min_length_filter(self):
        out = extract_strings(b"ab\x00abcdef\x00", min_len=5)
        assert "abcdef" in out.ascii
        assert "ab" not in out.ascii

    def test_utf16(self):
        wide = "C:\\Windows\\System32".encode("utf-16-le")
        out = extract_strings(b"\x00" + wide + b"\x00", min_len=5)
        assert any("Windows" in s for s in out.unicode)

    def test_interesting_tags(self):
        data = b"connect to http://evil.example/c2 and call VirtualAlloc now\x00"
        out = extract_strings(data, min_len=4)
        assert "url" in out.interesting
        assert "api_hint" in out.interesting

    def test_truncation(self):
        # Many short distinct strings; cap forces truncation.
        blob = b"\x00".join(f"string{i:05d}".encode() for i in range(100))
        out = extract_strings(blob, min_len=4, max_count=10)
        assert out.truncated is True
        assert out.count <= 10


class TestIOCs:
    def test_url_and_domain(self):
        iocs = extract_iocs("visit http://malware.test/payload.bin or evilzone.xyz")
        types = {i.type for i in iocs}
        assert "url" in types
        assert any(i.type == "domain" and "evilzone.xyz" in i.value for i in iocs)

    def test_public_vs_private_ip(self):
        iocs = extract_iocs("c2 at 45.155.205.10 lan host 192.168.1.5 loopback 127.0.0.1 "
                            "resolver 8.8.8.8 netmask 255.255.255.0")
        ips = {i.value for i in iocs if i.type == "ip"}
        assert "45.155.205.10" in ips     # routable, non-resolver -> kept
        assert "192.168.1.5" not in ips   # private filtered
        assert "127.0.0.1" not in ips     # loopback filtered
        assert "8.8.8.8" not in ips       # well-known DNS resolver filtered
        assert "255.255.255.0" not in ips  # netmask/reserved filtered

    def test_domain_allowlist(self):
        iocs = extract_iocs("update.microsoft.com and sub.android.com")
        domains = {i.value for i in iocs if i.type == "domain"}
        assert not domains  # both allow-listed

    def test_hashes_and_btc(self):
        text = "drop e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        text += "pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        iocs = extract_iocs(text)
        assert any(i.type == "sha256" for i in iocs)
        assert any(i.type == "btc_address" for i in iocs)

    def test_dedup_keeps_highest_confidence(self):
        iocs = extract_iocs("45.155.205.10 45.155.205.10 45.155.205.10")
        assert sum(i.type == "ip" for i in iocs) == 1
