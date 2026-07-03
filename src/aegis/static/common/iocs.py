"""Indicator-of-Compromise extraction from raw bytes / strings.

Produces candidate IOCs (domains, IPs, URLs, emails, file paths, hashes, Bitcoin
addresses) with a source tag and a coarse confidence (SRS FR-10.1/10.2). These are
*candidates* — defanging, allow-listing and analyst review happen downstream. We bias
toward recall here and let the confidence field + dedupe carry triage weight.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Common false-positive domains/strings that show up in benign binaries. These are
# schema/namespace/vendor hosts, not indicators — matched as an exact host or 2-label
# registrable suffix.
_DOMAIN_ALLOWLIST = {
    "microsoft.com", "windows.com", "schemas.android.com", "w3.org", "apache.org",
    "google.com", "android.com", "gnu.org", "openssl.org", "mozilla.org",
    "schemas.xmlsoap.org", "verisign.com", "digicert.com", "example.com",
    "schemas.microsoft.com", "adobe.com", "ns.adobe.com", "xmlpull.org", "java.sun.com",
    "purl.org", "iptc.org", "sun.com", "oracle.com", "googleapis.com", "gstatic.com",
    "goo.gl", "g.co", "bit.ly", "fabric.io", "crashlytics.com", "facebook.com",
}
# Substrings that mark a URL as a benign schema/namespace/SDK reference, not an IOC.
_BENIGN_URL_HOSTS = (
    "schemas.android.com", "schemas.microsoft.com", "ns.adobe.com", "w3.org",
    "apache.org", "xmlpull.org", "java.sun.com", "javax.xml", "purl.org", "iptc.org",
    "specification", "openxmlformats.org", "docbook.org", "jquery.com", "googleapis.com",
    "gstatic.com", "schemas.openxmlformats", "www.w3", "xml.org",
)

# Well-known public DNS resolvers — appear in privacy/VPN apps, not C2.
_DNS_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4",
    "76.76.2.0", "76.76.10.0", "94.140.14.14", "94.140.15.15", "64.6.64.6", "64.6.65.6",
    "185.228.168.9", "77.88.8.8", "156.154.70.1", "156.154.71.1",
}

# Context words that mean a dotted-quad is a version/build string, not an IP.
_VERSION_CTX = re.compile(
    r"(?i)(version|ver\.|\bv\d|sdk|build|release|revision|\brev\b|library|copyright|"
    r"\bapi\b|schema|namespace|dtd|ns/)")

_RE = {
    # Exclude control chars AND high bytes (0x7f-0xff) so binary string-table junk
    # (e.g. "http://w�…") doesn't bleed into a URL — URLs are ASCII.
    "url": re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}\x00-\x1f\x7f-\xff]+", re.I),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|app|dev|co|me|"
        r"tk|ml|ga|cf|gq|pw|cc|su|gov|edu|mil|de|uk|fr|nl|br|in|ir|kp)\b",
        re.I,
    ),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "path_win": re.compile(r"\b[A-Za-z]:\\(?:[^\\\s\"'<>|]+\\?)+"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]+", re.I),
}


@dataclass(frozen=True, slots=True)
class IOC:
    type: str
    value: str
    confidence: float
    source: str  # e.g. "strings", "pe.imports", "apk.manifest"

    def key(self) -> tuple[str, str]:
        return (self.type, self.value.lower())


def _is_public_ip(value: str) -> bool:
    """A globally-routable, non-reserved unicast IP that isn't a well-known DNS resolver.

    ``is_global`` already rejects private/loopback/link-local/multicast/reserved ranges,
    which covers netmasks (255.255.255.0 is reserved) and 0.0.0.0/8 — the classic
    dotted-quad false positives."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not getattr(ip, "is_global", False):
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
        return False
    return value not in _DNS_RESOLVERS


def _url_is_benign(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in _BENIGN_URL_HOSTS)


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _valid_btc(addr: str) -> bool:
    """Validate a base58check Bitcoin address (checksum) to kill false positives — random
    base58-looking tokens (class names, hashes) otherwise match the loose regex."""
    if addr.startswith("bc1"):
        return len(addr) >= 14   # bech32; distinctive prefix, low FP — accept
    try:
        num = 0
        for ch in addr:
            num = num * 58 + _B58_ALPHABET.index(ch)
    except ValueError:
        return False
    raw = num.to_bytes(25, "big", signed=False) if num < 256**25 else b""
    # account for leading '1' -> leading 0x00 bytes
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw.lstrip(b"\x00")
    if len(raw) != 25:
        return False
    import hashlib
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _url_host_ok(url: str) -> bool:
    """A real URL has a host with a dot (domain) or a bare IP — rejects junk like
    'http://w' left over after trimming binary bytes."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "")
    if not host:
        return False
    if "." in host:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ip_is_versiony(text: str, start: int, end: int) -> bool:
    """True if a dotted-quad at [start:end] is really a version/build string, not an IP:
    it sits inside a longer dotted-number sequence or next to version-ish context."""
    before = text[max(0, start-18):start]
    after = text[end:end+3]
    if before[-1:] == "." and before[-2:-1].isdigit():   # ...N.  -> part of a.b.c.d.e
        return True
    if after[:1] == "." and after[1:2].isdigit():        # d.e    -> longer sequence
        return True
    return bool(_VERSION_CTX.search(before))


def _is_interesting_domain(value: str) -> bool:
    v = value.lower().rstrip(".")
    if v in _DOMAIN_ALLOWLIST:
        return False
    # Strip to registrable-ish suffix for allowlist check (foo.microsoft.com -> microsoft.com).
    parts = v.split(".")
    return not (len(parts) >= 2 and ".".join(parts[-2:]) in _DOMAIN_ALLOWLIST)


def extract_iocs(text: str, source: str = "strings") -> list[IOC]:
    """Extract deduplicated candidate IOCs from a text blob.

    ``text`` is typically the concatenation of extracted strings, but any caller
    (a PE import table, an APK manifest) can pass its own text and ``source`` tag
    so each IOC keeps provenance (SRS FR-10.2)."""
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc: IOC) -> None:
        existing = found.get(ioc.key())
        if existing is None or ioc.confidence > existing.confidence:
            found[ioc.key()] = ioc

    for m in _RE["url"].finditer(text):
        u = m.group(0).rstrip(".,);]\"'")
        if _url_host_ok(u) and not _url_is_benign(u):
            add(IOC("url", u, 0.8, source))
    for m in _RE["domain"].findall(text):
        if _is_interesting_domain(m):
            add(IOC("domain", m.lower(), 0.5, source))
    for m in _RE["ipv4"].finditer(text):
        v = m.group(0)
        if _is_public_ip(v) and not _ip_is_versiony(text, m.start(), m.end()):
            add(IOC("ip", v, 0.6, source))
    for m in _RE["email"].findall(text):
        add(IOC("email", m.lower(), 0.4, source))
    for m in _RE["btc"].findall(text):
        if _valid_btc(m):
            add(IOC("btc_address", m, 0.5, source))
    for m in _RE["registry"].findall(text):
        add(IOC("registry_key", m, 0.5, source))
    for m in _RE["path_win"].findall(text):
        add(IOC("file_path", m.rstrip(".,);\"'"), 0.3, source))
    for htype in ("sha256", "sha1", "md5"):
        for m in _RE[htype].findall(text):
            add(IOC(htype, m.lower(), 0.3, source))

    return sorted(found.values(), key=lambda i: (-i.confidence, i.type, i.value))
