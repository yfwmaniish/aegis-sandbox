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

# Common false-positive domains/strings that show up in benign binaries.
_DOMAIN_ALLOWLIST = {
    "microsoft.com", "windows.com", "schemas.android.com", "w3.org", "apache.org",
    "google.com", "android.com", "gnu.org", "openssl.org", "mozilla.org",
    "schemas.xmlsoap.org", "verisign.com", "digicert.com", "example.com",
}

# Private / non-routable ranges — almost always noise as an IOC.
_PRIVATE_NETS = [
    ipaddress.ip_network(c)
    for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")
]

_RE = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]+", re.I),
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
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(ip in net for net in _PRIVATE_NETS)


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

    for m in _RE["url"].findall(text):
        add(IOC("url", m.rstrip(".,);]\"'"), 0.8, source))
    for m in _RE["domain"].findall(text):
        if _is_interesting_domain(m):
            add(IOC("domain", m.lower(), 0.5, source))
    for m in _RE["ipv4"].findall(text):
        if _is_public_ip(m):
            add(IOC("ip", m, 0.6, source))
    for m in _RE["email"].findall(text):
        add(IOC("email", m.lower(), 0.4, source))
    for m in _RE["btc"].findall(text):
        add(IOC("btc_address", m, 0.5, source))
    for m in _RE["registry"].findall(text):
        add(IOC("registry_key", m, 0.5, source))
    for m in _RE["path_win"].findall(text):
        add(IOC("file_path", m.rstrip(".,);\"'"), 0.3, source))
    for htype in ("sha256", "sha1", "md5"):
        for m in _RE[htype].findall(text):
            add(IOC(htype, m.lower(), 0.3, source))

    return sorted(found.values(), key=lambda i: (-i.confidence, i.type, i.value))
