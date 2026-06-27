"""Printable-string extraction (ASCII + UTF-16LE) with lightweight categorisation.

Strings are the cheapest high-signal static feature: URLs, file paths, registry
keys, command lines, crypto constants and library names all leak here. We extract
both ASCII and UTF-16LE (Windows wide strings) and tag the interesting ones so the
IOC extractor and report can pivot quickly (Program Doc §6.1 "strings").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_MIN_LEN = 5
DEFAULT_MAX_COUNT = 50_000

# Printable ASCII run (space..~ plus tab).
_ASCII_RE = re.compile(rb"[\x09\x20-\x7e]{%d,}")
# UTF-16LE: printable ASCII char followed by a NUL byte, repeated.
_UTF16_RE = re.compile(rb"(?:[\x09\x20-\x7e]\x00){%d,}")

# Heuristic taggers — purely for analyst triage, not authoritative IOCs.
_TAGGERS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"\bhttps?://", re.I)),
    ("ip", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("path_win", re.compile(r"[A-Za-z]:\\\\?[^\s\"']+|\\\\[^\s\"']+")),
    ("path_unix", re.compile(r"(?:/[\w.\-]+){2,}")),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\", re.I)),
    ("dll", re.compile(r"\b\w+\.dll\b", re.I)),
    ("api_hint", re.compile(r"\b(?:VirtualAlloc|CreateRemoteThread|LoadLibrary|GetProcAddress|"
                            r"WriteProcessMemory|WinExec|ShellExecute|URLDownloadToFile|"
                            r"CreateProcess|RegSetValue|CryptEncrypt|socket|connect)\w*\b")),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
]


@dataclass(slots=True)
class ExtractedStrings:
    ascii: list[str] = field(default_factory=list)
    unicode: list[str] = field(default_factory=list)
    count: int = 0
    truncated: bool = False
    # tag -> sample of matching strings (deduped, capped)
    interesting: dict[str, list[str]] = field(default_factory=dict)

    def all(self) -> list[str]:
        return [*self.ascii, *self.unicode]


def _decode_utf16(match: bytes) -> str:
    try:
        return match.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return ""


def extract_strings(
    data: bytes,
    min_len: int = DEFAULT_MIN_LEN,
    max_count: int = DEFAULT_MAX_COUNT,
) -> ExtractedStrings:
    """Extract ASCII + UTF-16LE strings of at least ``min_len`` chars.

    Caps total output at ``max_count`` to bound memory/latency on huge files
    (TR-TEL/SLO: bounded work per sample); sets ``truncated`` when the cap is hit.
    """
    ascii_re = re.compile(_ASCII_RE.pattern % min_len)
    utf16_re = re.compile(_UTF16_RE.pattern % min_len)

    ascii_strings = [m.decode("ascii", "ignore") for m in ascii_re.findall(data)]

    unicode_strings: list[str] = []
    for m in utf16_re.findall(data):
        s = _decode_utf16(m)
        if len(s) >= min_len:
            unicode_strings.append(s)

    truncated = False
    total = len(ascii_strings) + len(unicode_strings)
    if total > max_count:
        truncated = True
        # Keep a proportional slice of each so we don't drop one kind entirely.
        keep_ascii = max(1, int(max_count * len(ascii_strings) / total))
        ascii_strings = ascii_strings[:keep_ascii]
        unicode_strings = unicode_strings[: max_count - len(ascii_strings)]

    result = ExtractedStrings(
        ascii=ascii_strings,
        unicode=unicode_strings,
        count=len(ascii_strings) + len(unicode_strings),
        truncated=truncated,
    )
    result.interesting = _tag_interesting(result.all())
    return result


def _tag_interesting(strings: list[str], per_tag_cap: int = 200) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for s in strings:
        for tag, pat in _TAGGERS:
            if pat.search(s):
                bucket = buckets.setdefault(tag, [])
                seen_set = seen.setdefault(tag, set())
                if s not in seen_set and len(bucket) < per_tag_cap:
                    bucket.append(s)
                    seen_set.add(s)
    return buckets
