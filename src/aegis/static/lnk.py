"""Windows shortcut (.lnk) static analysis — a top initial-access vector.

Parses the MS-SHLLINK structure enough to recover the fields that matter for detection:
the **command-line arguments** and target/working dir. Malicious LNKs point at
``powershell``/``cmd``/``mshta``/``rundll32`` with encoded or download-and-run arguments;
the argument string is the payload. Bounds-checked so a malformed shortcut degrades to
partial features rather than raising.
"""

from __future__ import annotations

import struct

from aegis.static.models import LNKFeatures, Severity, SuspiciousIndicator

# LinkFlags bits (MS-SHLLINK 2.1).
_HAS_TARGET_IDLIST = 0x0001
_HAS_LINKINFO = 0x0002
_HAS_NAME = 0x0004
_HAS_RELATIVE_PATH = 0x0008
_HAS_WORKING_DIR = 0x0010
_HAS_ARGUMENTS = 0x0020
_HAS_ICON = 0x0040
_IS_UNICODE = 0x0080

_LIVING_OFF_LAND = ("powershell", "pwsh", "cmd.exe", "cmd ", "/c ", "mshta", "rundll32",
                    "regsvr32", "wscript", "cscript", "bitsadmin", "certutil", "curl",
                    "msiexec", "installutil", "wmic")
_DOWNLOAD_RUN = ("downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "iex",
                 "invoke-expression", "-enc", "-encodedcommand", "frombase64string",
                 "http://", "https://", "start-process", "webclient")


def _read_string(data: bytes, off: int, unicode: bool) -> tuple[str | None, int]:
    """StringData: 2-byte character count, then the (ansi/unicode) chars."""
    if off + 2 > len(data):
        return None, off
    count = struct.unpack_from("<H", data, off)[0]
    off += 2
    nbytes = count * (2 if unicode else 1)
    raw = data[off:off + nbytes]
    off += nbytes
    text = raw.decode("utf-16-le" if unicode else "latin-1", "replace")
    return text, off


def analyze(data: bytes) -> tuple[LNKFeatures, list[SuspiciousIndicator]]:
    feats = LNKFeatures()
    if len(data) < 76 or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return feats, []
    flags = struct.unpack_from("<I", data, 20)[0]
    unicode = bool(flags & _IS_UNICODE)
    feats.is_unicode = unicode
    feats.flags = [n for n, b in (
        ("TargetIDList", _HAS_TARGET_IDLIST), ("LinkInfo", _HAS_LINKINFO),
        ("Name", _HAS_NAME), ("RelativePath", _HAS_RELATIVE_PATH),
        ("WorkingDir", _HAS_WORKING_DIR), ("Arguments", _HAS_ARGUMENTS),
        ("IconLocation", _HAS_ICON)) if flags & b]

    off = 76
    if flags & _HAS_TARGET_IDLIST and off + 2 <= len(data):
        idlist_size = struct.unpack_from("<H", data, off)[0]
        off += 2 + idlist_size
    if flags & _HAS_LINKINFO and off + 4 <= len(data):
        linkinfo_size = struct.unpack_from("<I", data, off)[0]
        off += max(linkinfo_size, 4)

    for bit, attr in ((_HAS_NAME, None), (_HAS_RELATIVE_PATH, "relative_path"),
                      (_HAS_WORKING_DIR, "working_dir"), (_HAS_ARGUMENTS, "arguments"),
                      (_HAS_ICON, "icon_location")):
        if flags & bit and off < len(data):
            text, off = _read_string(data, off, unicode)
            if attr and text is not None:
                setattr(feats, attr, text[:1000])
    feats.target = feats.relative_path

    ind: list[SuspiciousIndicator] = []
    args = (feats.arguments or "")
    low = args.lower()
    lol = [t for t in _LIVING_OFF_LAND if t in low]
    dlrun = [t for t in _DOWNLOAD_RUN if t in low]

    if lol and (dlrun or "-enc" in low or len(args) > 200):
        ind.append(SuspiciousIndicator(
            id="lnk.command_execution", title="Shortcut launches a script/download command",
            severity=Severity.CRITICAL if dlrun else Severity.HIGH, confidence=0.85,
            observed_facts=[f"target: {feats.target or '?'}", f"args: {args[:200]}"],
            inference="A .lnk that runs powershell/cmd/mshta with encoded or download "
                      "arguments is a classic initial-access dropper, not a real shortcut.",
            evidence=sorted(set(lol + dlrun)),
        ))
    elif lol:
        ind.append(SuspiciousIndicator(
            id="lnk.interpreter", title="Shortcut targets a command interpreter",
            severity=Severity.HIGH, confidence=0.7,
            observed_facts=[f"args: {args[:200]}"] if args else [f"target: {feats.target or '?'}"],
            inference="Legitimate shortcuts point at applications, not at "
                      "powershell/cmd/rundll32 with arguments.",
            evidence=sorted(set(lol)),
        ))
    return feats, ind
