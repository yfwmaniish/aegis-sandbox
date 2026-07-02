"""RTF static analysis — embedded OLE objects + exploit indicators.

RTF is a text control-word format; malicious RTFs smuggle OLE objects (embedded
executables/packages) or trigger the Equation Editor exploits (CVE-2017-11882 /
CVE-2018-0802). We scan control words and decode ``\\objdata`` hex to spot an embedded
PE. Dependency-free.
"""

from __future__ import annotations

import re

from aegis.static.models import RTFFeatures, Severity, SuspiciousIndicator

_OBJDATA = re.compile(rb"\\objdata[^{}]*?([0-9A-Fa-f\s]{16,})", re.DOTALL)
_WS = re.compile(rb"\s+")


def _hex_has_pe(blob: bytes) -> bool:
    """True if the decoded hex begins like / contains an MZ...PE executable."""
    try:
        raw = bytes.fromhex(_WS.sub(b"", blob[:200000]).decode("ascii", "ignore"))
    except ValueError:
        return False
    return raw[:2] == b"MZ" or b"MZ\x90\x00" in raw[:4096] or b"This program cannot" in raw


def analyze(data: bytes) -> tuple[RTFFeatures, list[SuspiciousIndicator]]:
    low = data.lower()
    feats = RTFFeatures(
        object_count=low.count(b"\\object"),
        has_ole_object=b"\\objdata" in low or b"\\objclass" in low,
        has_equation=b"equation.3" in low or b"equation native" in low or b"eqnedt32" in low,
        has_embedded_package=b"\\objclass package" in low or b"package\x00" in low,
    )
    cw = []
    for w in (b"\\objdata", b"\\objupdate", b"\\objautlink", b"\\objemb", b"\\datastore",
              b"\\*\\template"):
        if w in low:
            cw.append(w.decode("ascii").lstrip("\\"))
    feats.control_words = cw

    m = _OBJDATA.search(data)
    if m and _hex_has_pe(m.group(1)):
        feats.embedded_pe = True

    ind: list[SuspiciousIndicator] = []
    if feats.has_equation:
        ind.append(SuspiciousIndicator(
            id="rtf.equation_exploit", title="RTF references the Equation Editor",
            severity=Severity.CRITICAL, confidence=0.85,
            observed_facts=["Equation.3 / EQNEDT32 / Equation Native"],
            inference="Equation Editor objects in RTF are almost exclusively CVE-2017-11882/"
                      "CVE-2018-0802 exploit delivery — a hands-off code-execution primitive.",
            evidence=["Equation Native"],
        ))
    if feats.embedded_pe:
        ind.append(SuspiciousIndicator(
            id="rtf.embedded_executable", title="RTF embeds a PE executable in \\objdata",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=["MZ header in decoded \\objdata"],
            inference="An executable hex-encoded inside an object stream is a staged payload.",
            evidence=["\\objdata -> MZ"],
        ))
    if feats.has_ole_object and not (feats.has_equation or feats.embedded_pe):
        ind.append(SuspiciousIndicator(
            id="rtf.ole_object", title="RTF contains an embedded OLE object",
            severity=Severity.MEDIUM, confidence=0.55,
            observed_facts=feats.control_words or ["\\object"],
            inference="Embedded OLE objects are used to smuggle payloads or trigger "
                      "handlers; benign documents rarely embed them.",
            evidence=feats.control_words or ["\\objclass"],
        ))
    return feats, ind
