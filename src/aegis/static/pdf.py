"""PDF static analysis — structure + dangerous-feature keyword scan (pdfid-style).

Dependency-free. Malicious PDFs are characterised less by their content than by the
*active* features they carry: JavaScript, automatic actions that fire on open, launch
actions that spawn programs, embedded files, and historically-exploited decoders. We
count these (decoding hex-obfuscated names like ``/J#61vaScript`` first) and raise
evidence-first indicators. IOC extraction over the raw bytes is handled by the runner.
"""

from __future__ import annotations

import re

from aegis.static.models import PDFFeatures, Severity, SuspiciousIndicator

_VERSION = re.compile(rb"%PDF-(\d\.\d)")
_OBJ = re.compile(rb"\b\d+\s+\d+\s+obj\b")
_HEXNAME = re.compile(rb"#([0-9A-Fa-f]{2})")

# Keyword -> the PDF token to count (leading slash included).
_KEYWORDS = {
    "javascript": b"/JavaScript", "js": b"/JS", "openaction": b"/OpenAction",
    "aa": b"/AA", "launch": b"/Launch", "embeddedfile": b"/EmbeddedFile",
    "uri": b"/URI", "acroform": b"/AcroForm", "xfa": b"/XFA",
    "richmedia": b"/RichMedia", "jbig2decode": b"/JBIG2Decode", "gotor": b"/GoToR",
    "objstm": b"/ObjStm", "encrypt": b"/Encrypt",
}


def _deobfuscate_names(data: bytes) -> bytes:
    """Decode ``#XX`` hex escapes in PDF names so obfuscated /J#61vaScript is counted."""
    return _HEXNAME.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def analyze(data: bytes) -> tuple[PDFFeatures, list[SuspiciousIndicator]]:
    norm = _deobfuscate_names(data)
    counts = {name: len(re.findall(re.escape(tok), norm)) for name, tok in _KEYWORDS.items()}

    vmatch = _VERSION.search(data)
    feats = PDFFeatures(
        version=vmatch.group(1).decode("ascii") if vmatch else None,
        object_count=len(_OBJ.findall(norm)),
        stream_count=len(re.findall(rb"\bstream\b", norm)),
        is_encrypted=counts["encrypt"] > 0,
        has_javascript=counts["javascript"] > 0 or counts["js"] > 0,
        js_count=counts["javascript"] + counts["js"],
        has_openaction=counts["openaction"] > 0,
        has_additional_actions=counts["aa"] > 0,
        has_launch=counts["launch"] > 0,
        has_embedded_files=counts["embeddedfile"] > 0,
        embedded_count=counts["embeddedfile"],
        has_uri=counts["uri"] > 0,
        has_acroform=counts["acroform"] > 0,
        has_xfa=counts["xfa"] > 0,
        has_richmedia=counts["richmedia"] > 0,
        has_jbig2=counts["jbig2decode"] > 0,
        has_gotor=counts["gotor"] > 0,
        keyword_counts={k: v for k, v in counts.items() if v},
    )

    ind: list[SuspiciousIndicator] = []
    auto = feats.has_openaction or feats.has_additional_actions

    if feats.has_javascript:
        ind.append(SuspiciousIndicator(
            id="pdf.javascript", title="PDF carries embedded JavaScript",
            severity=Severity.HIGH if auto else Severity.MEDIUM, confidence=0.75,
            observed_facts=[f"/JavaScript x{counts['javascript']}", f"/JS x{counts['js']}"],
            inference="JavaScript in a PDF is the primary vehicle for reader exploits and "
                      "for driving further actions; benign documents rarely need it.",
            evidence=["/JavaScript", "/JS"],
        ))
    if auto:
        ind.append(SuspiciousIndicator(
            id="pdf.auto_action", title="Automatic action fires when the PDF is opened",
            severity=Severity.HIGH if feats.has_javascript or feats.has_launch else Severity.MEDIUM,
            confidence=0.7,
            observed_facts=[k for k in ("/OpenAction" if feats.has_openaction else "",
                                        "/AA" if feats.has_additional_actions else "") if k],
            inference="An open/additional action auto-executes behaviour without user "
                      "interaction — combined with JavaScript or /Launch this is a classic "
                      "weaponised-document pattern.",
            evidence=["/OpenAction", "/AA"],
        ))
    if feats.has_launch:
        ind.append(SuspiciousIndicator(
            id="pdf.launch_action", title="PDF contains a /Launch action",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=[f"/Launch x{counts['launch']}"],
            inference="/Launch runs an external program/command from the document — almost "
                      "never legitimate and a well-known execution primitive.",
            evidence=["/Launch"],
        ))
    if feats.has_embedded_files:
        ind.append(SuspiciousIndicator(
            id="pdf.embedded_file", title="PDF embeds file(s)",
            severity=Severity.MEDIUM, confidence=0.6,
            observed_facts=[f"/EmbeddedFile x{counts['embeddedfile']}"],
            inference="Embedded files are used to smuggle a secondary payload inside the PDF.",
            evidence=["/EmbeddedFile"],
        ))
    if feats.has_jbig2 or feats.has_richmedia:
        ind.append(SuspiciousIndicator(
            id="pdf.exploit_surface", title="PDF uses an exploit-prone feature",
            severity=Severity.MEDIUM, confidence=0.55,
            observed_facts=[k for k in ("/JBIG2Decode" if feats.has_jbig2 else "",
                                        "/RichMedia" if feats.has_richmedia else "") if k],
            inference="JBIG2/RichMedia decoders have a history of memory-corruption CVEs "
                      "and are a common exploit surface.",
            evidence=["/JBIG2Decode", "/RichMedia"],
        ))
    return feats, ind
