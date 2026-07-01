"""Office document static analysis — VBA macros + weaponisation heuristics.

Handles both legacy OLE (.doc/.xls/.ppt) and OOXML (.docx/.xlsm/.pptm). The malicious
signal is: does it carry macros, do they auto-run on open, do they reach for shell/
download primitives, and does the document pull a remote template or use DDE?

Macro *source* recovery uses ``oletools`` (olevba) when installed; without it we degrade
to a byte-scan of the macro streams for the same keywords (best-effort, never fatal).
"""

from __future__ import annotations

import re
import zipfile
from io import BytesIO

from aegis.static.models import OfficeFeatures, Severity, SuspiciousIndicator

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_AUTO_EXEC = [
    "AutoOpen", "Auto_Open", "AutoExec", "AutoClose", "AutoNew", "Document_Open",
    "DocumentOpen", "Workbook_Open", "Workbook_Activate", "Document_Close",
    "Auto_Close", "Worksheet_Activate",
]
_SUSPICIOUS = [
    "Shell", "WScript", "powershell", "cmd.exe", "CreateObject", "GetObject",
    "URLDownloadToFile", "XMLHTTP", "WinHttp", "ADODB.Stream", "Environ",
    "CreateProcess", "VirtualAlloc", "CallByName", "StrReverse", "Chr(",
    "ExecQuery", "MSXML2", "ServerXMLHTTP", "Base64", "FileSystemObject",
    "SaveToFile", "Run ", "ShellExecute", "RegWrite", "Kill ",
]


def _scan_keywords(text: str) -> tuple[list[str], list[str]]:
    auto = [k for k in _AUTO_EXEC if k.lower() in text.lower()]
    susp = [k for k in _SUSPICIOUS if k.lower() in text.lower()]
    return auto, susp


def _macro_source_via_oletools(data: bytes) -> tuple[bool, str, list[str], int]:
    """Return (found, combined_source, module_names, line_count) using olevba if present."""
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except ImportError:
        return False, "", [], 0
    try:
        vp = VBA_Parser("sample", data=data)
        if not vp.detect_vba_macros():
            vp.close()
            return False, "", [], 0
        src_parts: list[str] = []
        modules: list[str] = []
        for _fn, _stream, vba_name, code in vp.extract_macros():
            if code:
                src_parts.append(code)
                modules.append(vba_name or _stream)
        vp.close()
        src = "\n".join(src_parts)
        return True, src, modules, src.count("\n") + (1 if src else 0)
    except Exception:  # noqa: BLE001 - degrade to byte-scan
        return False, "", [], 0


def _ooxml_info(data: bytes) -> tuple[str | None, bool, list[str], list[str]]:
    """Return (doc_type, has_vba, macro_bins, external_targets) for an OOXML package."""
    doc_type = None
    has_vba = False
    macro_bins: list[str] = []
    external: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
            if any(n.startswith("word/") for n in names):
                doc_type = "word"
            elif any(n.startswith("xl/") for n in names):
                doc_type = "excel"
            elif any(n.startswith("ppt/") for n in names):
                doc_type = "powerpoint"
            for n in names:
                if n.endswith("vbaProject.bin"):
                    has_vba = True
                    macro_bins.append(n)
                if n.endswith(".rels"):
                    try:
                        rel = zf.read(n).decode("utf-8", "replace")
                    except KeyError:
                        continue
                    # External relationships (remote templates / links).
                    for m in re.finditer(r'Target="([^"]+)"[^>]*TargetMode="External"', rel):
                        external.append(m.group(1))
                    if 'attachedTemplate' in rel:
                        for m in re.finditer(r'Target="(https?://[^"]+)"', rel):
                            external.append(m.group(1))
    except (zipfile.BadZipFile, OSError):
        pass
    return doc_type, has_vba, macro_bins, sorted(set(external))


def analyze(data: bytes) -> tuple[OfficeFeatures, list[SuspiciousIndicator]]:
    is_ole = data[:8] == _OLE_MAGIC
    feats = OfficeFeatures(container="ole" if is_ole else "ooxml")

    # Recover macro source (olevba) or fall back to scanning raw macro bytes.
    found, source, modules, lines = _macro_source_via_oletools(data)
    if is_ole:
        feats.doc_type = _ole_doc_type(data)
        if not found:
            source = data.decode("latin-1", "replace")  # byte-scan fallback
    else:
        doc_type, has_vba, macro_bins, external = _ooxml_info(data)
        feats.doc_type = doc_type
        feats.external_targets = external
        if not found:
            feats.macro_streams = macro_bins
            if has_vba:
                source = _read_macro_bins(data, macro_bins)
        else:
            feats.macro_streams = modules

    if found:
        feats.vba_extracted = True
        feats.macro_streams = modules or feats.macro_streams
        feats.macro_line_count = lines

    auto, susp = _scan_keywords(source)
    # Only treat auto/suspicious as "macro" evidence when macros are actually present.
    has_macros = found or bool(feats.macro_streams) or (is_ole and bool(auto or susp))
    feats.has_macros = has_macros
    feats.auto_exec = auto if has_macros else []
    feats.suspicious_keywords = susp if has_macros else []
    feats.has_dde = bool(re.search(r"DDEAUTO|\bDDE\b", source, re.I)) if source else False

    ind: list[SuspiciousIndicator] = []
    if has_macros:
        ind.append(SuspiciousIndicator(
            id="office.macros_present", title="Document contains VBA macros",
            severity=Severity.MEDIUM, confidence=0.6,
            observed_facts=feats.macro_streams[:6] or ["VBA project present"],
            inference="Macros are the dominant delivery mechanism for document-based "
                      "malware; a document that needs them is inherently higher-risk.",
            evidence=feats.macro_streams[:6] or ["vbaProject"],
        ))
    if feats.auto_exec:
        ind.append(SuspiciousIndicator(
            id="office.auto_exec_macro", title="Macro auto-executes on open",
            severity=Severity.HIGH, confidence=0.75,
            observed_facts=feats.auto_exec,
            inference="AutoOpen/Document_Open/Workbook_Open run code the moment the file "
                      "is opened — no further user action needed.",
            evidence=feats.auto_exec,
        ))
    dangerous = [k for k in feats.suspicious_keywords
                 if k.lower() in ("shell", "powershell", "wscript", "cmd.exe",
                                  "urldownloadtofile", "createobject", "shellexecute",
                                  "xmlhttp", "winhttp", "adodb.stream", "createprocess")]
    if dangerous:
        ind.append(SuspiciousIndicator(
            id="office.suspicious_macro", title="Macro uses shell/download primitives",
            severity=Severity.CRITICAL if feats.auto_exec else Severity.HIGH, confidence=0.8,
            observed_facts=dangerous,
            inference="Spawning a shell / downloading a payload from a macro is the core of "
                      "a maldoc dropper; combined with auto-exec it is a complete attack.",
            evidence=dangerous,
        ))
    if feats.external_targets:
        ind.append(SuspiciousIndicator(
            id="office.remote_template", title="Document references a remote target/template",
            severity=Severity.HIGH, confidence=0.7,
            observed_facts=feats.external_targets[:6],
            inference="Remote template injection pulls a malicious template at open time, "
                      "keeping the delivered document itself clean.",
            evidence=feats.external_targets[:6],
        ))
    if feats.has_dde:
        ind.append(SuspiciousIndicator(
            id="office.dde", title="Document uses DDE",
            severity=Severity.HIGH, confidence=0.65,
            observed_facts=["DDE / DDEAUTO field"],
            inference="DDE fields execute external commands without macros — a macro-less "
                      "code-execution technique.",
            evidence=["DDEAUTO"],
        ))
    return feats, ind


def _ole_doc_type(data: bytes) -> str | None:
    low = data[:8192].lower()
    if b"word.document" in low or b"msworddoc" in low:
        return "word"
    if b"excel" in low or b"workbook" in low:
        return "excel"
    if b"powerpoint" in low:
        return "powerpoint"
    return None


def _read_macro_bins(data: bytes, names: list[str]) -> str:
    parts: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for n in names:
                try:
                    parts.append(zf.read(n).decode("latin-1", "replace"))
                except KeyError:
                    continue
    except (zipfile.BadZipFile, OSError):
        return ""
    return "\n".join(parts)
