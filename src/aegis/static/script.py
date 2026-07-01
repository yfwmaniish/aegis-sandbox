"""Script static analysis — JS / VBScript / PowerShell / batch / HTA / WSF.

Dependency-free. Script droppers hide behaviour behind obfuscation (base64 blobs,
char-code arrays, string reversal/concat) and then reach for a small set of
download-and-execute primitives. We detect the language, score how obfuscated the text
is, and flag the suspicious APIs — separating what we observed from the inference.
"""

from __future__ import annotations

import re

from aegis.static.models import ScriptFeatures, Severity, SuspiciousIndicator

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_BLOB = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2},\s*){20,}")
_CHARCODE = re.compile(r"(?:fromCharCode|Chr[\$W]?\s*\(|\[char\])", re.I)

# api marker -> label. Matched case-insensitively over the text.
_SUSPICIOUS_APIS = {
    r"invoke-expression": "Invoke-Expression", r"\biex\b": "IEX",
    r"downloadstring": "DownloadString", r"downloadfile": "DownloadFile",
    r"net\.webclient": "Net.WebClient", r"start-bitstransfer": "Start-BitsTransfer",
    r"wscript\.shell": "WScript.Shell", r"shell\s*\(": "Shell()",
    r"createobject": "CreateObject", r"getobject": "GetObject",
    r"powershell": "powershell", r"-enc(odedcommand)?\b": "-EncodedCommand",
    r"frombase64string": "FromBase64String", r"\bcertutil\b": "certutil",
    r"\bbitsadmin\b": "bitsadmin", r"\bmshta\b": "mshta", r"\bregsvr32\b": "regsvr32",
    r"\brundll32\b": "rundll32", r"new-object": "New-Object",
    r"start-process": "Start-Process", r"\beval\s*\(": "eval()",
    r"\bunescape\s*\(": "unescape()", r"virtualalloc": "VirtualAlloc",
    r"\bcmd\.exe": "cmd.exe", r"urldownloadtofile": "URLDownloadToFile",
    r"xmlhttp": "XMLHTTP", r"adodb\.stream": "ADODB.Stream",
}

_LANG_MARKERS = [
    ("powershell", (r"\$\w+\s*=", r"-Encoded", r"Invoke-", r"\[System\.", r"Get-\w+")),
    ("vbscript", (r"\bDim\b", r"\bSet\b\s+\w+\s*=", r"WScript\.", r"CreateObject", r"\bSub\b")),
    ("batch", (r"@echo off", r"%~dp0", r"\bset /", r"\bgoto\b")),
    ("hta", (r"<hta:application", r"<html")),
    ("wsf", (r"<job", r"<script\s+language")),
    ("javascript", (r"\bfunction\b", r"\bvar\b", r"=>", r"document\.", r"ActiveXObject")),
]


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def _language(text: str, filename: str | None) -> str:
    if filename and "." in filename:
        from aegis.static.dispatch import _SCRIPT_EXTS
        lang = _SCRIPT_EXTS.get("." + filename.rsplit(".", 1)[-1].lower())
        if lang:
            return lang
    scores = {lang: sum(bool(re.search(p, text, re.I)) for p in pats)
              for lang, pats in _LANG_MARKERS}
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] else "unknown"


def analyze(data: bytes, filename: str | None = None) -> tuple[ScriptFeatures, list[SuspiciousIndicator]]:
    text = _decode(data)
    lang = _language(text, filename)
    lines = text.splitlines()

    b64 = _B64_BLOB.findall(text)
    longest_b64 = max((len(b) for b in b64), default=0)
    longest_line = max((len(ln) for ln in lines), default=0)

    obf: list[str] = []
    if longest_b64 >= 200:
        obf.append(f"base64 blob ({longest_b64} chars)")
    if _CHARCODE.search(text):
        obf.append("char-code assembly (fromCharCode/Chr)")
    if _HEX_BLOB.search(text):
        obf.append("hex byte array")
    if longest_line >= 1000:
        obf.append(f"very long line ({longest_line} chars)")
    concat = text.count('"+"') + text.count("'+'") + text.count("&\"")
    if concat >= 20:
        obf.append(f"heavy string concatenation (x{concat})")
    if re.search(r"-enc(odedcommand)?\b", text, re.I):
        obf.append("PowerShell -EncodedCommand")

    # 0..1 obfuscation score.
    score = min(1.0, 0.35 * bool(longest_b64 >= 200) + 0.2 * bool(_CHARCODE.search(text))
                + 0.2 * bool(_HEX_BLOB.search(text)) + 0.15 * (longest_line >= 1000)
                + 0.15 * (concat >= 20) + 0.2 * bool(re.search(r"-enc", text, re.I)))

    apis: list[str] = []
    for pat, label in _SUSPICIOUS_APIS.items():
        if re.search(pat, text, re.I):
            apis.append(label)
    apis = sorted(set(apis))

    feats = ScriptFeatures(
        language=lang, line_count=len(lines), char_count=len(text),
        obfuscation_score=round(score, 2), obfuscation_indicators=obf,
        suspicious_apis=apis, has_base64_blobs=bool(b64), longest_base64=longest_b64,
    )

    ind: list[SuspiciousIndicator] = []
    downloaders = {"DownloadString", "DownloadFile", "Net.WebClient", "URLDownloadToFile",
                   "Start-BitsTransfer", "XMLHTTP", "certutil", "bitsadmin"}
    runners = {"Invoke-Expression", "IEX", "eval()", "Shell()", "WScript.Shell",
               "Start-Process", "mshta", "rundll32", "regsvr32", "cmd.exe"}
    has_dl = bool(downloaders & set(apis))
    has_run = bool(runners & set(apis))

    if has_dl and has_run:
        ind.append(SuspiciousIndicator(
            id="script.download_exec", title="Download-and-execute pattern",
            severity=Severity.CRITICAL, confidence=0.85,
            observed_facts=sorted(downloaders & set(apis)) + sorted(runners & set(apis)),
            inference="The script both fetches remote content and executes code — the "
                      "defining behaviour of a script stager/dropper.",
            evidence=apis[:10],
        ))
    elif has_run or has_dl:
        ind.append(SuspiciousIndicator(
            id="script.suspicious_api", title="Script uses execution/download APIs",
            severity=Severity.HIGH, confidence=0.7,
            observed_facts=sorted((downloaders | runners) & set(apis)),
            inference="Shell/exec or network-download primitives in a script are rare in "
                      "benign automation and typical of malware.",
            evidence=apis[:10],
        ))

    if "-EncodedCommand" in apis or any("EncodedCommand" in o for o in obf):
        ind.append(SuspiciousIndicator(
            id="script.encoded_command", title="PowerShell encoded command",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=["-EncodedCommand / -enc"],
            inference="Base64-encoded PowerShell hides the real command from casual "
                      "inspection and logging — a common evasion.",
            evidence=["-enc"],
        ))

    if score >= 0.5 and not (has_dl or has_run):
        ind.append(SuspiciousIndicator(
            id="script.obfuscated", title="Heavily obfuscated script",
            severity=Severity.MEDIUM, confidence=0.6,
            observed_facts=obf,
            inference="Dense obfuscation (encoded blobs / char-code assembly) conceals "
                      "intent and is uncommon in legitimate scripts.",
            evidence=obf,
        ))
    return feats, ind
