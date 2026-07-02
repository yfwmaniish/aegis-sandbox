"""HTML smuggling detection.

HTML smuggling hides a payload as a JavaScript-embedded blob (often base64) that the
page reconstructs client-side and triggers a download — bypassing network content
filters because the bytes are assembled in the browser. We look for the co-occurrence of
a large encoded blob and the Blob/download reconstruction APIs. Dependency-free.
"""

from __future__ import annotations

import re

from aegis.static.models import HTMLFeatures, Severity, SuspiciousIndicator

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{500,}={0,2}")
_BLOB_API = re.compile(r"new\s+Blob|msSave(?:OrOpen)?Blob|URL\.createObjectURL|Uint8Array",
                       re.I)
_DOWNLOAD_ATTR = re.compile(r"<a\b[^>]*\bdownload\b", re.I)
_DATA_URI = re.compile(r"""(?:href|src)\s*=\s*['"]?data:[^;]+;base64,""", re.I)


def analyze(data: bytes) -> tuple[HTMLFeatures, list[SuspiciousIndicator]]:
    text = data.decode("utf-8", "replace")
    blobs = _B64_BLOB.findall(text)
    longest = max((len(b) for b in blobs), default=0)

    feats = HTMLFeatures(
        has_base64_blob=bool(blobs),
        longest_base64=longest,
        has_blob_api=bool(_BLOB_API.search(text)),
        has_download_attr=bool(_DOWNLOAD_ATTR.search(text)),
        has_data_uri=bool(_DATA_URI.search(text)),
        has_octet_stream="application/octet-stream" in text.lower(),
    )
    reasons = []
    if feats.longest_base64:
        reasons.append(f"base64 blob ({feats.longest_base64} chars)")
    if feats.has_blob_api:
        reasons.append("Blob/createObjectURL reconstruction")
    if feats.has_download_attr:
        reasons.append("<a download>")
    if feats.has_data_uri:
        reasons.append("data: URI")
    if feats.has_octet_stream:
        reasons.append("octet-stream")
    if "atob(" in text.lower():
        reasons.append("atob() decode")
    if "fromcharcode" in text.lower():
        reasons.append("fromCharCode assembly")
    feats.indicators = reasons

    score = min(1.0, 0.4 * bool(feats.longest_base64 >= 500) + 0.3 * feats.has_blob_api
                + 0.2 * feats.has_download_attr + 0.15 * feats.has_data_uri
                + 0.15 * feats.has_octet_stream + 0.15 * ("atob(" in text.lower()))
    feats.smuggling_score = round(score, 2)

    ind: list[SuspiciousIndicator] = []
    strong = feats.longest_base64 >= 500 and (feats.has_blob_api or feats.has_download_attr
                                              or feats.has_octet_stream)
    if strong:
        ind.append(SuspiciousIndicator(
            id="html.smuggling", title="HTML smuggling pattern",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=reasons,
            inference="A large encoded blob reconstructed into a file and offered for "
                      "download in-browser is the defining pattern of HTML smuggling, used "
                      "to slip payloads past content filters.",
            evidence=reasons,
        ))
    elif feats.has_blob_api and feats.longest_base64:
        ind.append(SuspiciousIndicator(
            id="html.suspicious_script", title="HTML builds a binary blob in script",
            severity=Severity.MEDIUM, confidence=0.55,
            observed_facts=reasons,
            inference="Client-side blob assembly from encoded data is uncommon in benign "
                      "pages and is a building block of smuggling.",
            evidence=reasons,
        ))
    return feats, ind
