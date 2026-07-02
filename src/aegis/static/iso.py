"""ISO/disk-image static analysis — Mark-of-the-Web bypass container.

ISO (and IMG/VHD) files are increasingly used to deliver malware: mounting one drops the
contents *without* the Mark-of-the-Web that would otherwise warn the user, so a `.lnk` or
`.exe` inside runs with fewer prompts. Full ISO-9660 parsing is out of scope; we read the
Primary Volume Descriptor for the label and scan the raw image for suspicious embedded
filenames (`.lnk/.exe/.bat/.vbs/.ps1/.js/.scr`). Dependency-free.
"""

from __future__ import annotations

import re

from aegis.static.models import ISOFeatures, Severity, SuspiciousIndicator

_PVD_OFFSET = 0x8000  # Primary Volume Descriptor
_FILENAME = re.compile(rb"[\w \-\.\(\)]{1,60}\.(?:lnk|exe|bat|vbs|ps1|js|jse|scr|cmd|hta|wsf|dll)",
                       re.I)


def analyze(data: bytes) -> tuple[ISOFeatures, list[SuspiciousIndicator]]:
    feats = ISOFeatures()
    # Volume identifier lives at PVD offset 40, 32 bytes (ISO-9660).
    vid = data[_PVD_OFFSET + 40:_PVD_OFFSET + 72]
    if vid:
        feats.volume_id = vid.decode("latin-1", "replace").strip() or None

    hints: list[str] = []
    seen: set[str] = set()
    for m in _FILENAME.finditer(data[:2_000_000]):
        name = m.group(0).decode("latin-1", "replace").strip()
        key = name.lower()
        if key not in seen:
            seen.add(key)
            hints.append(name)
        if len(hints) >= 40:
            break
    feats.contained_hints = hints

    ind: list[SuspiciousIndicator] = []
    lures = [h for h in hints if h.lower().endswith((".lnk", ".exe", ".scr", ".bat",
                                                     ".vbs", ".ps1", ".js", ".hta"))]
    if lures:
        ind.append(SuspiciousIndicator(
            id="iso.motw_bypass_payload", title="ISO image carries executable/shortcut lure",
            severity=Severity.HIGH, confidence=0.65,
            observed_facts=lures[:12],
            inference="Delivering a .lnk/.exe inside an ISO strips the Mark-of-the-Web, so "
                      "it runs with fewer warnings — a common phishing packaging trick.",
            evidence=lures[:12],
        ))
    else:
        ind.append(SuspiciousIndicator(
            id="iso.container", title="Disk-image container (Mark-of-the-Web bypass)",
            severity=Severity.LOW, confidence=0.4,
            observed_facts=[feats.volume_id or "ISO-9660 image"],
            inference="ISO/IMG delivery is itself a mild evasion (MOTW bypass); inspect the "
                      "contained files.",
            evidence=["ISO-9660"],
        ))
    return feats, ind
