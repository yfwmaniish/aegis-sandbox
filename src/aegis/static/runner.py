"""Static analysis entry point — orchestrates the whole static pass.

``analyze_bytes`` is the single function the worker/task layer calls. It runs the
format-independent extractors (hashing, entropy, strings, IOCs) unconditionally, then
routes to exactly one format analyzer based on magic bytes. Every stage is wrapped so
a failure in one module is recorded in ``analyzer_errors`` and the rest of the report
still completes (TR-STA-02 / NFR-7: non-critical parser failure never aborts output).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from aegis.static.common.entropy import chunked_entropy, packing_likelihood, shannon_entropy
from aegis.static.common.hashing import compute_hashes
from aegis.static.common.iocs import IOC, extract_iocs
from aegis.static.common.strings import DEFAULT_MAX_COUNT, DEFAULT_MIN_LEN, extract_strings
from aegis.static.dispatch import detect_file_type, mime_for
from aegis.static.models import (
    EntropySummary,
    FileType,
    HashSummary,
    IOCEntry,
    Severity,
    StaticReport,
    StringSummary,
    SuspiciousIndicator,
)

_ENTROPY_CHUNK = 4096


def analyze_file(
    path: str | Path,
    *,
    string_min_len: int = DEFAULT_MIN_LEN,
    string_max_count: int = DEFAULT_MAX_COUNT,
) -> StaticReport:
    """Read ``path`` and run the static analysis pipeline over its contents."""
    p = Path(path)
    data = p.read_bytes()
    return analyze_bytes(
        data,
        filename=p.name,
        string_min_len=string_min_len,
        string_max_count=string_max_count,
    )


def analyze_bytes(
    data: bytes,
    *,
    filename: str | None = None,
    string_min_len: int = DEFAULT_MIN_LEN,
    string_max_count: int = DEFAULT_MAX_COUNT,
) -> StaticReport:
    """Run the static analysis pipeline over ``data`` and return a :class:`StaticReport`."""
    hashes = compute_hashes(data)
    file_type = detect_file_type(data, filename)

    # Build the report shell first so later stages can record isolated errors on it.
    report = StaticReport(
        file_type=file_type,
        detected_mime=mime_for(file_type),
        size=len(data),
        hashes=HashSummary(sha256=hashes.sha256, sha1=hashes.sha1, md5=hashes.md5, tlsh=hashes.tlsh),
        entropy=EntropySummary(overall=0.0),
    )

    _run_entropy(report, data)
    iocs = _run_strings_and_iocs(report, data, string_min_len, string_max_count)

    # Route to the format analyzer (exactly one populates its sub-block).
    if file_type == FileType.PE:
        _run_with("pe", report, lambda: _populate_pe(report, data))
    elif file_type == FileType.ELF:
        _run_with("elf", report, lambda: _populate_elf(report, data))
    elif file_type == FileType.APK:
        _run_with("apk", report, lambda: _populate_apk(report, data, iocs))
        # Also scan decompressed entries: catches IOCs/APIs hidden in DEX/resources
        # that the raw-bytes string pass misses on large/compressed APKs.
        _run_with("archive", report, lambda: _populate_archive(report, data, iocs))
    elif file_type == FileType.MACHO:
        _run_with("macho", report, lambda: _populate_macho(report, data))
    elif file_type == FileType.PDF:
        _run_with("pdf", report, lambda: _populate_pdf(report, data))
    elif file_type == FileType.OFFICE:
        _run_with("office", report, lambda: _populate_office(report, data))
    elif file_type == FileType.SCRIPT:
        _run_with("script", report, lambda: _populate_script(report, data, filename))
    elif file_type == FileType.LNK:
        _run_with("lnk", report, lambda: _populate_simple(report, "lnk", data))
    elif file_type == FileType.RTF:
        _run_with("rtf", report, lambda: _populate_simple(report, "rtf", data))
    elif file_type == FileType.HTML:
        _run_with("html", report, lambda: _populate_simple(report, "html", data))
    elif file_type == FileType.JAR:
        _run_with("jar", report, lambda: _populate_simple(report, "jar", data))
    elif file_type == FileType.ISO:
        _run_with("iso", report, lambda: _populate_simple(report, "iso", data))
    elif file_type == FileType.ZIP:
        # ZIP/APK-project archives (e.g. apktool/APKEditor output) — the payload lives
        # in decompressed smali/dex, not a parseable manifest.
        _run_with("archive", report, lambda: _populate_archive(report, data, iocs))

    _finalize_iocs(report, iocs)
    # Cross-cutting indicators derived from the consolidated IOC list + features
    # (e.g. hardcoded C2, or network IOCs in an APK that declares no INTERNET).
    _derive_correlation_indicators(report)
    report.indicators.sort(key=lambda i: (_sev_rank(i.severity), -i.confidence))
    return report


# ── Stage helpers ────────────────────────────────────────────────────────────


_ARCHIVE_ENTROPY_TYPES = {FileType.APK, FileType.ZIP, FileType.JAR, FileType.OFFICE}


def _run_entropy(report: StaticReport, data: bytes) -> None:
    try:
        # An APK/JAR/OOXML is a ZIP container — whole-file entropy is always ~7.9 and tells
        # you nothing. Measure the *decompressed* code (classes.dex / native .so) instead;
        # that's where real packers (Bangcle/Jiagu/…) show up as high entropy.
        code = (_archive_code_entropy(data)
                if report.file_type in _ARCHIVE_ENTROPY_TYPES else None)
        if code is not None:
            overall, ratio, high = code
        else:
            overall = shannon_entropy(data)
            bands = chunked_entropy(data, _ENTROPY_CHUNK)
            high = sum(1 for b in bands if b.entropy >= 7.0)
            ratio = (high / len(bands)) if bands else 0.0
        report.entropy = EntropySummary(
            overall=round(overall, 3),
            packing_likelihood=packing_likelihood(overall, ratio),
            high_entropy_regions=high,
        )
    except Exception as exc:  # noqa: BLE001
        report.add_error("entropy", exc)


def _archive_code_entropy(data: bytes) -> tuple[float, float, int] | None:
    """Size-weighted entropy over the decompressed classes*.dex + lib/*.so entries.
    Returns (overall_entropy, high_entropy_ratio, high_entropy_count) or None if the
    archive has no code entries / can't be read."""
    import zipfile
    from io import BytesIO

    ents: list[tuple[int, float]] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for n in zf.namelist():
                is_dex = n.startswith("classes") and n.endswith(".dex")
                is_so = n.startswith("lib/") and n.endswith(".so")
                if not (is_dex or is_so):
                    continue
                try:
                    blob = zf.read(n)
                except (zipfile.BadZipFile, OSError):
                    continue
                if blob:
                    ents.append((len(blob), shannon_entropy(blob)))
    except (zipfile.BadZipFile, OSError):
        return None
    if not ents:
        return None
    total = sum(s for s, _ in ents)
    overall = sum(s * e for s, e in ents) / total if total else 0.0
    high = sum(1 for _, e in ents if e >= 7.0)
    return overall, (high / len(ents)), high


def _run_strings_and_iocs(
    report: StaticReport, data: bytes, min_len: int, max_count: int
) -> list[IOC]:
    iocs: list[IOC] = []
    try:
        extracted = extract_strings(data, min_len=min_len, max_count=max_count)
        report.strings = StringSummary(
            count=extracted.count,
            truncated=extracted.truncated,
            interesting=extracted.interesting,
        )
        iocs = extract_iocs("\n".join(extracted.all()), source="strings")
    except Exception as exc:  # noqa: BLE001
        report.add_error("strings", exc)
    return iocs


def _run_with(module: str, report: StaticReport, fn) -> None:
    """Run a format analyzer, recording any failure as an isolated module error."""
    try:
        report.analyzers_run.append(module)
        fn()
    except Exception as exc:  # noqa: BLE001
        report.add_error(module, exc)


def _populate_pe(report: StaticReport, data: bytes) -> None:
    from aegis.static import pe

    feats, indicators, imphash = pe.analyze(data)
    report.pe = feats
    report.indicators.extend(indicators)
    if imphash:
        report.hashes.imphash = imphash


def _populate_elf(report: StaticReport, data: bytes) -> None:
    from aegis.static import elf

    feats, indicators = elf.analyze(data)
    report.elf = feats
    report.indicators.extend(indicators)


def _populate_apk(report: StaticReport, data: bytes, iocs: list[IOC]) -> None:
    from aegis.static import apk

    feats, indicators, apk_iocs = apk.analyze(data)
    report.apk = feats
    report.indicators.extend(indicators)
    iocs.extend(apk_iocs)


def _populate_macho(report: StaticReport, data: bytes) -> None:
    from aegis.static import macho

    feats, indicators = macho.analyze(data)
    report.macho = feats
    report.indicators.extend(indicators)


def _populate_pdf(report: StaticReport, data: bytes) -> None:
    from aegis.static import pdf

    feats, indicators = pdf.analyze(data)
    report.pdf = feats
    report.indicators.extend(indicators)


def _populate_office(report: StaticReport, data: bytes) -> None:
    from aegis.static import office

    feats, indicators = office.analyze(data)
    report.office = feats
    report.indicators.extend(indicators)


def _populate_script(report: StaticReport, data: bytes, filename: str | None) -> None:
    from aegis.static import script

    feats, indicators = script.analyze(data, filename)
    report.script = feats
    report.indicators.extend(indicators)


def _populate_simple(report: StaticReport, kind: str, data: bytes) -> None:
    """Route to a single-arg analyzer (analyze(data)->(feats, indicators)) and store the
    features on the matching report field."""
    import importlib

    module_name = {"html": "html_smuggle"}.get(kind, kind)
    mod = importlib.import_module(f"aegis.static.{module_name}")
    feats, indicators = mod.analyze(data)
    setattr(report, kind, feats)
    report.indicators.extend(indicators)


# Spyware capability categories -> substrings to look for in scanned API labels.
_SPYWARE_CATEGORIES = {
    "SMS interception": ("sms", "sendtextmessage"),
    "command execution": ("runtime.exec", "processbuilder", "native command"),
    "dynamic code loading": ("dexclassloader", "inmemorydexclassloader"),
    "device fingerprinting": ("getdeviceid", "getsimserial", "imei"),
    "accessibility abuse": ("accessibilityservice",),
    "location tracking": ("location",),
    "audio/video/screen capture": ("mediarecorder", "audiorecord", "camera", "mediaprojection"),
    "contact/call harvesting": ("contactscontract", "calllog"),
    "clipboard theft": ("clipboard",),
}

# Permission-gated categories: an API hit only counts as a real capability if the app
# also *declares* a matching permission. Code referencing an API it has no permission for
# is almost always dead code from a bundled library (support/ad SDKs). Categories not
# listed here need no permission (clipboard, dynamic loading, command exec).
_CATEGORY_PERMS = {
    "SMS interception": {"SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS", "RECEIVE_MMS",
                         "RECEIVE_WAP_PUSH"},
    "device fingerprinting": {"READ_PHONE_STATE", "READ_PRIVILEGED_PHONE_STATE",
                              "READ_PHONE_NUMBERS"},
    "accessibility abuse": {"BIND_ACCESSIBILITY_SERVICE"},
    "location tracking": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                          "ACCESS_BACKGROUND_LOCATION"},
    "audio/video/screen capture": {"CAMERA", "RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT"},
    "contact/call harvesting": {"READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG",
                                "WRITE_CALL_LOG", "GET_ACCOUNTS"},
}


def _populate_archive(report: StaticReport, data: bytes, iocs: list[IOC]) -> None:
    from aegis.static import archive

    scan = archive.scan_archive(data)
    iocs.extend(scan.iocs)

    # Fold scanned APIs/native-libs into the APK block when there is one.
    declared_perms: set[str] = set()
    if report.apk is not None:
        report.apk.suspicious_apis = sorted(set(report.apk.suspicious_apis) | set(scan.suspicious_apis))
        report.apk.dex_count = report.apk.dex_count or scan.dex_count
        declared_perms = {p.rsplit(".", 1)[-1].upper() for p in report.apk.permissions}

    # If we parsed a manifest, correlate capability APIs against declared permissions.
    # A raw ZIP/project (no manifest) has no permission context, so skip correlation.
    report.indicators.extend(_archive_indicators(
        scan, declared_perms, correlate=report.apk is not None))


def _archive_indicators(scan, declared_perms: set[str] | None = None,
                        *, correlate: bool = False) -> list[SuspiciousIndicator]:
    out: list[SuspiciousIndicator] = []
    declared_perms = declared_perms or set()

    if scan.is_decompiled_project:
        out.append(SuspiciousIndicator(
            id="archive.decompiled_project",
            title="Decompiled / repackaging project (apktool/APKEditor)",
            severity=Severity.MEDIUM,
            confidence=0.55,
            observed_facts=[f"{scan.smali_count} smali files, {scan.entries} entries"],
            inference="This is a modding/repackaging workspace, not an installable app — "
                      "consistent with a trojanized/rebuilt application.",
            evidence=["smali/", "original/"],
        ))

    if scan.embedded_apks:
        out.append(SuspiciousIndicator(
            id="archive.embedded_apk",
            title=f"Contains {len(scan.embedded_apks)} embedded APK(s)",
            severity=Severity.MEDIUM,
            confidence=0.55,
            observed_facts=scan.embedded_apks[:8],
            inference="A bundled original app alongside modified code is a hallmark of "
                      "trojanized repackaging (graft malware onto a legitimate app).",
            evidence=scan.embedded_apks[:8],
        ))

    # Spyware capability fan-out from the decompressed API scan. When we have a manifest
    # (correlate=True), a permission-gated category only counts if the matching permission
    # is declared — code referencing e.g. Camera2 without the CAMERA permission is dead
    # library code, not a capability. Categories with no permission gate always count.
    hits: dict[str, list[str]] = {}
    for cat, keys in _SPYWARE_CATEGORIES.items():
        matched = [a for a in scan.suspicious_apis if any(k in a.lower() for k in keys)]
        if not matched:
            continue
        need = _CATEGORY_PERMS.get(cat)
        if correlate and need and not (need & declared_perms):
            continue  # API present but no matching permission -> dead code
        hits[cat] = matched

    if hits:
        # HIGH only when several *corroborated* categories co-occur; a single category
        # (or two) is common in benign apps and stays MEDIUM.
        sev = Severity.HIGH if len(hits) >= 4 else Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
        evidence = sorted({a for v in hits.values() for a in v})
        out.append(SuspiciousIndicator(
            id="archive.spyware_capabilities",
            title=f"Surveillance/exfiltration capabilities in code ({len(hits)} categories)",
            severity=sev,
            confidence=min(0.85, 0.35 + 0.12 * len(hits)),
            observed_facts=sorted(hits.keys()),
            inference="Code references surveillance/exfiltration APIs across "
                      f"{len(hits)} categor{'ies' if len(hits) != 1 else 'y'} "
                      + ("backed by matching permissions" if correlate else "(no manifest to "
                         "correlate against)") + " — review for spyware behaviour.",
            evidence=evidence[:15],
        ))

    return out


def _finalize_iocs(report: StaticReport, iocs: list[IOC]) -> None:
    # Dedupe across sources, keeping the highest-confidence provenance.
    best: dict[tuple[str, str], IOC] = {}
    for ioc in iocs:
        k = ioc.key()
        if k not in best or ioc.confidence > best[k].confidence:
            best[k] = ioc
    report.iocs = [
        IOCEntry(type=i.type, value=i.value, confidence=i.confidence, source=i.source)
        for i in sorted(best.values(), key=lambda i: (-i.confidence, i.type, i.value))
    ]


_TELEGRAM_HOSTS = ("t.me", "telegram.me", "telegram.org", "telegram.dog")


def _url_host_is_ip(url: str) -> bool:
    """True only for URLs whose host is a *public, routable* IP. Loopback/private/reserved
    IP hosts (http://127.0.0.1, http://192.168.x.x) are local/dev references, not C2."""
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(getattr(ip, "is_global", False)) and not (
        ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local)


def _derive_correlation_indicators(report: StaticReport) -> None:
    """Promote the most damning IOCs into scored findings, and correlate IOCs against
    declared capability. This is where 'we extracted a C2 IP' becomes an actual
    finding with severity/confidence — and where a network-speaking APK that declares
    no INTERNET permission gets flagged as a likely hidden-capability dropper (FR-8)."""
    url_iocs = [i for i in report.iocs if i.type == "url"]
    ip_iocs = [i for i in report.iocs if i.type == "ip"]

    # 1) Hardcoded raw-IP C2 endpoint (http://1.2.3.4/...): a strong C2 signal.
    ip_urls = [i.value for i in url_iocs if _url_host_is_ip(i.value)]
    if ip_urls:
        report.indicators.append(SuspiciousIndicator(
            id="net.hardcoded_ip_c2",
            title="Hardcoded raw-IP URL (likely C2)",
            severity=Severity.HIGH,
            confidence=0.75,
            observed_facts=ip_urls[:10],
            inference="URLs pointing at a bare IP (no domain) are a common C2 pattern; "
                      "legitimate apps almost always use named hosts.",
            evidence=ip_urls[:10],
        ))
    # NOTE: bare public IPs (not in a URL) are intentionally NOT promoted to a finding.
    # Dotted-quads in a code blob are overwhelmingly version/build strings, DNS resolvers
    # or CDN addresses; flagging them produced heavy false positives on benign apps. A
    # real hardcoded C2 shows up as an IP-host URL (net.hardcoded_ip_c2 above) or an
    # ip:port endpoint; bare IPs remain as low-confidence IOCs for the analyst only.

    # 2) Telegram channel reference — frequent actor C2 / exfil / contact channel.
    tg = [i.value for i in url_iocs if any(h in i.value.lower() for h in _TELEGRAM_HOSTS)]
    if tg:
        report.indicators.append(SuspiciousIndicator(
            id="net.telegram_channel",
            title="Telegram channel/bot reference",
            severity=Severity.MEDIUM,
            confidence=0.55,
            observed_facts=tg[:10],
            inference="Telegram is widely used for C2, exfiltration and actor contact.",
            evidence=tg[:10],
        ))

    # 3) APK: network IOCs present but INTERNET not declared → hidden capability/dropper.
    if report.apk is not None and (url_iocs or ip_iocs):
        perms = set(report.apk.permissions)
        if "android.permission.INTERNET" not in perms:
            net_evidence = [i.value for i in (url_iocs + ip_iocs)][:10]
            report.indicators.append(SuspiciousIndicator(
                id="apk.network_without_internet_permission",
                title="Network endpoints in code but no INTERNET permission declared",
                severity=Severity.HIGH,
                confidence=0.7,
                observed_facts=[f"{len(url_iocs)} URL + {len(ip_iocs)} IP IOC(s); "
                               f"declared permissions: {len(perms)}"],
                inference="A benign-looking manifest (no/low permissions) carrying C2/network "
                          "indicators in code is a hallmark of a first-stage dropper/loader "
                          "that fetches a second stage.",
                evidence=net_evidence,
            ))


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_rank(severity) -> int:
    return _SEV_ORDER.get(getattr(severity, "value", str(severity)), 99)
