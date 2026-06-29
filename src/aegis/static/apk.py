"""APK (Android) static analyzer.

Android is the platform's headline differentiator (PRD §3.2, FR-6/7/8), so this is
the richest static parser. It extracts the manifest essentials (package, SDKs, main
activity), the full permission set with dangerous/custom partitioning, every declared
component with its *effective* exported state and intent actions, the signing
certificates (flagging debug certs), and a lightweight DEX API scan for the API
families that matter to the downstream Android detectors (SMS/OTP, accessibility,
dynamic code loading, native exec).

androguard drives manifest + certificate parsing; the zip and DEX byte scans are done
directly so we don't pay androguard's full bytecode-analysis cost for a static pass.
"""

from __future__ import annotations

import contextlib
import zipfile
from io import BytesIO

from aegis.static.common.iocs import IOC, extract_iocs
from aegis.static.models import (
    AndroidComponent,
    APKFeatures,
    CertInfo,
    Severity,
    SuspiciousIndicator,
)

ANALYZER_NAME = "apk"

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# High-risk runtime permissions (subset of Android "dangerous" + signature/abused).
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.WRITE_SMS",
    "android.permission.RECEIVE_MMS", "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.PACKAGE_USAGE_STATS", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.GET_ACCOUNTS", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.FOREGROUND_SERVICE", "android.permission.DISABLE_KEYGUARD",
}

# DEX byte-scan markers: descriptor/string -> (api label, why it matters).
_DEX_API_MARKERS: dict[bytes, str] = {
    b"Landroid/telephony/SmsManager": "SmsManager (send/intercept SMS)",
    b"sendTextMessage": "SmsManager.sendTextMessage",
    b"Landroid/content/pm/PackageInstaller": "PackageInstaller (dropper)",
    b"Ldalvik/system/DexClassLoader": "DexClassLoader (dynamic code load)",
    b"Ldalvik/system/PathClassLoader": "PathClassLoader (dynamic code load)",
    b"Ldalvik/system/InMemoryDexClassLoader": "InMemoryDexClassLoader (in-memory load)",
    b"Ljava/lang/Runtime;->exec": "Runtime.exec (native command exec)",
    b"Ljava/lang/ProcessBuilder": "ProcessBuilder (native command exec)",
    b"addJavascriptInterface": "WebView.addJavascriptInterface (JS bridge)",
    b"Landroid/accessibilityservice": "AccessibilityService (UI automation/abuse)",
    b"Landroid/app/admin/DevicePolicyManager": "DevicePolicyManager (device admin)",
    b"Landroidx/security/crypto": "Jetpack crypto",
    b"Ljavax/crypto/Cipher": "javax.crypto.Cipher (payload (de)cryption)",
    b"getDeviceId": "TelephonyManager.getDeviceId (IMEI)",
    b"getSimSerialNumber": "getSimSerialNumber",
    b"Landroid/content/ClipboardManager": "ClipboardManager (clipboard theft)",
    b"Landroid/media/projection": "MediaProjection (screen capture)",
    b"Lorg/json": "JSON (C2 protocol, weak signal)",
    b"createSocket": "raw socket (C2)",
    # Generic networking / HTTP clients — capability even without SMS/accessibility.
    b"Ljava/net/URL": "java.net.URL (HTTP networking)",
    b"Ljava/net/HttpURLConnection": "HttpURLConnection (HTTP C2)",
    b"Ljavax/net/ssl/HttpsURLConnection": "HttpsURLConnection (HTTPS C2)",
    b"Lokhttp3": "OkHttp (HTTP client)",
    b"Lretrofit2": "Retrofit (REST client)",
    b"Lcom/android/volley": "Volley (HTTP client)",
    b"Ljava/net/Socket": "java.net.Socket (raw TCP)",
    # Reflection — used to hide API calls / load hidden behaviour.
    b"Ljava/lang/reflect/Method": "reflection (hidden API calls)",
    b"Ljava/lang/Class;->forName": "Class.forName (reflective loading)",
    # Background persistence.
    b"Landroid/app/job/JobScheduler": "JobScheduler (background persistence)",
    b"Landroidx/work/WorkManager": "WorkManager (background persistence)",
    # Surveillance: location, camera, microphone/recording.
    b"getLastKnownLocation": "location (getLastKnownLocation)",
    b"requestLocationUpdates": "location tracking (requestLocationUpdates)",
    b"Landroid/hardware/Camera": "Camera API (photo/video capture)",
    b"Landroid/hardware/camera2": "Camera2 API (photo/video capture)",
    b"Landroid/media/MediaRecorder": "MediaRecorder (audio/video capture)",
    b"Landroid/media/AudioRecord": "AudioRecord (microphone capture)",
    b"getRunningAppProcesses": "getRunningAppProcesses (process enumeration)",
    b"Landroid/provider/ContactsContract": "ContactsContract (contact harvesting)",
    b"Landroid/provider/CallLog": "CallLog (call-log harvesting)",
}


def _silence_androguard_logs() -> None:
    """androguard 4.x logs verbosely via loguru on every parse — disable it so the
    engine output (and any caller's stdout) stays clean."""
    with contextlib.suppress(Exception):
        from loguru import logger as _loguru

        _loguru.disable("androguard")


def _import_apk_class():
    _silence_androguard_logs()
    try:  # androguard >= 4.x
        from androguard.core.apk import APK  # type: ignore
        return APK
    except ImportError:  # androguard 3.x layout
        from androguard.core.bytecodes.apk import APK  # type: ignore
        return APK


def _effective_exported(elem, has_intent_filter: bool) -> bool:
    """Android's default-export rule: if android:exported is set, honour it; otherwise
    a component is exported iff it declares at least one intent-filter."""
    val = elem.get(f"{{{_ANDROID_NS}}}exported")
    if val is not None:
        return val.lower() == "true"
    return has_intent_filter


def _parse_components(manifest) -> list[AndroidComponent]:
    components: list[AndroidComponent] = []
    app = manifest.find("application")
    if app is None:
        return components
    tag_to_type = {
        "activity": "activity",
        "activity-alias": "activity",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }
    for child in app:
        ctype = tag_to_type.get(child.tag)
        if ctype is None:
            continue
        name = child.get(f"{{{_ANDROID_NS}}}name") or "?"
        perm = child.get(f"{{{_ANDROID_NS}}}permission")
        actions: list[str] = []
        for intent in child.findall("intent-filter"):
            for action in intent.findall("action"):
                a = action.get(f"{{{_ANDROID_NS}}}name")
                if a:
                    actions.append(a)
        components.append(AndroidComponent(
            type=ctype,
            name=name,
            exported=_effective_exported(child, bool(actions)),
            permission=perm,
            intent_actions=actions,
        ))
    return components


def _parse_certificates(apk) -> list[CertInfo]:
    certs: list[CertInfo] = []
    try:
        raw_certs = apk.get_certificates()
    except Exception:  # noqa: BLE001 - unsigned or parse failure
        return certs
    for c in raw_certs:
        try:
            subject = c.subject.human_friendly
            issuer = c.issuer.human_friendly
            certs.append(CertInfo(
                subject=subject,
                issuer=issuer,
                serial=str(getattr(c, "serial_number", "")) or None,
                not_before=str(getattr(c, "not_valid_before", "")) or None,
                not_after=str(getattr(c, "not_valid_after", "")) or None,
                sha256=getattr(c, "sha256_fingerprint", "").replace(" ", "") or None,
                is_debug_cert="Android Debug" in (subject or ""),
            ))
        except Exception:  # noqa: BLE001 - one bad cert shouldn't drop the rest
            continue
    return certs


def _scan_dex_apis(data: bytes) -> tuple[list[str], int, list[str]]:
    """Return (suspicious_api_labels, dex_count, native_libs) from the APK zip."""
    apis: set[str] = set()
    native_libs: list[str] = []
    dex_count = 0
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.startswith("classes") and name.endswith(".dex"):
                    dex_count += 1
                    try:
                        blob = zf.read(name)
                    except (zipfile.BadZipFile, OSError):
                        continue
                    for marker, label in _DEX_API_MARKERS.items():
                        if marker in blob:
                            apis.add(label)
                elif name.startswith("lib/") and name.endswith(".so"):
                    native_libs.append(name)
    except (zipfile.BadZipFile, OSError):
        pass
    return sorted(apis), dex_count, sorted(set(native_libs))


def _safe(fn, default=None):
    """Call an androguard getter, returning ``default`` on any failure. androguard
    raises (e.g. KeyError) rather than returning None for fields a malformed/modded
    APK omits, so one missing field must not abort the whole analysis (TR-STA-02)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - androguard getters raise varied exceptions
        return default


def _safe_int(fn) -> int | None:
    val = _safe(fn)
    try:
        return int(val) if val not in (None, "") else None
    except (TypeError, ValueError):
        return None


def analyze(data: bytes) -> tuple[APKFeatures, list[SuspiciousIndicator], list[IOC]]:
    """Parse ``data`` as an APK; returns features, indicators and manifest-derived IOCs."""
    APK = _import_apk_class()
    apk = APK(data, raw=True)
    feats = APKFeatures()
    indicators: list[SuspiciousIndicator] = []

    # Every metadata getter is wrapped: modded/obfuscated APKs frequently omit fields
    # that make androguard raise instead of returning None.
    feats.package = _safe(apk.get_package)
    feats.version_name = _safe(apk.get_androidversion_name)
    feats.version_code = _safe_int(apk.get_androidversion_code)
    feats.min_sdk = _safe_int(apk.get_min_sdk_version)
    feats.target_sdk = _safe_int(apk.get_target_sdk_version)
    feats.main_activity = _safe(apk.get_main_activity)

    # Permissions, partitioned.
    perms = sorted(set(_safe(apk.get_permissions, []) or []))
    feats.permissions = perms
    feats.dangerous_permissions = [p for p in perms if p in _DANGEROUS_PERMISSIONS]
    with contextlib.suppress(Exception):
        feats.custom_permissions = sorted(set(apk.get_declared_permissions() or []))
    with contextlib.suppress(Exception):
        feats.uses_features = sorted(set(apk.get_features() or []))

    # Components + exported analysis.
    try:
        manifest = apk.get_android_manifest_xml()
        feats.components = _parse_components(manifest)
    except Exception as exc:  # noqa: BLE001 - manifest parse fallback
        # Fall back to androguard's flat component lists (no exported/intent detail).
        for ctype, getter in (("activity", apk.get_activities),
                              ("service", apk.get_services),
                              ("receiver", apk.get_receivers),
                              ("provider", apk.get_providers)):
            try:
                for n in getter() or []:
                    feats.components.append(AndroidComponent(type=ctype, name=n))
            except Exception:  # noqa: BLE001
                pass
        indicators.append(SuspiciousIndicator(
            id="apk.manifest_parse_partial",
            title="Manifest parsed with reduced fidelity",
            severity=Severity.LOW,
            confidence=0.3,
            observed_facts=[f"{type(exc).__name__}: {exc}"],
            inference="Exported/intent-filter detail may be incomplete.",
        ))

    feats.activities = sum(c.type == "activity" for c in feats.components)
    feats.services = sum(c.type == "service" for c in feats.components)
    feats.receivers = sum(c.type == "receiver" for c in feats.components)
    feats.providers = sum(c.type == "provider" for c in feats.components)

    feats.certificates = _parse_certificates(apk)
    feats.suspicious_apis, feats.dex_count, feats.uses_native_libs = _scan_dex_apis(data)

    feats.requests_accessibility = (
        "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
        or any(c.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
               for c in feats.components)
        or any("accessibility" in a.lower() for c in feats.components for a in c.intent_actions)
    )
    feats.requests_device_admin = (
        "android.permission.BIND_DEVICE_ADMIN" in perms
        or any(c.permission == "android.permission.BIND_DEVICE_ADMIN" for c in feats.components)
    )

    indicators.extend(_apk_indicators(feats))

    # IOCs from the (decoded) manifest text + package name.
    iocs: list[IOC] = []
    try:
        manifest_text = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace")
        iocs = extract_iocs(manifest_text, source="apk.manifest")
    except Exception:  # noqa: BLE001
        pass

    return feats, indicators, iocs


def _apk_indicators(feats: APKFeatures) -> list[SuspiciousIndicator]:
    """Derive explainable indicators from extracted APK features."""
    out: list[SuspiciousIndicator] = []

    # SMS/OTP-interception capability (FR-9 defensive signal).
    sms_perms = [p for p in feats.dangerous_permissions if "SMS" in p or "MMS" in p or "WAP" in p]
    if sms_perms:
        out.append(SuspiciousIndicator(
            id="apk.sms_capability",
            title="SMS/MMS interception capability",
            severity=Severity.MEDIUM,
            confidence=0.6,
            observed_facts=sms_perms,
            inference="App can read/receive/send SMS — relevant to OTP/MFA interception "
                      "(defensive signal only).",
            evidence=sms_perms,
        ))

    # Accessibility abuse capability (FR-7).
    if feats.requests_accessibility:
        out.append(SuspiciousIndicator(
            id="apk.accessibility_service",
            title="Requests accessibility service binding",
            severity=Severity.HIGH,
            confidence=0.65,
            observed_facts=["BIND_ACCESSIBILITY_SERVICE requested or service declared"],
            inference="Accessibility access enables screen reading and UI automation — "
                      "frequently abused by banking trojans.",
            evidence=["BIND_ACCESSIBILITY_SERVICE"],
        ))

    # Overlay + accessibility together is a strong banker pattern.
    if feats.requests_accessibility and "android.permission.SYSTEM_ALERT_WINDOW" in feats.permissions:
        out.append(SuspiciousIndicator(
            id="apk.overlay_plus_accessibility",
            title="Overlay + accessibility combination",
            severity=Severity.HIGH,
            confidence=0.75,
            observed_facts=["SYSTEM_ALERT_WINDOW + accessibility"],
            inference="Overlay windows driven by accessibility is a classic credential-"
                      "phishing / banker pattern.",
            evidence=["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
        ))

    # Device admin (anti-uninstall / lock).
    if feats.requests_device_admin:
        out.append(SuspiciousIndicator(
            id="apk.device_admin",
            title="Requests device administrator",
            severity=Severity.MEDIUM,
            confidence=0.6,
            observed_facts=["BIND_DEVICE_ADMIN"],
            inference="Device admin is abused to resist uninstall and lock the device.",
            evidence=["BIND_DEVICE_ADMIN"],
        ))

    # Dynamic code loading / dropper (FR-8).
    loaders = [a for a in feats.suspicious_apis if "ClassLoader" in a or "PackageInstaller" in a]
    if loaders:
        out.append(SuspiciousIndicator(
            id="apk.dynamic_code_loading",
            title="Dynamic code loading / installer APIs",
            severity=Severity.HIGH,
            confidence=0.6,
            observed_facts=loaders,
            inference="Loading code at runtime is a hallmark of droppers/stagers.",
            evidence=loaders,
        ))

    # Debug-signed release.
    if any(c.is_debug_cert for c in feats.certificates):
        out.append(SuspiciousIndicator(
            id="apk.debug_signed",
            title="Signed with Android debug certificate",
            severity=Severity.LOW,
            confidence=0.5,
            observed_facts=["certificate subject contains 'Android Debug'"],
            inference="Production apps are not normally debug-signed.",
            evidence=["certificate"],
        ))

    # Request to install other packages (side-loading dropper).
    if "android.permission.REQUEST_INSTALL_PACKAGES" in feats.permissions:
        out.append(SuspiciousIndicator(
            id="apk.request_install_packages",
            title="Can request installation of other packages",
            severity=Severity.MEDIUM,
            confidence=0.55,
            observed_facts=["REQUEST_INSTALL_PACKAGES"],
            inference="Used by droppers to side-load a second-stage APK.",
            evidence=["REQUEST_INSTALL_PACKAGES"],
        ))

    # Excessive dangerous-permission footprint.
    if len(feats.dangerous_permissions) >= 8:
        out.append(SuspiciousIndicator(
            id="apk.excessive_permissions",
            title=f"Large dangerous-permission footprint ({len(feats.dangerous_permissions)})",
            severity=Severity.MEDIUM,
            confidence=0.5,
            observed_facts=feats.dangerous_permissions,
            inference="Broad sensitive access disproportionate to a typical single-purpose app.",
            evidence=feats.dangerous_permissions,
        ))

    return out
