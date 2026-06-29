"""Command-line interface for running the static engine directly on a file.

    python -m aegis.cli analyze <path> [--json] [--min-len N]

Useful for analysts and demos without standing up the API/stack.
"""

from __future__ import annotations

import argparse
import sys

from aegis.static import analyze_file


def _print_summary(report) -> None:
    print(f"file_type     : {report.file_type.value}  ({report.detected_mime})")
    print(f"size          : {report.size} bytes")
    print(f"sha256        : {report.hashes.sha256}")
    if report.hashes.imphash:
        print(f"imphash       : {report.hashes.imphash}")
    if report.hashes.tlsh:
        print(f"tlsh          : {report.hashes.tlsh}")
    print(f"entropy       : {report.entropy.overall}  (packing: {report.entropy.packing_likelihood})")
    print(f"analyzers     : {', '.join(report.analyzers_run) or '(none)'}")
    if report.analyzer_errors:
        print(f"errors        : {report.analyzer_errors}")

    if report.apk:
        _print_apk(report.apk)

    print(f"strings       : {report.strings.count}"
          f"{' (truncated)' if report.strings.truncated else ''}")
    print(f"iocs          : {len(report.iocs)}")
    for ioc in report.iocs[:15]:
        print(f"   - [{ioc.type}] {ioc.value}  (conf {ioc.confidence})")

    print(f"indicators    : {len(report.indicators)}")
    for ind in report.indicators:
        print(f"   - {ind.severity.value.upper():8} {ind.id}")
        print(f"       {ind.title}")
        if ind.inference:
            print(f"       -> {ind.inference}")


def _print_apk(a) -> None:
    print("--- android ---")
    print(f"package       : {a.package}  (v{a.version_name}/{a.version_code})")
    print(f"sdk           : min {a.min_sdk} / target {a.target_sdk}")
    print(f"main_activity : {a.main_activity}")
    print(f"permissions   : {len(a.permissions)} total, {len(a.dangerous_permissions)} dangerous")
    for p in a.dangerous_permissions:
        print(f"   ! {p}")
    print(f"components    : {a.activities} act / {a.services} svc / "
          f"{a.receivers} rcv / {a.providers} prov")
    exported = [(c.type, c.name) for c in a.components if c.exported]
    if exported:
        print(f"exported      : {exported}")
    print(f"accessibility : {a.requests_accessibility}   device_admin: {a.requests_device_admin}")
    print(f"native libs   : {a.uses_native_libs or '(none)'}   dex: {a.dex_count}")
    if a.suspicious_apis:
        print(f"suspicious API: {len(a.suspicious_apis)}")
        for api in a.suspicious_apis:
            print(f"   - {api}")
    for c in a.certificates:
        print(f"signer        : {c.subject}  (debug={c.is_debug_cert})")


def _doctor() -> int:
    """Report dynamic-analysis toolchain readiness for each backend."""
    from aegis.orchestrator.avd import AvdOrchestrator
    from aegis.orchestrator.genymotion import GenymotionOrchestrator

    print("Aegis dynamic-analysis preflight")
    print("=" * 44)

    print("\n[avd] Android Emulator - free, no license (recommended)")
    avd = AvdOrchestrator.preflight()
    for tool, ok in avd.items():
        print(f"  [{'OK ' if ok else 'MISSING'}] {tool}")
    avd_ready = avd.get("emulator") and avd.get("adb")

    print("\n[genymotion] Genymotion Desktop (gmtool may need a paid license)")
    gm = GenymotionOrchestrator.preflight()
    for tool, ok in gm.items():
        print(f"  [{'OK ' if ok else 'MISSING'}] {tool}")

    print()
    if avd_ready:
        print("AVD backend ready. Set SANDBOX_BACKEND=avd, create an AVD named per AVD_NAME,")
        print("and (for API hooking) pip install frida + set FRIDA_SERVER_PATH.")
    else:
        print("For the free path, install the Android SDK 'emulator' + platform-tools 'adb':")
        print("  - Android command-line tools / Android Studio  https://developer.android.com/studio")
        print("  - Create an AVD (x86_64, API 30, Google APIs) named 'aegis-avd'")
        print("  - pip install frida frida-tools  (+ matching frida-server, FRIDA_SERVER_PATH)")
        print("\nWithout a device, set SANDBOX_BACKEND=fake to exercise the pipeline (SIMULATED),")
        print("or leave it unset for static-only analysis.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis static analysis engine")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="run static analysis on a file")
    a.add_argument("path", help="path to the sample")
    a.add_argument("--json", action="store_true", help="emit the full JSON report")
    a.add_argument("--min-len", type=int, default=5, help="minimum string length")

    sub.add_parser("doctor", help="check the dynamic-analysis toolchain (Genymotion/adb/frida)")

    args = parser.parse_args(argv)

    if args.command == "doctor":
        return _doctor()

    if args.command == "analyze":
        try:
            report = analyze_file(args.path, string_min_len=args.min_len)
        except FileNotFoundError:
            print(f"error: no such file: {args.path}", file=sys.stderr)
            return 2
        if args.json:
            print(report.model_dump_json(indent=2))
        else:
            _print_summary(report)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
