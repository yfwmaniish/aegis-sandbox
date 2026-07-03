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
    from aegis.orchestrator.docker_linux import DockerLinuxOrchestrator
    from aegis.orchestrator.genymotion import GenymotionOrchestrator
    from aegis.orchestrator.windows import WindowsOrchestrator

    print("MalwareTotal dynamic-analysis preflight")
    print("=" * 44)

    print("\n[avd] Android Emulator (APK) - free, no license (recommended)")
    avd = AvdOrchestrator.preflight()
    for tool, ok in avd.items():
        print(f"  [{'OK ' if ok else 'MISSING'}] {tool}")
    avd_ready = avd.get("emulator") and avd.get("adb")

    print("\n[docker] Linux ELF detonation - isolated container + strace")
    dk = DockerLinuxOrchestrator.preflight()
    for tool, ok in dk.items():
        print(f"  [{'OK ' if ok else 'MISSING'}] {tool}")

    print("\n[genymotion] Genymotion Desktop (gmtool may need a paid license)")
    gm = GenymotionOrchestrator.preflight()
    for tool, ok in gm.items():
        print(f"  [{'OK ' if ok else 'MISSING'}] {tool}")

    print("\n[windows] PE detonation - requires a configured Windows guest+agent")
    win = WindowsOrchestrator.preflight()
    for tool, ok in win.items():
        print(f"  [{'OK ' if ok else 'not set'}] {tool}")

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


def _scan(folder: str, *, recursive: bool, as_json: bool, virustotal: bool) -> int:
    """Batch-scan a folder and print a catch-rate scoreboard."""
    import os
    from pathlib import Path

    from aegis.corpus import build_scoreboard, scan_folder

    root = Path(folder)
    if not root.is_dir():
        print(f"error: not a directory: {folder}", file=sys.stderr)
        return 2
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY") if virustotal else None
    if virustotal and not vt_key:
        print("note: --virustotal set but VIRUSTOTAL_API_KEY is unset; skipping VT.", file=sys.stderr)
    rows = scan_folder(root, recursive=recursive, vt_api_key=vt_key)
    board = build_scoreboard(rows)

    if as_json:
        print(board.model_dump_json(indent=2))
        return 0

    print(f"\nMalwareTotal corpus scoreboard  -  {board.total} sample(s) scanned")
    print("=" * 60)
    for r in sorted(board.rows, key=lambda x: x.risk_score, reverse=True):
        vt = ""
        if r.vt_missed:
            vt = "  [VT-MISSED]"
        elif r.vt_found:
            vt = f"  VT {r.vt_malicious} flagged"
        print(f"  {r.verdict:8} {r.risk_score:5.1f}  {r.file_type:5}  {r.filename}{vt}")
    errs = [r for r in rows if r.error]
    for r in errs:
        print(f"  ERROR           {r.filename}: {r.error}")
    print("-" * 60)
    print(f"  flagged: {board.flagged}/{board.total} ({board.flagged_pct}%)   "
          f"clean: {board.clean}")
    print("  verdicts : " + ", ".join(f"{c.label} {c.count}" for c in board.verdict_counts))
    print("  types    : " + ", ".join(f"{c.label} {c.count}" for c in board.file_type_counts))
    print("  risk     : " + ", ".join(f"{b.label.split(' ')[0]} {b.count}" for b in board.risk_histogram))
    if board.top_capabilities:
        print("  top caps : " + ", ".join(f"{c.label}({c.count})" for c in board.top_capabilities[:6]))
    if board.vt_checked:
        print(f"  VT       : {board.vt_missed_count}/{board.vt_checked} caught by MalwareTotal but MISSED by VirusTotal")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="MalwareTotal static analysis engine")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="run static analysis on a file")
    a.add_argument("path", help="path to the sample")
    a.add_argument("--json", action="store_true", help="emit the full JSON report")
    a.add_argument("--min-len", type=int, default=5, help="minimum string length")

    sc = sub.add_parser("scan", help="batch-scan a folder and print a catch-rate scoreboard")
    sc.add_argument("folder", help="directory of samples to scan (parse-only, never executed)")
    sc.add_argument("--recursive", action="store_true", help="recurse into subdirectories")
    sc.add_argument("--json", action="store_true", help="emit the scoreboard as JSON")
    sc.add_argument("--virustotal", action="store_true",
                    help="cross-reference each sample against VirusTotal (needs VIRUSTOTAL_API_KEY)")

    sub.add_parser("doctor", help="check the dynamic-analysis toolchain (Genymotion/adb/frida)")

    args = parser.parse_args(argv)

    if args.command == "doctor":
        return _doctor()

    if args.command == "scan":
        return _scan(args.folder, recursive=args.recursive, as_json=args.json,
                     virustotal=args.virustotal)

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
