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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis static analysis engine")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="run static analysis on a file")
    a.add_argument("path", help="path to the sample")
    a.add_argument("--json", action="store_true", help="emit the full JSON report")
    a.add_argument("--min-len", type=int, default=5, help="minimum string length")

    args = parser.parse_args(argv)

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
