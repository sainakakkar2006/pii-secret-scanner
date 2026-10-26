from __future__ import annotations

import argparse

from .reporting import findings_to_json, findings_to_text, write_report
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan files for accidentally committed secrets and, with --pii, personal data.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--out", help="optional report path")
    scan.add_argument(
        "--pii",
        action="store_true",
        help="also look for personal data: SSNs, payment card numbers, email addresses",
    )
    scan.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit with code 0, even when findings exist",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    findings = scan_path(args.path, include_pii=args.pii)
    report = findings_to_json(findings) if args.format == "json" else findings_to_text(findings)

    if args.out:
        write_report(report, args.out)
    print(report)

    if findings and not args.no_fail:
        return 1
    return 0

