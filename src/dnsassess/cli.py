"""Command-line interface (placeholder; implemented fully in Phase 3-4).

Phase 2 ships the prober, safety gate, rate limiter and config loader. The
``scan``/``compare``/``report``/``demo`` commands are wired here as stubs so
the package is importable and the Makefile targets resolve.
"""
from __future__ import annotations

import argparse
import sys


def _cmd_scan(args: argparse.Namespace) -> int:
    print("scan: not yet implemented (Phase 3-4).")
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    print("compare: not yet implemented (Phase 3-4).")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    print("report: not yet implemented (Phase 3-4).")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    print("demo: not yet implemented (Phase 3-4).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsassess")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run authorised probes")
    p_scan.add_argument("--scope", required=True)
    p_scan.add_argument("--rate", required=True)
    p_scan.add_argument("--out", default="out")
    p_scan.set_defaults(func=_cmd_scan)

    p_compare = sub.add_parser("compare", help="compare results to ground truth")
    p_compare.set_defaults(func=_cmd_compare)

    p_report = sub.add_parser("report", help="write JSON/CSV/HTML reports")
    p_report.set_defaults(func=_cmd_report)

    sub.add_parser("demo", help="full lab-up → scan → compare → report").set_defaults(
        func=_cmd_demo
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
