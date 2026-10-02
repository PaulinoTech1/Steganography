"""CLI: scan text or files, print JSON report."""
from __future__ import annotations

import argparse
import json
import sys

from .report import analyze
from .inspection import Limits, _held, inspect_bytes, inspect_text
from .policy import POLICY_IDS, Policy


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stegdetect",
                                description="Detect steganographic prompt-injection carriers in text.")
    p.add_argument("input", nargs="?", help="Text to scan, or - for stdin")
    p.add_argument("-f", "--file", help="Read input from file")
    p.add_argument("--sanitize", action="store_true",
                   help="Print only the sanitized text")
    p.add_argument("--inspect", action="store_true",
                   help="Use the bounded, preserve-only policy API (ASCII JSON)")
    args = p.parse_args(argv)

    if args.inspect:
        if args.sanitize:
            p.error("--inspect cannot be combined with --sanitize")
        limits = Limits()
        if args.file:
            try:
                with open(args.file, "rb") as fh:
                    raw = fh.read(limits.max_input_bytes + 1)
            except OSError:
                report = _held(POLICY_IDS[Policy.BALANCED], "error", "INPUT_IO_ERROR", limits)
            else:
                report = inspect_bytes(raw, limits=limits)
        elif args.input == "-" or (args.input is None and not sys.stdin.isatty()):
            try:
                raw = sys.stdin.buffer.read(limits.max_input_bytes + 1)
            except OSError:
                report = _held(POLICY_IDS[Policy.BALANCED], "error", "INPUT_IO_ERROR", limits)
            else:
                report = inspect_bytes(raw, limits=limits)
        elif args.input is not None:
            report = inspect_text(args.input, limits=limits)
        else:
            p.error("provide text, -f FILE, or pipe stdin")
        print(report.to_json())
        return 0 if report.action == "allow" else 3 if report.status == "complete" else 4

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    elif args.input == "-" or (args.input is None and not sys.stdin.isatty()):
        text = sys.stdin.read()
    elif args.input:
        text = args.input
    else:
        p.error("provide text, -f FILE, or pipe stdin")

    report = analyze(text)
    if args.sanitize:
        print(report.sanitized)
    else:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    return 0 if report.verdict == "clean" else 2


if __name__ == "__main__":
    sys.exit(main())
