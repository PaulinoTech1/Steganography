"""CLI: scan text or files, print JSON report."""
from __future__ import annotations

import argparse
import json
import sys

from .report import analyze


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stegdetect",
                                description="Detect steganographic prompt-injection carriers in text.")
    p.add_argument("input", nargs="?", help="Text to scan, or - for stdin")
    p.add_argument("-f", "--file", help="Read input from file")
    p.add_argument("--sanitize", action="store_true",
                   help="Print only the sanitized text")
    args = p.parse_args(argv)

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
