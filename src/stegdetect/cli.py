"""CLI: scan text or files, print JSON report."""
from __future__ import annotations

import argparse
import json
import sys
from typing import BinaryIO

from .report import analyze
from .inspection import Limits, _held, inspect_bytes, inspect_text
from .policy import POLICY_IDS, Policy
from .reasons import REASON_EXPLANATIONS


_BATCH_BYTE_LIMIT = 67_108_864

# Nesting deeper than this is held outright. Newer json scanners parse input
# that older ones reject with RecursionError, so the bound is enforced here
# instead of relying on version-dependent parser behavior.
_MAX_JSON_NESTING_DEPTH = 200


def _json_nesting_depth(value) -> int:
    """Depth of nested lists/dicts; scalars are depth 0.

    Iterative on purpose: the C scanner now accepts nesting deeper than
    Python's recursion limit, so a recursive walk would crash on exactly
    the input this guard exists to hold.
    """
    max_depth = 0
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, list):
            if depth > max_depth:
                max_depth = depth
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, dict):
            if depth > max_depth:
                max_depth = depth
            stack.extend((item, depth + 1) for item in node.values())
    return max_depth


def _exit_code(report) -> int:
    return 0 if report.action == "allow" else 3 if report.status == "complete" else 4


def _emit(report, explain: bool, record: int | None = None,
          payload: str | None = None) -> int:
    print(report.to_json() if payload is None else payload)
    if explain:
        label = f"record {record}: " if record is not None else ""
        reasons = "; ".join(REASON_EXPLANATIONS.get(code, code.replace("_", " ").lower())
                            for code in report.reason_codes)
        print(f"{label}{report.status} / {report.action or 'held'}: {reasons} "
              f"({report.finding_count_total} findings; "
              f"{'candidate available' if report.candidate_text is not None else 'no forwarding candidate'})",
              file=sys.stderr)
    return _exit_code(report)


def _inspect_jsonl(source: BinaryIO, policy: Policy, limits: Limits,
                   explain: bool, max_records: int,
                   batch_input_byte_limit: int = _BATCH_BYTE_LIMIT,
                   batch_output_byte_limit: int = _BATCH_BYTE_LIMIT) -> int:
    """One JSON string per line; no document metadata controls trusted policy."""
    exit_code = 0
    input_bytes = output_bytes = 0
    for record in range(1, max_records + 1):
        raw = source.readline(limits.max_input_bytes + 2)
        if not raw:
            if record == 1:
                if explain:
                    print("empty document batch; no whole-batch authorization",
                          file=sys.stderr)
                return 4
            return exit_code
        input_bytes += len(raw)
        if input_bytes > batch_input_byte_limit:
            if explain:
                print("batch input byte limit exceeded; no whole-batch authorization",
                      file=sys.stderr)
            return 4
        line = raw[:-1] if raw.endswith(b"\n") else raw
        if len(line) > limits.max_input_bytes:
            report = _held(POLICY_IDS[policy], "limit_exceeded", "INPUT_BYTE_LIMIT", limits)
            _emit(report, explain, record)
            return 4
        try:
            value = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            report = _held(POLICY_IDS[policy], "invalid_input", "INVALID_JSON", limits)
        else:
            if _json_nesting_depth(value) > _MAX_JSON_NESTING_DEPTH:
                report = _held(POLICY_IDS[policy], "invalid_input", "INVALID_JSON", limits)
            else:
                report = (inspect_text(value, policy=policy, limits=limits)
                          if isinstance(value, str) else
                          _held(POLICY_IDS[policy], "invalid_input", "INVALID_TYPE", limits))
        payload = report.to_json()
        output_bytes += len(payload) + 1
        if output_bytes > batch_output_byte_limit:
            if explain:
                print("batch output byte limit exceeded; no whole-batch authorization",
                      file=sys.stderr)
            return 4
        exit_code = max(exit_code, _emit(report, explain, record, payload))
    if source.read(1):
        if explain:
            print("batch record limit exceeded; no whole-batch authorization", file=sys.stderr)
        return 4
    return exit_code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stegdetect",
                                description="Detect steganographic prompt-injection carriers in text.")
    p.add_argument("input", nargs="?", help="Text to scan, or - for stdin")
    p.add_argument("-f", "--file", help="Read input from file")
    p.add_argument("--sanitize", action="store_true",
                   help="Print only the sanitized text")
    p.add_argument("--inspect", action="store_true",
                   help="Use the bounded, preserve-only policy API (ASCII JSON)")
    p.add_argument("--contextual", action="store_true",
                   help="With --inspect, opt in to Emoji 18 and narrow joiner/isolate contexts")
    p.add_argument("--explain", action="store_true",
                   help="With --inspect, print ASCII-safe decision explanations to stderr")
    p.add_argument("--jsonl", action="store_true",
                   help="With --inspect, stream one UTF-8 JSON string per document line")
    p.add_argument("--max-records", type=int, default=1000,
                   help="Maximum JSONL documents to inspect (default: 1000)")
    args = p.parse_args(argv)

    if (args.contextual or args.explain or args.jsonl or args.max_records != 1000) and not args.inspect:
        p.error("--contextual, --explain, --jsonl and --max-records require --inspect")
    if args.max_records < 1:
        p.error("--max-records must be positive")
    if args.inspect:
        if args.sanitize:
            p.error("--inspect cannot be combined with --sanitize")
        limits = Limits()
        policy = Policy.CONTEXTUAL if args.contextual else Policy.BALANCED
        if args.jsonl:
            if args.input not in (None, "-"):
                p.error("--jsonl accepts -f FILE or stdin, not positional text")
            if args.file:
                try:
                    with open(args.file, "rb") as fh:
                        return _inspect_jsonl(fh, policy, limits, args.explain,
                                              args.max_records)
                except OSError:
                    return _emit(_held(POLICY_IDS[policy], "error", "INPUT_IO_ERROR", limits),
                                 args.explain)
            if args.input == "-" or not sys.stdin.isatty():
                try:
                    return _inspect_jsonl(sys.stdin.buffer, policy, limits,
                                          args.explain, args.max_records)
                except OSError:
                    return _emit(_held(POLICY_IDS[policy], "error", "INPUT_IO_ERROR", limits),
                                 args.explain)
            p.error("provide -f FILE or pipe JSONL on stdin")
        if args.file:
            try:
                with open(args.file, "rb") as fh:
                    raw = fh.read(limits.max_input_bytes + 1)
            except OSError:
                report = _held(POLICY_IDS[policy], "error", "INPUT_IO_ERROR", limits)
            else:
                report = inspect_bytes(raw, limits=limits, policy=policy)
        elif args.input == "-" or (args.input is None and not sys.stdin.isatty()):
            try:
                raw = sys.stdin.buffer.read(limits.max_input_bytes + 1)
            except OSError:
                report = _held(POLICY_IDS[policy], "error", "INPUT_IO_ERROR", limits)
            else:
                report = inspect_bytes(raw, limits=limits, policy=policy)
        elif args.input is not None:
            report = inspect_text(args.input, limits=limits, policy=policy)
        else:
            p.error("provide text, -f FILE, or pipe stdin")
        return _emit(report, args.explain)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    elif args.input == "-" or (args.input is None and not sys.stdin.isatty()):
        text = sys.stdin.read()
    elif args.input:
        text = args.input
    else:
        p.error("provide text, -f FILE, or pipe stdin")

    try:
        report = analyze(text)
    except (TypeError, ValueError) as exc:
        print(f"stegdetect: input rejected: {exc}", file=sys.stderr)
        return 2
    if args.sanitize:
        print(report.sanitized)
    else:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    return 0 if report.verdict == "clean" else 2


if __name__ == "__main__":
    sys.exit(main())
