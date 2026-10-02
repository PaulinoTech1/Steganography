"""Observe bounded Unicode decisions on consented local JSONL, without forwarding.

This is a replay instrument, not proof that a production pipeline used it.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import sys
from time import perf_counter_ns
from typing import BinaryIO, TextIO

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stegdetect import Policy, inspect_bytes  # noqa: E402
from stegdetect.policy import POLICY_IDS  # noqa: E402


MAX_LINE_BYTES = 16_777_216
MAX_TOTAL_BYTES = 536_870_912
MAX_RECORDS = 10_000
_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(fraction * len(ordered)) - 1]


def _event(index: int, source_id: str | None, status: str,
           action: str | None, reasons: list[str], *,
           finding_count: int = 0, categories: dict | None = None,
           elapsed_ms: float | None = None, input_bytes: int | None = None) -> dict:
    return {"record_index": index, "source_id": source_id, "status": status,
            "action": action, "reason_codes": reasons,
            "finding_count_total": finding_count,
            "category_counts": categories or {}, "elapsed_ms": elapsed_ms,
            "input_bytes": input_bytes}


def run_shadow(source: BinaryIO, *, policy: Policy, pipeline_id: str,
               events: TextIO | None = None, max_records: int = MAX_RECORDS,
               max_total_bytes: int = MAX_TOTAL_BYTES,
               max_line_bytes: int = MAX_LINE_BYTES) -> dict:
    """Inspect one original document per record; emit no source/candidate text."""
    if not _OPAQUE_ID.fullmatch(pipeline_id):
        raise ValueError("pipeline_id must be an opaque ASCII identifier")
    if min(max_records, max_total_bytes, max_line_bytes) < 1:
        raise ValueError("trusted limits must be positive")
    if not isinstance(policy, Policy):
        raise TypeError("policy must be selected by the caller")
    counts: Counter[str] = Counter()
    timings: list[float] = []
    seen_ids: set[str] = set()
    bytes_read = 0
    processed = 0
    incomplete_reason = None
    for index in range(1, max_records + 1):
        raw = source.readline(max_line_bytes + 2)
        if not raw:
            break
        bytes_read += len(raw)
        if bytes_read > max_total_bytes:
            incomplete_reason = "BATCH_INPUT_LIMIT"
            break
        if len(raw.rstrip(b"\n")) > max_line_bytes:
            incomplete_reason = "RECORD_BYTE_LIMIT"
            break
        processed += 1
        source_id = None
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            event = _event(index, None, "invalid_input", None, ["INVALID_JSON"])
        else:
            if not isinstance(value, dict) or set(value) != {"source_id", "text"}:
                event = _event(index, None, "invalid_input", None, ["INVALID_RECORD"])
            elif not isinstance(value["source_id"], str) or not _OPAQUE_ID.fullmatch(value["source_id"]):
                event = _event(index, None, "invalid_input", None, ["INVALID_SOURCE_ID"])
            elif value["source_id"] in seen_ids:
                event = _event(index, None, "invalid_input", None, ["DUPLICATE_SOURCE_ID"])
            elif not isinstance(value["text"], str):
                event = _event(index, None, "invalid_input", None, ["INVALID_TEXT"])
            else:
                source_id = value["source_id"]
                seen_ids.add(source_id)
                try:
                    data = value["text"].encode("utf-8", "strict")
                except UnicodeEncodeError:
                    event = _event(index, source_id, "invalid_input", None,
                                   ["INVALID_UNICODE"])
                else:
                    start = perf_counter_ns()
                    report = inspect_bytes(data, policy=policy)
                    elapsed_ms = (perf_counter_ns() - start) / 1_000_000
                    timings.append(elapsed_ms)
                    event = _event(index, source_id, report.status, report.action,
                                   list(report.reason_codes),
                                   finding_count=report.finding_count_total,
                                   categories=dict(report.category_counts),
                                   elapsed_ms=round(elapsed_ms, 6),
                                   input_bytes=len(data))
        counts[event["action"] or event["status"]] += 1
        if event["status"] != "complete" or event["action"] is None:
            incomplete_reason = incomplete_reason or "INCOMPLETE_INSPECTION"
        if events is not None:
            events.write(json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        if source.read(1):
            incomplete_reason = "BATCH_RECORD_LIMIT"
    if processed == 0 and incomplete_reason is None:
        incomplete_reason = "EMPTY_REPLAY"
    return {
        "schema_version": 1, "kind": "local_shadow_replay",
        "pipeline_id": pipeline_id,
        "policy_id": POLICY_IDS[policy],
        "status": "incomplete" if incomplete_reason else "replay_complete",
        "incomplete_reason": incomplete_reason,
        "processed_records": processed, "input_bytes_read": bytes_read,
        "action_or_status_counts": dict(sorted(counts.items())),
        "scan_latency_ms": {"sample_count": len(timings),
                            "median": _percentile(timings, .5),
                            "p95_nearest_rank": _percentile(timings, .95)},
        "labels_reviewed": 0, "independent_users": 0,
        "production_pipeline_verified": False,
        "release_claim_supported": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Local UTF-8 JSONL replay file")
    parser.add_argument("--summary", required=True, help="New content-free summary JSON file")
    parser.add_argument("--events", help="New metadata-only JSONL event file (optional)")
    parser.add_argument("--pipeline-id", required=True, help="Opaque pipeline identifier")
    parser.add_argument("--policy", choices=["balanced", "contextual"], default="balanced")
    args = parser.parse_args(argv)
    paths = [Path(args.input).resolve(), Path(args.summary).resolve()]
    if args.events:
        paths.append(Path(args.events).resolve())
    if len(set(paths)) != len(paths):
        parser.error("input, summary, and events paths must differ")
    policy = Policy.CONTEXTUAL if args.policy == "contextual" else Policy.BALANCED
    try:
        if args.events:
            with Path(args.input).open("rb") as source, Path(args.events).open("x", encoding="utf-8") as events:
                summary = run_shadow(source, policy=policy, pipeline_id=args.pipeline_id,
                                     events=events)
        else:
            with Path(args.input).open("rb") as source:
                summary = run_shadow(source, policy=policy, pipeline_id=args.pipeline_id)
        with Path(args.summary).open("x", encoding="utf-8") as output:
            json.dump(summary, output, ensure_ascii=True, indent=2, sort_keys=True)
            output.write("\n")
    except (OSError, ValueError, TypeError):
        print("shadow replay failed; discard any partial output", file=sys.stderr)
        return 4
    print(f"shadow replay {summary['status']}; {summary['processed_records']} records; no release claim")
    return 0 if summary["status"] == "replay_complete" else 4


if __name__ == "__main__":
    raise SystemExit(main())
