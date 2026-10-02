"""Validate the P2 raw resource artifact and bind it to the measured code.

Use --record only after a successful full benchmarks/resources.py run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "p2-resource-results.json"
RECEIPT = ROOT / "docs" / "p2-resource-receipt.json"
SOURCES = (
    "src/stegdetect/inspection.py", "src/stegdetect/bounded_scan.py",
    "src/stegdetect/policy.py", "src/stegdetect/unicode_scan.py",
    "benchmarks/resources.py",
)
CASES = ("ordinary", "zero_width", "nested_bidi", "mixed_script",
         "compatibility_combining", "emoji", "late_override")
SIZES = (16_384, 65_536, 1_048_576)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_structure(data: dict) -> dict:
    if (data.get("method_version") != 1 or data.get("workers") != 2 or
            data.get("warmups_per_latency_worker") != 5 or
            data.get("cases") != list(CASES) or data.get("sizes") != list(SIZES) or
            data.get("failure")):
        raise ValueError("resource study profile incomplete or failed")
    rows = data.get("rows", [])
    if len(rows) != len(CASES) * len(SIZES):
        raise ValueError("resource study has missing workload rows")
    seen = set()
    trials_total = 0
    for row in rows:
        key = (row["case"], row["chars"])
        if key in seen or key not in {(case, size) for case in CASES for size in SIZES}:
            raise ValueError(f"unknown or duplicate workload row: {key}")
        seen.add(key)
        case, size = key
        expected_action = ("allow" if case in ("ordinary", "compatibility_combining", "emoji")
                           else "review" if case in ("zero_width", "mixed_script") else "block")
        expected_count = (0 if expected_action == "allow" else
                          size // 2 if case == "mixed_script" else size)
        if row["expected_action"] != expected_action or row["expected_findings"] != expected_count:
            raise ValueError(f"workload result was not content-validated: {key}")
        times = row["raw_seconds"]
        target = 30 if size >= 1_048_576 else 100
        if (row["trials"] != target or len(times) != target or
                row["timeout_count"] != 0 or
                any(not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0
                    for value in times)):
            raise ValueError(f"missing/invalid timing trials: {key}")
        ordered = sorted(times)
        if (not math.isclose(row["median_seconds"], statistics.median(ordered), abs_tol=1e-9) or
                not math.isclose(row["p95_nearest_rank_seconds"],
                                 ordered[math.ceil(0.95 * target) - 1], abs_tol=1e-9) or
                not math.isclose(row["max_seconds"], ordered[-1], abs_tol=1e-9)):
            raise ValueError(f"timing summary disagrees with raw trials: {key}")
        if (row["baseline_peak_rss_bytes"] <= 0 or
                row["peak_rss_bytes"] < row["baseline_peak_rss_bytes"] or
                not 0 < row["output_bytes"] <= 16_777_216 or
                not 0 < row["input_utf8_bytes"] <= 4_194_304):
            raise ValueError(f"invalid resource units or output budget: {key}")
        trials_total += target
    return {"rows": len(rows), "trials": trials_total,
            "timeouts": sum(row["timeout_count"] for row in rows),
            "max_peak_rss_bytes": max(row["peak_rss_bytes"] for row in rows),
            "max_p95_seconds": max(row["p95_nearest_rank_seconds"] for row in rows)}


def expected_receipt() -> dict:
    return {"schema_version": 1, "artifact_sha256": digest(ARTIFACT),
            "source_sha256": {relative: digest(ROOT / relative) for relative in SOURCES}}


def verify_receipt(receipt: dict) -> None:
    if receipt != expected_receipt():
        raise ValueError("resource receipt or measured source changed; rerun full profile")


def verify_resource_artifact() -> dict:
    summary = verify_structure(json.loads(ARTIFACT.read_text(encoding="utf-8")))
    verify_receipt(json.loads(RECEIPT.read_text(encoding="utf-8")))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true",
                        help="Bind a completed local full-profile artifact to source hashes")
    args = parser.parse_args()
    try:
        data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        summary = verify_structure(data)
        expected = expected_receipt()
        if args.record:
            RECEIPT.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        else:
            verify_receipt(json.loads(RECEIPT.read_text(encoding="utf-8")))
        print(json.dumps({"status": "PASS", **summary}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"resource validation FAILED: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
