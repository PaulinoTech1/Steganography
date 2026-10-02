"""Small, killable resource study for opt-in Unicode context inspection."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

if __package__:
    from .resources import peak_rss_bytes
else:
    from resources import peak_rss_bytes


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "p3-context-results.json"
SIZE = 1_048_576
CASES = ("family", "persian", "rtl", "stray_joiner")
SOURCES = (
    "src/stegdetect/inspection.py", "src/stegdetect/bounded_scan.py",
    "src/stegdetect/policy.py", "src/stegdetect/unicode_context.py",
    "src/stegdetect/unicode_scan.py", "src/stegdetect/data/emoji-context-18.0.txt",
    "benchmarks/resources.py", "benchmarks/context_resources.py",
)


def source_hashes() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCES}


def workload(case: str) -> tuple[str, str, int]:
    units = {
        "family": ("\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466", "allow", 3),
        "persian": ("\u0645\u06cc\u200c\u0631\u0648\u0645", "allow", 1),
        "rtl": ("\u2067\u05e9\u05dc\u05d5\u05dd\u2069", "allow", 2),
        "stray_joiner": ("a\u200db", "review", 1),
    }
    unit, action, count = units[case]
    repeats = SIZE // len(unit)
    text = unit * repeats + " " * (SIZE % len(unit))
    return text, action, count * repeats


def worker(case: str, trials: int, warmups: int) -> dict:
    from stegdetect import Policy, inspect_text

    baseline = peak_rss_bytes()
    text, action, count = workload(case)
    assert len(text) == SIZE

    def exercise() -> tuple[float, int]:
        start = time.perf_counter()
        report = inspect_text(text, policy=Policy.CONTEXTUAL)
        payload = report.to_json()
        elapsed = time.perf_counter() - start
        if (report.status != "complete" or report.action != action or
                report.finding_count_total != count or
                report.candidate_text != (text if action == "allow" else None) or
                len(report.findings) > 256):
            raise AssertionError(f"context workload outcome mismatch: {case}")
        return elapsed, len(payload)

    for _ in range(warmups):
        exercise()
    times = []
    for _ in range(trials):
        elapsed, output_bytes = exercise()
        times.append(elapsed)
    return {"case": case, "chars": len(text), "expected_action": action,
            "expected_findings": count, "raw_seconds": times,
            "output_bytes": output_bytes, "baseline_peak_rss_bytes": baseline,
            "peak_rss_bytes": peak_rss_bytes()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-case", choices=CASES)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--deadline", type=int, default=120)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.trials < 1 or args.warmups < 0 or args.deadline < 1:
        parser.error("trials and deadline must be positive; warmups nonnegative")
    if args.worker_case:
        print(json.dumps(worker(args.worker_case, args.trials, args.warmups)))
        return 0
    before = source_hashes()
    rows = []
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    try:
        for case in CASES:
            argv = [sys.executable, str(Path(__file__).resolve()),
                    "--worker-case", case, "--trials", str(args.trials),
                    "--warmups", str(args.warmups)]
            proc = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                                  text=True, encoding="utf-8", timeout=args.deadline)
            if proc.returncode:
                raise RuntimeError(f"{case} failed: {proc.stderr[-1500:]}")
            row = json.loads(proc.stdout)
            times = sorted(row["raw_seconds"])
            row.update(trials=len(times), median_seconds=statistics.median(times),
                       p95_nearest_rank_seconds=times[math.ceil(0.95 * len(times)) - 1],
                       max_seconds=times[-1], timeout_count=0)
            rows.append(row)
            print(json.dumps({k: v for k, v in row.items() if k != "raw_seconds"}), flush=True)
    except (subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
        print(f"context resource study failed: {error}", file=sys.stderr)
        return 1
    if before != source_hashes():
        print("measured source changed during context study", file=sys.stderr)
        return 1
    data = {"method_version": 1, "platform": platform.platform(), "python": sys.version,
            "policy_id": "contextual-v1", "trials_per_case": args.trials,
            "warmups_per_case": args.warmups, "deadline_seconds_per_worker": args.deadline,
            "source_sha256": before, "rows": rows}
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
