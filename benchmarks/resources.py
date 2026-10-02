"""P2 resource study in killable worker processes.

Full run: python benchmarks/resources.py --output docs/p2-resource-results.json
Use --cases/--sizes for a clearly labeled subset. Runtime JSON includes raw trials.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import unicodedata


ROOT = Path(__file__).resolve().parents[1]
CASES = ("ordinary", "zero_width", "nested_bidi", "mixed_script",
         "compatibility_combining", "emoji", "late_override")
SIZES = (16_384, 65_536, 1_048_576)


def workload(case: str, size: int) -> str:
    if case == "ordinary":
        return ("Please summarize this report. " * (size // 30 + 1))[:size]
    if case == "zero_width":
        return "\u200b" * size
    if case == "nested_bidi":
        return "\u202e" * (size // 2) + "\u202c" * (size - size // 2)
    if case == "mixed_script":
        return ("a\u0430" * (size // 2 + 1))[:size]
    if case == "compatibility_combining":
        return "a" + ("\uff9e\u0334" * (size // 2 + 1))[:size - 1]
    if case == "emoji":
        return "\U0001f468" * size
    if case == "late_override":
        return "\u00a0" * (size - 1) + "\u202e"
    raise ValueError(case)


def expected(case: str, size: int) -> tuple[str, int]:
    if case in ("ordinary", "compatibility_combining", "emoji"):
        return "allow", 0
    if case == "zero_width":
        return "review", size
    if case == "mixed_script":
        return "review", size // 2
    return "block", size


def peak_rss_bytes() -> int:
    """OS-reported process peak working set/RSS, including interpreter and input."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        counts = Counters()
        counts.cb = ctypes.sizeof(Counters)
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(),
                                         ctypes.byref(counts), counts.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return counts.PeakWorkingSetSize
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def worker(case: str, size: int, mode: str, warmups: int, trials: int) -> dict:
    from stegdetect import inspect_text

    baseline = peak_rss_bytes()
    text = workload(case, size)
    assert len(text) == size
    action, count = expected(case, size)

    def exercise() -> tuple[float, int]:
        started = time.perf_counter()
        report = inspect_text(text)
        payload = report.to_json()
        elapsed = time.perf_counter() - started
        if (report.status != "complete" or report.action != action or
                report.finding_count_total != count or
                len(report.findings) > 256 or not report.scan_complete or
                report.candidate_text != (text if action == "allow" else None)):
            raise AssertionError(f"report mismatch for {case}/{size}")
        if case == "late_override" and not any(
                finding.offset == size - 1 for finding in report.findings):
            raise AssertionError("late deciding carrier lost after evidence cap")
        if len(payload.encode("ascii")) > 16_777_216:
            raise AssertionError("serialized output exceeded default cap")
        return elapsed, len(payload)

    times = []
    if mode == "latency":
        for _ in range(warmups):
            exercise()
        for _ in range(trials):
            elapsed, output_bytes = exercise()
            times.append(elapsed)
    else:
        _, output_bytes = exercise()
    return {"case": case, "chars": size, "input_utf8_bytes": len(text.encode("utf-8")),
            "mode": mode, "times_seconds": times, "output_bytes": output_bytes,
            "expected_action": action, "expected_findings": count,
            "baseline_peak_rss_bytes": baseline, "peak_rss_bytes": peak_rss_bytes()}


def child(case: str, size: int, mode: str, warmups: int, trials: int, deadline: int) -> dict:
    args = [sys.executable, str(Path(__file__).resolve()), "--worker-case", case,
            "--worker-size", str(size), "--worker-mode", mode,
            "--warmups", str(warmups), "--worker-trials", str(trials)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                            text=True, encoding="utf-8", timeout=deadline)
    if result.returncode:
        raise RuntimeError(f"worker failed: {args!r}\n{result.stderr[-1500:]}")
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-case", choices=CASES)
    parser.add_argument("--worker-size", type=int)
    parser.add_argument("--worker-mode", choices=("latency", "memory"))
    parser.add_argument("--worker-trials", type=int, default=0)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--sizes", nargs="+", type=int, default=list(SIZES))
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--trials-small", type=int, default=100)
    parser.add_argument("--trials-large", type=int, default=30)
    parser.add_argument("--deadline", type=int, default=180)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker_case:
        print(json.dumps(worker(args.worker_case, args.worker_size, args.worker_mode,
                                args.warmups, args.worker_trials)))
        return 0
    if args.workers < 1 or args.deadline < 1 or min(args.sizes) < 1:
        parser.error("workers, deadline and sizes must be positive")
    results = {"method_version": 1, "python": sys.version, "platform": platform.platform(),
               "processor": platform.processor(), "logical_cpus": os.cpu_count(),
               "unicode_version": unicodedata.unidata_version,
               "warmups_per_latency_worker": args.warmups,
               "workers": args.workers, "deadline_seconds_per_worker": args.deadline,
               "serialization": "compact ASCII JSON via InspectionReport.to_json",
               "cases": args.cases, "sizes": args.sizes, "rows": []}
    try:
        for case in args.cases:
            for size in args.sizes:
                trials = args.trials_large if size >= 1_048_576 else args.trials_small
                counts = [trials // args.workers + (index < trials % args.workers)
                          for index in range(args.workers)]
                latency = [child(case, size, "latency", args.warmups, count, args.deadline)
                           for count in counts if count]
                memory = child(case, size, "memory", 0, 0, args.deadline)
                times = sorted(t for run in latency for t in run["times_seconds"])
                row = {"case": case, "chars": size, "input_utf8_bytes": memory["input_utf8_bytes"],
                       "expected_action": memory["expected_action"],
                       "expected_findings": memory["expected_findings"],
                       "trials": len(times), "raw_seconds": times,
                       "median_seconds": statistics.median(times),
                       "p95_nearest_rank_seconds": times[math.ceil(0.95 * len(times)) - 1],
                       "max_seconds": times[-1], "timeout_count": 0,
                       "baseline_peak_rss_bytes": memory["baseline_peak_rss_bytes"],
                       "peak_rss_bytes": memory["peak_rss_bytes"],
                       "output_bytes": memory["output_bytes"]}
                results["rows"].append(row)
                print(json.dumps({key: value for key, value in row.items()
                                  if key != "raw_seconds"}), flush=True)
    except (subprocess.TimeoutExpired, RuntimeError, AssertionError) as error:
        results["failure"] = str(error)
        if args.output:
            args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"resource study failed: {error}", file=sys.stderr)
        return 1
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
