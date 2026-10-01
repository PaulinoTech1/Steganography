"""Measured workloads in isolated children. Times exclude process startup.

Run: python benchmarks/robustness.py --output docs/robustness-results.json
"""
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


CASES = ("ascii", "surrogates", "nested_bidi", "mixed_script",
         "combining", "compatibility_combining", "zero_width", "tags")


def workload(name, n):
    if name == "ascii":
        return ("Please summarize the report. " * (n // 28 + 1))[:n]
    if name == "surrogates":
        return ("a\ud800\udfff" * (n // 3 + 1))[:n]
    if name == "nested_bidi":
        return "\u202e" * (n // 2) + "\u202c" * (n - n // 2)
    if name == "mixed_script":
        return ("a\u0430" * (n // 2 + 1))[:n]
    if name == "combining":
        return "a" + ("\u0315\u0300" * (n // 2 + 1))[:n - 1]
    if name == "compatibility_combining":
        # Halfwidth voiced mark has class zero until NFKD decomposes it.
        return "a" + ("\uff9e\u0334" * (n // 2 + 1))[:n - 1]
    if name == "zero_width":
        return "\u200b" * n
    if name == "tags":
        return "\U000e0061" * n
    raise ValueError(name)


def measure(name, n, repeats, baseline):
    from stegdetect import analyze
    if baseline:
        import stegdetect.canonicalize as module
        import unicodedata
        module._nfkc = lambda text: unicodedata.normalize("NFKC", text)
    text = workload(name, n)
    timings = []
    for _ in range(repeats):
        start = time.perf_counter()
        report = analyze(text)
        timings.append(time.perf_counter() - start)
        expected = "malicious" if name in {"nested_bidi", "mixed_script", "zero_width", "tags"} else "clean"
        assert report.verdict == expected
        assert report.stats["input_chars"] == n
        count = len(report.findings)
        del report  # don't keep two million-finding reports live during timing
    return {"case": name, "chars": n, "seconds": timings,
            "median_seconds": statistics.median(timings), "finding_count": count}


def isolated(name, n, repeats=3, timeout=30, baseline=False):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", name,
               "--size", str(n), "--repeats", str(repeats)]
    if baseline:
        command.append("--baseline")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                            check=True, env=env)
    return json.loads(result.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--worker", choices=CASES)
    p.add_argument("--size", type=int, default=1048576)
    p.add_argument("--sizes", type=int, nargs="+", default=[262144, 524288, 1048576])
    p.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--baseline", action="store_true", help="Use original stdlib NFKC path")
    p.add_argument("--output")
    args = p.parse_args()
    if args.worker:
        print(json.dumps(measure(args.worker, args.size, args.repeats, args.baseline)))
        return
    results = {"python": sys.version, "platform": platform.platform(),
               "unicode_version": __import__("unicodedata").unidata_version,
               "baseline_normalization": args.baseline, "timeout_seconds": args.timeout,
               "repeats": args.repeats, "rows": []}
    for name in args.cases:
        for n in args.sizes:
            try:
                row = isolated(name, n, args.repeats, args.timeout, args.baseline)
            except subprocess.TimeoutExpired:
                row = {"case": name, "chars": n, "timeout": True}
            results["rows"].append(row)
            print(json.dumps(row), flush=True)
    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
