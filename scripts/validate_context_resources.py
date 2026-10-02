"""Check complete context measurements and measured-source hashes offline."""
from __future__ import annotations

import json
import math
from pathlib import Path
import statistics
import sys


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "p3-context-results.json"


def verify_context_resources(data: dict | None = None) -> dict:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from benchmarks.context_resources import CASES, SIZE, source_hashes, workload

    if data is None:
        data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    if (data.get("method_version") != 1 or data.get("policy_id") != "contextual-v1" or
            data.get("trials_per_case") != 10 or data.get("warmups_per_case") != 2 or
            data.get("source_sha256") != source_hashes()):
        raise ValueError("context resource metadata or measured source changed")
    rows = data.get("rows", [])
    if len(rows) != len(CASES) or {row["case"] for row in rows} != set(CASES):
        raise ValueError("context resource rows missing or duplicated")
    for row in rows:
        text, action, count = workload(row["case"])
        times = row["raw_seconds"]
        if (row["chars"] != SIZE or len(text) != SIZE or
                row["expected_action"] != action or row["expected_findings"] != count or
                row["trials"] != 10 or len(times) != 10 or row["timeout_count"] != 0 or
                any(not isinstance(t, (int, float)) or not math.isfinite(t) or t < 0
                    for t in times) or
                not 0 < row["output_bytes"] <= 16_777_216 or
                row["baseline_peak_rss_bytes"] <= 0 or
                row["peak_rss_bytes"] < row["baseline_peak_rss_bytes"]):
            raise ValueError(f"invalid context resource row: {row['case']}")
        ordered = sorted(times)
        if (not math.isclose(row["median_seconds"], statistics.median(ordered), abs_tol=1e-9) or
                not math.isclose(row["p95_nearest_rank_seconds"], ordered[9], abs_tol=1e-9) or
                not math.isclose(row["max_seconds"], ordered[-1], abs_tol=1e-9)):
            raise ValueError(f"context timing summary disagrees with raw trials: {row['case']}")
    return {"rows": len(rows), "trials": 40, "timeouts": 0,
            "max_p95_seconds": max(row["p95_nearest_rank_seconds"] for row in rows),
            "max_peak_rss_bytes": max(row["peak_rss_bytes"] for row in rows)}


if __name__ == "__main__":
    print(json.dumps({"status": "PASS", **verify_context_resources()}, sort_keys=True))
