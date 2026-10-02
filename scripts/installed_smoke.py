"""Execute inside an isolated venv from a directory outside the source checkout."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from baseline_corpus import measure
import stegdetect
from stegdetect import Policy, analyze, inspect_text


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: installed_smoke.py REPO_ROOT")
    root = Path(sys.argv[1]).resolve()
    package_path = Path(stegdetect.__file__).resolve()
    if package_path.is_relative_to(root):
        raise RuntimeError(f"source import leaked into installed smoke: {package_path}")
    if not package_path.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError(f"not importing from isolated environment: {package_path}")
    manifest = json.loads((root / "evals" / "manifest.json").read_text(encoding="utf-8"))
    for fixture in manifest["fixtures"]:
        report = analyze(fixture["text"])
        actual = {"verdict": report.verdict,
                  "categories": sorted({finding.category for finding in report.findings}),
                  "finding_count": len(report.findings), "sanitized": report.sanitized}
        if actual != fixture["expected_legacy"]:
            raise AssertionError(f"installed API mismatch: {fixture['id']}")
        for policy, key in ((Policy.BALANCED, "balanced"),
                            (Policy.LEGACY_VERDICT, "legacy_verdict")):
            inspected = inspect_text(fixture["text"], policy=policy)
            if (inspected.status != "complete" or
                    inspected.action != fixture["expected_actions"][key] or
                    inspected.candidate_text != (fixture["text"] if inspected.action == "allow" else None)):
                raise AssertionError(f"installed policy mismatch: {key}/{fixture['id']}")
    snapshot = json.loads((root / "evals" / "fixtures" / "legacy_cli.json").read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != 1 or not snapshot.get("cases"):
        raise AssertionError("CLI snapshot missing or malformed")
    console = Path(sys.prefix) / ("Scripts/stegdetect.exe" if os.name == "nt" else "bin/stegdetect")
    if not console.is_file():
        raise AssertionError(f"installed console entry missing: {console}")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONIOENCODING"] = "utf-8"
    for case in snapshot["cases"]:
        proc = subprocess.run([str(console), *case["argv"]], cwd=Path.cwd(), env=env,
                              capture_output=True, text=True, encoding="utf-8", timeout=20)
        if proc.returncode != case["exit_code"] or json.loads(proc.stdout) != case["report"]:
            raise AssertionError(f"installed CLI mismatch: {case['argv']!r}, {proc.stderr!r}")
    corpus = measure(root / "tests" / "test_false_positives.py")
    expected = json.loads((root / "docs" / "robustness-corpus.json").read_text(encoding="utf-8"))
    if corpus != expected:
        raise AssertionError("installed legacy corpus counts changed")
    print(json.dumps({"installed_module": str(package_path), "api_fixtures": len(manifest["fixtures"]),
                      "policy_cases": len(manifest["fixtures"]) * 2,
                      "cli_cases": len(snapshot["cases"]), "corpus": corpus}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
