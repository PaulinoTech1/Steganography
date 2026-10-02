"""P0 baseline validator. Other planned release profiles are not implemented yet.

Run from any directory: python scripts/validate_release.py --profile baseline
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import venv


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from baseline_corpus import measure  # noqa: E402
from evaluate import evaluate_manifest, evaluate_policy_actions, load_json, validate_rule_map, verify_protected_tests, verify_split_manifest  # noqa: E402
from validate_resources import verify_resource_artifact  # noqa: E402


def run(argv: list[str], *, cwd: Path, timeout: int = 240) -> str:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"command failed ({proc.returncode}): {argv!r}\n"
                           f"stdout: {proc.stdout[-4000:]}\nstderr: {proc.stderr[-4000:]}")
    return proc.stdout


def verify_claims(claims: dict, metrics: dict) -> int:
    if claims.get("schema_version") != 1 or not claims.get("claims"):
        raise ValueError("claims map missing or wrong version")
    for name, claim in claims["claims"].items():
        metric = claim["metric"]
        if metric not in metrics or metrics[metric] != claim["expected"]:
            raise ValueError(f"claim unsupported or changed: {name}/{metric}")
    return len(claims["claims"])


def prove_negative_controls(manifest: dict, protected: Path, claims: dict, metrics: dict) -> list[str]:
    def must_fail(label: str, action) -> None:
        try:
            action()
        except (ValueError, KeyError):
            failed.append(label)
        else:
            raise AssertionError(f"negative control did not fail: {label}")

    failed: list[str] = []
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"][0]["expected_legacy"]["verdict"] = "malicious"
    must_fail("changed_legacy_outcome", lambda: evaluate_manifest(mutated))
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"][0]["expected_actions"]["balanced"] = "block"
    must_fail("changed_policy_outcome", lambda: evaluate_policy_actions(mutated))
    mutated = copy.deepcopy(manifest)
    del mutated["fixtures"][0]["source_group"]
    must_fail("missing_source_provenance", lambda: evaluate_manifest(mutated))
    bad_claims = copy.deepcopy(claims)
    bad_claims["claims"]["invented_guarantee"] = {"metric": "guaranteed_prevention", "expected": True}
    must_fail("unsupported_claim", lambda: verify_claims(bad_claims, metrics))
    with tempfile.TemporaryDirectory(prefix="stegdetect-negative-") as directory:
        clone_root = Path(directory)
        for relative in load_json(protected)["sha256"]:
            source = ROOT / relative
            destination = clone_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        target = clone_root / "tests" / "test_historical.py"
        target.write_bytes(target.read_bytes() + b"\n# deliberate mutation\n")
        must_fail("protected_test_mutation", lambda: verify_protected_tests(clone_root, protected))
    return failed


def installed_wheel_smoke(temp_root: Path) -> dict:
    wheel_dir = temp_root / "wheels"
    wheel_dir.mkdir()
    run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-build-isolation",
         "--no-deps", "--wheel-dir", str(wheel_dir), str(ROOT)], cwd=temp_root)
    wheels = list(wheel_dir.glob("stegdetect-*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected one built wheel, got {len(wheels)}")
    environment = temp_root / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
        cwd=temp_root)
    result = run([str(python), str(ROOT / "scripts" / "installed_smoke.py"), str(ROOT)],
                 cwd=temp_root)
    return load_json_text(result)


def load_json_text(value: str) -> dict:
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object from installed smoke")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["baseline", "bounded"], required=True)
    args = parser.parse_args()
    try:
        manifest = load_json(ROOT / "evals" / "manifest.json")
        evaluated = evaluate_manifest(manifest)
        policy_actions = evaluate_policy_actions(manifest)
        verify_split_manifest(manifest)
        protected = ROOT / "evals" / "protected_tests.json"
        protected_count = verify_protected_tests(ROOT, protected)
        mapped_rules = validate_rule_map(ROOT / "evals" / "rule_map.json")
        source_corpus = measure(ROOT / "tests" / "test_false_positives.py")
        recorded_corpus = load_json(ROOT / "docs" / "robustness-corpus.json")
        if source_corpus != recorded_corpus:
            raise ValueError("source baseline corpus differs from recorded corpus")
        clean_count = source_corpus["legitimate_samples"]
        attack_count = sum(row["samples"] for row in source_corpus["attack_families"].values())
        missed = sum(row["false_negatives"] for row in source_corpus["attack_families"].values())
        metrics = {
            "mapped_rules": mapped_rules, "protected_tests": protected_count,
            "evaluated": evaluated["evaluated"],
            "independent_source_groups": evaluated["independent_source_groups"],
            "legacy_clean_samples": clean_count,
            "legacy_nonclean_clean_samples": source_corpus["false_positives"],
            "generated_attack_samples": attack_count,
            "generated_nonmalicious": missed,
            "intentional_density_evasions": source_corpus["deliberate_below_density_evasion"]["undetected"],
        }
        claims = load_json(ROOT / "evals" / "claims.json")
        mapped_claims = verify_claims(claims, metrics)
        negative = prove_negative_controls(manifest, protected, claims, metrics)
        resource_summary = verify_resource_artifact() if args.profile == "bounded" else None
        suite_output = run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, timeout=240)
        match = re.search(r"(\d+) passed", suite_output)
        if not match or int(match.group(1)) < (248 if args.profile == "bounded" else 227):
            raise ValueError(f"full suite missing or below {args.profile} baseline: {suite_output[-1000:]}")
        with tempfile.TemporaryDirectory(prefix="stegdetect-wheel-") as directory:
            installed = installed_wheel_smoke(Path(directory))
        if (installed["corpus"] != source_corpus or
                installed["api_fixtures"] != evaluated["evaluated"] or
                installed["policy_cases"] != evaluated["evaluated"] * len(policy_actions) or
                installed["bounded_cases"] != 3):
            raise ValueError("source/installed baseline mismatch")
        print(json.dumps({"profile": args.profile, "status": "PASS", "tests_passed": int(match.group(1)),
                          "development_fixtures": evaluated["evaluated"],
                          "independent_sources": evaluated["independent_source_groups"],
                          "protected_test_files": protected_count, "mapped_rules": mapped_rules,
                          "mapped_claims": mapped_claims, "negative_controls": negative,
                          "legacy_nonclean_clean_samples": source_corpus["false_positives"],
                          "generated_nonmalicious": missed,
                          "installed_api_fixtures": installed["api_fixtures"],
                          "installed_policy_cases": installed["policy_cases"],
                          "installed_bounded_cases": installed["bounded_cases"],
                          "installed_cli_cases": installed["cli_cases"],
                          "resource_summary": resource_summary}, sort_keys=True))
        return 0
    except (AssertionError, ValueError, RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        print(f"baseline validation FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
