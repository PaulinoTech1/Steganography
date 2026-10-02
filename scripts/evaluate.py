"""Evaluate P0 development fixtures against the unchanged legacy API.

Usage: python scripts/evaluate.py
Scores here are descriptive corpus checks, never deployment accuracy estimates.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from stegdetect import Policy, analyze, inspect_text  # noqa: E402
from stegdetect import samples, unicode_scan  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_protected_tests(root: Path, manifest_path: Path) -> int:
    """Preserve byte identity of every test present at the d876974 baseline."""
    mapping = load_json(manifest_path)["sha256"]
    if not mapping:
        raise ValueError("protected test map is empty")
    for relative, expected in mapping.items():
        target = root / relative
        if not target.is_file():
            raise ValueError(f"protected test missing: {relative}")
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"protected test changed: {relative}")
    return len(mapping)


def _test_symbol_exists(node_id: str) -> bool:
    try:
        relative, symbol = node_id.split("::", 1)
    except ValueError:
        return False
    target = ROOT / relative
    if not target.is_file() or not target.resolve().is_relative_to((ROOT / "tests").resolve()):
        return False
    tree = ast.parse(target.read_text(encoding="utf-8"))
    return any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol
               for node in tree.body)


def validate_rule_map(path: Path = ROOT / "evals" / "rule_map.json") -> int:
    mapping = load_json(path)
    if mapping.get("schema_version") != 1:
        raise ValueError("unexpected rule-map version")
    source = ast.parse(inspect.getsource(unicode_scan.scan_unicode))
    categories = {keyword.value.value for node in ast.walk(source)
                  if isinstance(node, ast.Call) for keyword in node.keywords
                  if keyword.arg == "category" and isinstance(keyword.value, ast.Constant)
                  and isinstance(keyword.value.value, str)}
    rules = mapping.get("rules", {})
    if not categories or set(rules) != categories:
        raise ValueError(f"rule-map categories mismatch: source={sorted(categories)} map={sorted(rules)}")
    for category, entry in rules.items():
        generators = entry.get("generators", [])
        if not generators:
            raise ValueError(f"rule has no generator: {category}")
        for generator in generators:
            symbol = generator["symbol"]
            function = getattr(samples, symbol, None)
            if not callable(function):
                raise ValueError(f"generator missing: {category}/{symbol}")
            sample = function(*generator["args"])
            if category not in {finding.category for finding in analyze(sample).findings}:
                raise ValueError(f"generator did not trigger mapped category: {category}/{symbol}")
        for key in ("positive_tests", "benign_tests", "boundary_tests"):
            if not entry.get(key):
                raise ValueError(f"rule lacks {key}: {category}")
            for node_id in entry[key]:
                if not _test_symbol_exists(node_id):
                    raise ValueError(f"missing test symbol: {node_id}")
    return len(rules)


def evaluate_manifest(manifest: dict, *, schema: dict | None = None) -> dict:
    """Check schema, provenance/split integrity, and exact legacy outcomes."""
    if not manifest.get("fixtures"):
        raise ValueError("fixture corpus is empty")
    validator = Draft202012Validator(schema or load_json(ROOT / "evals" / "manifest.schema.json"))
    errors = list(validator.iter_errors(manifest))
    if errors:
        raise ValueError(f"fixture schema invalid: {errors[0].message}")
    groups: dict[str, str] = {}
    texts: dict[str, str] = {}
    ids: set[str] = set()
    by_split = {"development": 0, "holdout": 0}
    by_intent = {"benign": 0, "constructed_attack": 0, "unknown": 0}
    strata = {key: 0 for key in (
        "latin_prose", "rtl_direction", "joining_control", "indic", "cjk_variation",
        "emoji", "mixed_script", "code_config", "science_math", "security_quote")}
    legacy_nonclean = 0
    for fixture in manifest["fixtures"]:
        name = fixture["id"]
        if name in ids:
            raise ValueError(f"duplicate fixture id: {name}")
        ids.add(name)
        group = fixture["source_group"]
        if group not in manifest["sources"]:
            raise ValueError(f"unknown source group: {group}")
        split = fixture["split"]
        if group in groups and groups[group] != split:
            raise ValueError(f"cross-split source group: {group}")
        groups[group] = split
        digest = hashlib.sha256(fixture["text"].encode("utf-8", "surrogatepass")).hexdigest()
        if digest in texts and texts[digest] != split:
            raise ValueError(f"cross-split duplicate text: {name}")
        texts[digest] = split
        report = analyze(fixture["text"])
        expected = fixture["expected_legacy"]
        actual = {"verdict": report.verdict,
                  "categories": sorted({finding.category for finding in report.findings}),
                  "finding_count": len(report.findings), "sanitized": report.sanitized}
        if actual != expected:
            raise ValueError(f"legacy outcome mismatch: {name}: {actual!r} != {expected!r}")
        changed = report.sanitized != fixture["text"]
        if changed != fixture["transform_constraints"]["legacy_changed"]:
            raise ValueError(f"legacy transformation mismatch: {name}")
        by_split[split] += 1
        by_intent[fixture["intent_label"]] += 1
        strata[fixture["primary_stratum"]] += 1
        legacy_nonclean += report.verdict != "clean"
    return {"evaluated": len(ids), "by_split": by_split,
            "by_intent": by_intent, "by_primary_stratum": strata,
            "source_groups": len(groups),
            "independent_source_groups": sum(bool(manifest["sources"][name]["independent_source"])
                                             for name in groups),
            "legacy_nonclean_fixtures": legacy_nonclean,
            "accuracy_claim_supported": False}


def verify_split_manifest(manifest: dict, path: Path = ROOT / "evals" / "splits" / "development.json") -> int:
    """Reject a stale or fabricated split inventory."""
    split = load_json(path)
    if split.get("schema_version") != 1 or set(split) != {
            "schema_version", "development_ids", "holdout_ids"}:
        raise ValueError("split inventory shape/version mismatch")
    development = [fixture["id"] for fixture in manifest["fixtures"]
                   if fixture["split"] == "development"]
    holdout = [fixture["id"] for fixture in manifest["fixtures"]
               if fixture["split"] == "holdout"]
    if split["development_ids"] != development or split["holdout_ids"] != holdout:
        raise ValueError("split inventory differs from corpus manifest")
    return len(development)


def evaluate_policy_actions(manifest: dict) -> dict:
    """Exact P1 goldens and descriptive counts; labels are not independent."""
    results: dict[str, dict] = {}
    for policy, key in ((Policy.BALANCED, "balanced"),
                        (Policy.LEGACY_VERDICT, "legacy_verdict")):
        counts = {intent: {action: 0 for action in ("allow", "review", "block")}
                  for intent in ("benign", "constructed_attack", "unknown")}
        for fixture in manifest["fixtures"]:
            report = inspect_text(fixture["text"], policy=policy)
            if report.status != "complete" or report.action != fixture["expected_actions"][key]:
                raise ValueError(f"policy outcome mismatch: {key}/{fixture['id']}")
            if report.candidate_text != (fixture["text"] if report.action == "allow" else None):
                raise ValueError(f"policy forwarding mismatch: {key}/{fixture['id']}")
            counts[fixture["intent_label"]][report.action] += 1
        results[key] = {"counts_by_project_label": counts,
                        "evaluated": len(manifest["fixtures"]),
                        "independent_accuracy_claim_supported": False}
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "evals" / "manifest.json")
    args = parser.parse_args()
    manifest = load_json(args.manifest)
    summary = evaluate_manifest(manifest)
    summary["development_split_ids"] = verify_split_manifest(manifest)
    summary["policy_actions"] = evaluate_policy_actions(manifest)
    summary["protected_tests"] = verify_protected_tests(ROOT, ROOT / "evals" / "protected_tests.json")
    summary["mapped_rules"] = validate_rule_map()
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
