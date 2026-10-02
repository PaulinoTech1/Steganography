"""The baseline evaluator must fail closed when evidence is missing or altered."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from scripts.evaluate import evaluate_manifest, validate_rule_map, verify_protected_tests, verify_split_manifest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def manifest():
    return json.loads((ROOT / "evals" / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture
def schema():
    document = json.loads((ROOT / "evals" / "manifest.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(document)
    return document


def test_fixture_schema_rejects_missing_provenance(manifest, schema):
    valid = Draft202012Validator(schema)
    assert not list(valid.iter_errors(manifest))
    mutated = copy.deepcopy(manifest)
    del mutated["fixtures"][0]["source_group"]
    with pytest.raises(ValidationError):
        valid.validate(mutated)


def test_fixture_schema_rejects_unrecognized_policy_actions(manifest, schema):
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"][0]["expected_actions"]["balanced"] = "trusted"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(mutated)


def test_manifest_rejects_duplicate_ids_and_cross_split_source_leak(manifest):
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"].append(copy.deepcopy(mutated["fixtures"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_manifest(mutated)
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"][1]["split"] = "holdout"
    mutated["fixtures"][1]["source_group"] = mutated["fixtures"][0]["source_group"]
    with pytest.raises(ValueError, match="cross-split"):
        evaluate_manifest(mutated)


def test_manifest_rejects_empty_or_mismatched_baseline(manifest):
    with pytest.raises(ValueError, match="empty"):
        evaluate_manifest({**manifest, "fixtures": []})
    mutated = copy.deepcopy(manifest)
    mutated["fixtures"][0]["expected_legacy"]["verdict"] = "malicious"
    with pytest.raises(ValueError, match="legacy"):
        evaluate_manifest(mutated)


def test_real_manifest_and_rule_map_pass(manifest, schema):
    summary = evaluate_manifest(manifest, schema=schema)
    assert summary["evaluated"] == len(manifest["fixtures"])
    assert summary["evaluated"] >= 20
    assert summary["by_split"]["development"] == len(manifest["fixtures"])
    assert validate_rule_map(ROOT / "evals" / "rule_map.json") == 6
    assert verify_split_manifest(manifest) == len(manifest["fixtures"])


def test_split_inventory_rejects_stale_fixture_list(manifest, tmp_path):
    split = {"schema_version": 1, "development_ids": [], "holdout_ids": []}
    path = tmp_path / "split.json"
    path.write_text(json.dumps(split), encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        verify_split_manifest(manifest, path)


def test_protected_test_byte_change_is_detected(tmp_path):
    assert verify_protected_tests(ROOT, ROOT / "evals" / "protected_tests.json") == 8
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    expected = json.loads((ROOT / "evals" / "protected_tests.json").read_text(encoding="utf-8"))
    for relative in expected["sha256"]:
        source = ROOT / relative
        destination = tmp_path / relative
        destination.write_bytes(source.read_bytes())
    target = tests_dir / "test_historical.py"
    target.write_bytes(target.read_bytes() + b"\n# mutated\n")
    with pytest.raises(ValueError, match="changed"):
        verify_protected_tests(tmp_path, ROOT / "evals" / "protected_tests.json")
