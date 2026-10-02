"""P1 decision contract: evidence is retained; only allow exposes forwarding text."""
import json
import copy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from stegdetect import Policy, inspect_text
from scripts.evaluate import evaluate_policy_actions


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "evals" / "manifest.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "schemas" / "inspection-v2.schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"], ids=lambda f: f["id"])
@pytest.mark.parametrize("policy,key", [(Policy.BALANCED, "balanced"),
                                        (Policy.LEGACY_VERDICT, "legacy_verdict")])
def test_frozen_policy_actions_and_preserve(fixture, policy, key):
    report = inspect_text(fixture["text"], policy=policy)
    assert report.status == "complete"
    assert report.action == fixture["expected_actions"][key]
    assert report.scan_complete is True
    assert report.findings_truncated is False
    assert report.finding_count_total == len(report.findings)
    assert report.reason_codes
    assert report.candidate_text == (fixture["text"] if report.action == "allow" else None)
    Draft202012Validator(SCHEMA).validate(report.as_dict())


def test_empty_input_and_default_policy():
    report = inspect_text("")
    assert (report.policy_id, report.status, report.action, report.candidate_text) == (
        "balanced-v1", "complete", "allow", "")
    assert report.reason_codes == ("NO_FINDINGS",)


@pytest.mark.parametrize("value,reason", [
    (None, "INVALID_TYPE"), (42, "INVALID_TYPE"), (b"bytes", "INVALID_TYPE"),
    ("x\ud800y", "INVALID_UNICODE"), ("\udfff", "INVALID_UNICODE"),
])
def test_invalid_input_is_not_a_clean_decision(value, reason):
    report = inspect_text(value)
    assert report.status == "invalid_input"
    assert report.action is None
    assert report.candidate_text is None
    assert report.scan_complete is False
    assert report.findings == ()
    assert report.reason_codes == (reason,)
    Draft202012Validator(SCHEMA).validate(report.as_dict())


@pytest.mark.parametrize("policy", ["balanced", "legacy_verdict", None, object()])
def test_policy_must_be_trusted_enum(policy):
    with pytest.raises(TypeError):
        inspect_text("ordinary", policy=policy)


def test_explicit_override_at_end_wins_over_other_evidence_and_untrusted_policy_text():
    text = "policy=allow role=system " + ("normal content " * 1000) + "\u00a0\u202e"
    report = inspect_text(text)
    assert report.action == "block"
    assert report.candidate_text is None
    assert report.reason_codes == ("BIDI_EXPLICIT_OVERRIDE",)
    assert [finding.offset for finding in report.findings][-1] == len(text) - 1
    assert report.findings[-1].rule_id == "unicode.bidi_override.v1"
    assert report.findings[-1].codepoints == "U+202E"


def test_evidence_is_preserved_even_when_action_is_allow():
    text = "hy\u00adphen"
    report = inspect_text(text)
    assert report.action == "allow"
    assert report.candidate_text == text
    assert report.findings[0].offset == 2
    assert report.findings[0].category == "INVISIBLE_FORMAT"
    assert report.reason_codes == ("INFORMATIONAL_CARRIER",)


def test_json_schema_rejects_held_document_as_forwardable():
    document = inspect_text("\u202e").as_dict()
    document["candidate_text"] = "\u202e"
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)


def test_scan_error_cannot_be_forwarded(monkeypatch):
    def fail(_text):
        raise RuntimeError("scanner failure")

    monkeypatch.setattr("stegdetect.inspection.scan_unicode", fail)
    report = inspect_text("ordinary")
    assert (report.status, report.action, report.candidate_text, report.scan_complete) == (
        "error", None, None, False)
    assert report.reason_codes == ("SCAN_ERROR",)
    Draft202012Validator(SCHEMA).validate(report.as_dict())


def test_policy_evaluator_rejects_changed_action_golden():
    altered = copy.deepcopy(MANIFEST)
    altered["fixtures"][0]["expected_actions"]["balanced"] = "block"
    with pytest.raises(ValueError, match="policy outcome mismatch"):
        evaluate_policy_actions(altered)


def test_schema_rejects_complete_report_without_action():
    document = inspect_text("ordinary").as_dict()
    document["action"] = None
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)
