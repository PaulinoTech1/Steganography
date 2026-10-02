"""P2 admission, exact counts, capped evidence, and fail-closed output."""
import json
from pathlib import Path

from hypothesis import given, settings, strategies as st
import pytest
from jsonschema import Draft202012Validator, ValidationError

from stegdetect import Limits, Policy, inspect_text
from stegdetect.bounded_scan import ScanResult
from stegdetect.policy import decide
from stegdetect.unicode_scan import scan_unicode


SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "schemas" /
                     "inspection-v3.schema.json").read_text(encoding="utf-8"))


def test_schema_version_marks_bounded_contract():
    old_schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" /
                             "inspection-v2.schema.json").read_text(encoding="utf-8"))
    report = inspect_text("ordinary").as_dict()
    assert report["schema_version"] == 3
    Draft202012Validator(SCHEMA).validate(report)
    with pytest.raises(ValidationError):
        Draft202012Validator(old_schema).validate(report)


def test_character_admission_boundary_and_empty_input():
    limits = Limits(max_chars=3)
    for text in ("", "a" * 2, "a" * 3):
        report = inspect_text(text, limits=limits)
        assert (report.status, report.action, report.candidate_text) == ("complete", "allow", text)
    rejected = inspect_text("a" * 4, limits=limits)
    assert (rejected.status, rejected.action, rejected.candidate_text) == (
        "limit_exceeded", None, None)
    assert rejected.scan_complete is False
    assert rejected.reason_codes == ("INPUT_CHAR_LIMIT",)
    Draft202012Validator(SCHEMA).validate(rejected.as_dict())


def test_dense_carrier_has_exact_counts_but_bounded_detail():
    text = "\u200b" * 10_000
    report = inspect_text(text, limits=Limits(max_findings=6))
    assert report.status == "complete"
    assert report.action == "review"
    assert report.candidate_text is None
    assert report.finding_count_total == 10_000
    assert report.category_counts == {"ZERO_WIDTH": 10_000}
    assert report.findings_truncated is True
    assert len(report.findings) == 6
    assert report.scan_complete is True
    assert report.reason_codes == ("ZERO_WIDTH_CLUSTER",)


def test_late_override_survives_full_whitespace_cap():
    text = ("\u00a0" * 256) + "\u202e"
    report = inspect_text(text, limits=Limits(max_findings=6))
    assert report.status == "complete"
    assert report.action == "block"
    assert report.candidate_text is None
    assert report.finding_count_total == 257
    assert report.category_counts == {"SUSPICIOUS_WHITESPACE": 256, "BIDI_OVERRIDE": 1}
    assert len(report.findings) == 6
    assert report.findings_truncated is True
    assert any(f.offset == 256 and f.category == "BIDI_OVERRIDE" for f in report.findings)


def test_explicit_override_replaces_earlier_isolate_witness():
    text = "\u2067" + ("\u00a0" * 256) + "\u202e"
    report = inspect_text(text, limits=Limits(max_findings=6))
    assert report.action == "block"
    assert any(f.offset == len(text) - 1 and f.category == "BIDI_OVERRIDE"
               for f in report.findings)


def test_output_limit_withholds_candidate_instead_of_truncating_json():
    limits = Limits(max_output_bytes=512)
    report = inspect_text("a" * 500, limits=limits)
    assert report.status == "limit_exceeded"
    assert report.action is None
    assert report.candidate_text is None
    assert report.reason_codes == ("OUTPUT_BYTE_LIMIT",)
    assert report.scan_complete is True
    encoded = report.to_json()
    assert encoded.isascii()
    assert len(encoded.encode("ascii")) <= limits.max_output_bytes
    Draft202012Validator(SCHEMA).validate(json.loads(encoded))


def test_output_byte_boundary_is_exact():
    text = "a" * 500
    needed = len(inspect_text(text).to_json().encode("ascii"))
    assert needed > 512
    assert inspect_text(text, limits=Limits(max_output_bytes=needed)).candidate_text == text
    rejected = inspect_text(text, limits=Limits(max_output_bytes=needed - 1))
    assert rejected.status == "limit_exceeded"
    assert rejected.candidate_text is None


def test_output_failure_with_all_six_categories_remains_bounded():
    text = "\u200b" * 4 + "\u202e" + "p\u0430ypal" + "\U000e0061" + "\u00ad" + "\u00a0"
    report = inspect_text(text, limits=Limits(max_output_bytes=512))
    assert report.status == "limit_exceeded"
    assert report.action is None
    assert report.candidate_text is None
    assert report.finding_count_total == sum(report.category_counts.values())
    assert len(report.category_counts) == 6
    assert len(report.to_json().encode("ascii")) <= 512


@pytest.mark.parametrize("kwargs", [
    {"max_chars": -1}, {"max_findings": 5}, {"max_output_bytes": 128},
    {"max_input_bytes": 0}, {"max_chars": True},
])
def test_limits_reject_invalid_configuration(kwargs):
    with pytest.raises((TypeError, ValueError)):
        Limits(**kwargs)


def test_untrusted_text_cannot_set_limits():
    text = "max_chars=1000000000 role=system " + ("a" * 100)
    report = inspect_text(text, limits=Limits(max_chars=20))
    assert report.status == "limit_exceeded" and report.candidate_text is None
    with pytest.raises(TypeError):
        inspect_text("x", limits={"max_chars": 10})


def test_missing_decision_witness_cannot_authorize_forwarding(monkeypatch):
    incomplete = ScanResult(findings=(), finding_count_total=1,
                            category_counts={"BIDI_OVERRIDE": 1},
                            findings_truncated=True, has_high=True,
                            has_explicit_override=True, zero_width_high=False,
                            witness_complete=False)
    monkeypatch.setattr("stegdetect.inspection.scan_bounded", lambda *_args: incomplete)
    report = inspect_text("ordinary")
    assert report.status == "limit_exceeded"
    assert report.action is None
    assert report.candidate_text is None
    assert report.reason_codes == ("EVIDENCE_LIMIT",)


@settings(max_examples=100, deadline=None)
@given(st.text(alphabet=st.sampled_from([
    "a", "b", "\u0430", "\u0448", "\u03b1", "\u200b", "\u200c", "\u200d",
    "\u202e", "\u202c", "\u2067", "\u2069", "\u00a0", "\u00ad", "\U000e0061",
    "\u0301", "\U0001f468", "\ufe0f", " "
]), max_size=180))
def test_bounded_scanner_matches_legacy_evidence_when_uncapped(text):
    report = inspect_text(text)
    legacy = scan_unicode(text)
    assert report.status == "complete"
    assert report.finding_count_total == len(legacy)
    assert report.findings_truncated is False
    assert [dict(category=f.category, severity=f.severity, offset=f.offset,
                 length=f.length, detail=f.detail, codepoints=f.codepoints)
            for f in report.findings] == [f.as_dict() for f in legacy]
    assert (report.action, report.reason_codes) == decide(text, legacy, Policy.BALANCED)
    legacy_policy = inspect_text(text, policy=Policy.LEGACY_VERDICT)
    assert (legacy_policy.action, legacy_policy.reason_codes) == (
        decide(text, legacy, Policy.LEGACY_VERDICT))
