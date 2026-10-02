"""Opt-in Unicode context: legitimate pairs and malformed near matches."""
import json
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st
from jsonschema import Draft202012Validator, ValidationError

from scripts.generate_emoji_context import OUTPUT, generate
from stegdetect import Limits, Policy, inspect_text
import stegdetect.unicode_context as unicode_context
from tests.test_false_positives import CLEAN_SAMPLES


ROOT = Path(__file__).resolve().parents[1]
V3 = json.loads((ROOT / "schemas" / "inspection-v3.schema.json").read_text())
V4 = json.loads((ROOT / "schemas" / "inspection-v4.schema.json").read_text())
FAMILY = "\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466"
ENGLAND = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + "\U000e007f"
PERSIAN = "\u0645\u06cc\u200c\u0631\u0648\u0645"
INDIC = "\u0915\u094d\u200d\u0937"
RTL = "Label: \u2067\u05e9\u05dc\u05d5\u05dd\u2069"
MANIFEST = json.loads((ROOT / "evals" / "manifest.json").read_text(encoding="utf-8"))
GOLDENS = json.loads((ROOT / "evals" / "contextual-actions.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"], ids=lambda f: f["id"])
def test_contextual_development_action_is_literal_and_preserved(fixture):
    assert GOLDENS["policy_id"] == "contextual-v1"
    assert set(GOLDENS["actions"]) == {row["id"] for row in MANIFEST["fixtures"]}
    report = inspect_text(fixture["text"], policy=Policy.CONTEXTUAL)
    assert report.action == GOLDENS["actions"][fixture["id"]]
    assert report.candidate_text == (fixture["text"] if report.action == "allow" else None)
    Draft202012Validator(V4).validate(report.as_dict())


def test_contextual_selected_corpus_counts_are_descriptive():
    benign = [row for row in MANIFEST["fixtures"] if row["intent_label"] == "benign"]
    attacks = [row for row in MANIFEST["fixtures"] if row["intent_label"] == "constructed_attack"]
    assert len(benign) == 17 and sum(GOLDENS["actions"][row["id"]] != "allow"
                                     for row in benign) == 0
    assert len(attacks) == 9
    assert [sum(GOLDENS["actions"][row["id"]] == action for row in attacks)
            for action in ("allow", "review", "block")] == [3, 4, 2]
    assert len(CLEAN_SAMPLES) == 16
    assert all(inspect_text(text, policy=Policy.CONTEXTUAL).action == "allow"
               for text in CLEAN_SAMPLES.values())


def test_pinned_emoji_table_rebuilds_byte_for_byte():
    assert OUTPUT.read_text(encoding="ascii") == generate()


def test_tampered_installed_context_data_fails_closed(tmp_path, monkeypatch):
    altered = tmp_path / "emoji-context-18.0.txt"
    altered.write_bytes(OUTPUT.read_bytes() + b"# altered\n")
    unicode_context._emoji_trie.cache_clear()
    monkeypatch.setattr(unicode_context, "_DATA", altered)
    report = inspect_text(FAMILY, policy=Policy.CONTEXTUAL)
    assert (report.status, report.action, report.candidate_text) == ("error", None, None)
    unicode_context._emoji_trie.cache_clear()


@pytest.mark.parametrize("text,category,minimum", [
    (FAMILY * 2, "ZERO_WIDTH", 6),
    (ENGLAND, "TAG_CHARACTER", 6),
    (PERSIAN * 4, "ZERO_WIDTH", 4),
    (INDIC * 4, "ZERO_WIDTH", 4),
    (RTL, "BIDI_OVERRIDE", 2),
])
def test_recognized_construction_is_allowed_with_original_evidence(text, category, minimum):
    baseline = inspect_text(text)
    contextual = inspect_text(text, policy=Policy.CONTEXTUAL)
    assert baseline.action == "review"
    assert contextual.status == "complete"
    assert contextual.action == "allow"
    assert contextual.candidate_text == text
    assert contextual.reason_codes == ("RECOGNIZED_CONTEXT",)
    assert contextual.finding_count_total == baseline.finding_count_total
    assert contextual.category_counts == baseline.category_counts
    assert contextual.category_counts[category] >= minimum
    assert [f.offset for f in contextual.findings] == [f.offset for f in baseline.findings]
    assert contextual.schema_version == 4
    Draft202012Validator(V4).validate(contextual.as_dict())
    with pytest.raises(ValidationError):
        Draft202012Validator(V3).validate(contextual.as_dict())


@pytest.mark.parametrize("text,reason", [
    (ENGLAND + chr(0xE0061), "TAG_CHARACTER"),
    (FAMILY + "\u200d" + "x", "UNRECOGNIZED_JOINER"),
    ("\u0915\u094d\u200d" + "x", "UNRECOGNIZED_JOINER"),
    ("\u0645\u06cc\u200c\u200c\u0631\u0648\u0645" * 4, "ZERO_WIDTH_CLUSTER"),
    ("Label: \u2067\u05e9\u05dc\u05d5\u05dd\u2069\u2069", "BIDI_CONTROL"),
    ("\u2067\u05e9\u2067\u05dc\u2069\u05dd\u2069", "BIDI_CONTROL"),
])
def test_malformed_or_extra_carrier_stays_held(text, reason):
    report = inspect_text(text, policy=Policy.CONTEXTUAL)
    assert report.status == "complete"
    assert report.action == "review"
    assert report.candidate_text is None
    assert reason in report.reason_codes
    assert report.finding_count_total > 0
    Draft202012Validator(V4).validate(report.as_dict())


def test_late_override_still_blocks_even_after_recognized_context():
    text = FAMILY * 2 + ("A" * 1000) + "\u202e"
    report = inspect_text(text, policy=Policy.CONTEXTUAL, limits=Limits(max_findings=6))
    assert report.action == "block"
    assert report.candidate_text is None
    assert report.reason_codes == ("BIDI_EXPLICIT_OVERRIDE",)
    assert any(f.offset == len(text) - 1 for f in report.findings)


def test_context_failure_and_admission_limit_never_forward(monkeypatch):
    over = inspect_text("abcd", policy=Policy.CONTEXTUAL, limits=Limits(max_chars=3))
    assert (over.status, over.action, over.candidate_text, over.schema_version) == (
        "limit_exceeded", None, None, 4)
    monkeypatch.setattr("stegdetect.inspection.recognize_context", lambda _text: 1 / 0)
    failed = inspect_text("ordinary", policy=Policy.CONTEXTUAL)
    assert (failed.status, failed.action, failed.candidate_text) == ("error", None, None)


def test_unrecognized_joiner_without_context_is_reviewed():
    text = "ab\u200dcd"
    assert inspect_text(text).action == "allow"
    report = inspect_text(text, policy=Policy.CONTEXTUAL)
    assert report.action == "review"
    assert report.reason_codes == ("UNRECOGNIZED_JOINER",)


def test_isolate_recognition_is_narrow():
    assert inspect_text("\u2068\u05e9\u05dc\u05d5\u05dd\u2069",
                        policy=Policy.CONTEXTUAL).action == "allow"
    for text in ("\u2066\u05e9\u05dc\u05d5\u05dd\u2069",
                 "\u2067\u05e9A\u05dc\u2069"):
        assert inspect_text(text, policy=Policy.CONTEXTUAL).action == "review"


@pytest.mark.parametrize("tag_letters", ["gbsct", "gbwls"])
def test_other_rgi_tag_flags_are_recognized_only_when_complete(tag_letters):
    flag = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in tag_letters) + "\U000e007f"
    assert inspect_text(flag, policy=Policy.CONTEXTUAL).action == "allow"
    assert inspect_text(flag[:-1], policy=Policy.CONTEXTUAL).action == "review"


@settings(max_examples=100, deadline=None)
@given(st.text(alphabet=st.sampled_from([
    "a", "\u05e9", "\u0645", "\u0915", "\u094d", "\u200b", "\u200c", "\u200d",
    "\u2067", "\u2068", "\u2069", "\u202e", "\U0001f468", "\U0001f3f4",
    chr(0xE0061), chr(0xE007F), " "
]), max_size=120))
def test_context_policy_preserves_all_raw_evidence_on_adversarial_compositions(text):
    baseline = inspect_text(text)
    contextual = inspect_text(text, policy=Policy.CONTEXTUAL)
    assert contextual.status == "complete"
    assert contextual.finding_count_total == baseline.finding_count_total
    assert contextual.category_counts == baseline.category_counts
    assert contextual.findings == baseline.findings
    assert contextual.candidate_text == (text if contextual.action == "allow" else None)
    if "\u202e" in text:
        assert contextual.action == "block"


def test_deeply_nested_isolates_finish_without_context_stack_growth():
    text = "\u2067" * 20_000 + "\u05e9" + "\u2069" * 20_000
    report = inspect_text(text, policy=Policy.CONTEXTUAL)
    assert report.status == "complete"
    assert report.action == "review"
    assert report.candidate_text is None
    assert report.finding_count_total == 40_000
