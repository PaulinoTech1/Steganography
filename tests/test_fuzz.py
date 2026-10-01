"""Bounded, reproducible properties; Python strings include lone surrogates."""
import json
import unicodedata

import pytest
from hypothesis import given, settings, strategies as st

from stegdetect import analyze
from stegdetect.canonicalize import _nfkc, canonicalize
from stegdetect.samples import bidi_wrap, homoglyph_swap, tag_encode, zero_width_encode
from stegdetect.unicode_scan import _is_tag


# st.text() normally excludes surrogates; explicitly include every codepoint.
unicode_text = st.text(st.integers(0, 0x10FFFF).map(chr), max_size=256)
property_settings = settings(max_examples=200, derandomize=True, deadline=None)


def check_report(text):
    report = analyze(text)
    assert report.verdict in {"clean", "suspicious", "malicious"}
    assert report.sanitized == canonicalize(text)
    assert report.stats["input_chars"] == len(text)
    assert report.stats["finding_count"] == len(report.findings)
    assert sum(report.stats["by_category"].values()) == len(report.findings)
    assert sum(report.stats["by_severity"].values()) == len(report.findings)
    assert [f.offset for f in report.findings] == sorted(f.offset for f in report.findings)
    for f in report.findings:
        assert 0 <= f.offset < len(text)
        assert f.codepoints == f"U+{ord(text[f.offset]):04X}"
    # ASCII escaping is the portable serialization path for lone surrogates.
    serialized = json.dumps(report.as_dict(), sort_keys=True)
    # JSON decoders may join a high/low surrogate pair into one scalar.
    assert json.dumps(json.loads(serialized), sort_keys=True) == serialized
    return report


@property_settings
@given(unicode_text)
def test_arbitrary_python_strings_have_consistent_reports(text):
    check_report(text)


@property_settings
@given(unicode_text)
def test_bounded_nfkc_matches_standard_library(text):
    assert _nfkc(text) == unicodedata.normalize("NFKC", text)


@property_settings
@given(st.text(st.sampled_from(["a", "\u0315", "\u0300", "\uff9e", "\u0334",
                              "\u0344", "\u1100", "\u1161", "\u11a8", "\ud800"]),
               max_size=512))
def test_nfkc_reordering_composition_and_compatibility(text):
    assert _nfkc(text) == unicodedata.normalize("NFKC", text)


@pytest.mark.parametrize("generator,category", [
    (zero_width_encode, "ZERO_WIDTH"),
    (bidi_wrap, "BIDI_OVERRIDE"),
    (tag_encode, "TAG_CHARACTER"),
    (homoglyph_swap, "MIXED_SCRIPT"),
])
@property_settings
@given(payload=st.text(alphabet="aeiopcx", min_size=1, max_size=64), cover=unicode_text)
def test_generator_carriers_survive_adversarial_covers(generator, category, payload, cover):
    # Arbitrary Unicode covers can legitimately suppress mixed-script density;
    # hold that generator's Latin context constant to test its promised domain.
    text = ("Latin " + generator(payload) if generator is homoglyph_swap
            else generator(payload, cover=cover))
    report = check_report(text)
    assert report.verdict == "malicious"
    assert any(f.category == category for f in report.findings)


@property_settings
@given(payload=unicode_text, cover=unicode_text)
def test_unicode_payload_generators_do_not_crash(payload, cover):
    for generator in (zero_width_encode, bidi_wrap):
        check_report(generator(payload, cover=cover))
    check_report(homoglyph_swap(payload))
    # Tag encoding represents ASCII only: arbitrary Unicode is not its domain.


@property_settings
@given(st.text(st.integers(0, 127).map(chr), min_size=1, max_size=128))
def test_tag_generator_entire_ascii_domain(payload):
    text = tag_encode(payload, cover="")
    assert all(_is_tag(ch) for ch in text)
    report = check_report(text)
    assert len(report.findings) == len(payload)
    assert report.verdict == "malicious"
    assert report.sanitized == ""


@property_settings
@given(st.text(alphabet="aeiopcx", min_size=1, max_size=128))
def test_spreading_generated_zero_width_bits_does_not_evade_cluster(payload):
    hidden = zero_width_encode(payload, cover="")
    report = check_report("visible".join(hidden))
    assert report.verdict == "malicious"
    assert all(f.severity == "high" for f in report.findings)


@property_settings
@given(st.integers(1, 8))
def test_homoglyph_density_boundary_stays_silent(n):
    # Padding with a nonconfusable letter can evade the rule by design.
    report = check_report("Latin " + homoglyph_swap("a" * n) + "\u0448")
    assert report.verdict == "clean"


@pytest.mark.parametrize("text", ["\ud800", "\udfff", "\ud800\udfff", "x\ud800\u202ey"])
def test_lone_surrogates_explicitly(text):
    check_report(text)


def test_nfkc_equivalence_for_every_single_codepoint():
    # Cover the runtime's entire Unicode table, including compatibility forms.
    for cp in range(0x110000):
        ch = chr(cp)
        assert _nfkc(ch) == unicodedata.normalize("NFKC", ch), hex(cp)


def test_normalization_preserves_equal_class_order():
    text = "a" + "\u0301\u0300\u0315\u0334" * 2048
    assert _nfkc(text) == unicodedata.normalize("NFKC", text)


@pytest.mark.parametrize("text,expected", [
    ("\u4f60\u597d\uff0c\u4e16\u754c\uff1f", "\u4f60\u597d,\u4e16\u754c?"),
    ("\u041f\u0440\u0438\u0432\u0435\u0442 world", "\u041fp\u0438\u0432e\u0442 world"),
])
def test_existing_clean_verdict_rewriting_policy_is_preserved(text, expected):
    report = analyze(text)
    assert report.verdict == "clean"
    assert report.findings == []
    assert report.sanitized == expected
    assert report.sanitized != text
