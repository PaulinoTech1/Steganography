"""Freeze observed legacy behavior before a new policy API is introduced."""
import io
import sys

import pytest

from stegdetect import analyze
from stegdetect.canonicalize import canonicalize
from stegdetect.cli import main
from stegdetect.samples import (
    greek_homoglyph_swap,
    invisible_format_embed,
    suspicious_whitespace_replace,
)
from stegdetect.unicode_scan import INVISIBLE_FORMAT, WEIRD_SPACES


@pytest.mark.parametrize("marker", list(INVISIBLE_FORMAT))
def test_invisible_format_generator_pair(marker):
    text = invisible_format_embed("example", marker=marker)
    report = analyze(text)
    assert "INVISIBLE_FORMAT" in {f.category for f in report.findings}
    assert any(text[f.offset] == marker for f in report.findings)


@pytest.mark.parametrize("marker", list(WEIRD_SPACES))
def test_whitespace_generator_pair(marker):
    text = suspicious_whitespace_replace("Total 100", marker=marker)
    report = analyze(text)
    assert "SUSPICIOUS_WHITESPACE" in {f.category for f in report.findings}
    assert any(text[f.offset] == marker for f in report.findings)


def test_greek_generator_shape2_pair():
    text = greek_homoglyph_swap("toxik pizza")
    assert analyze(text).verdict == "malicious"
    assert "MIXED_SCRIPT" in {f.category for f in analyze(text).findings}


@pytest.mark.parametrize("text", ["ordinary-hyphen", "Total 100"])
def test_plain_formatting_boundary_is_clean(text):
    assert analyze(text).verdict == "clean"


def test_plain_rtl_text_stays_clean():
    assert analyze("\u05e9\u05dc\u05d5\u05dd").verdict == "clean"


def test_ascii_tagless_text_stays_clean():
    assert analyze("Invoice attached.").verdict == "clean"


def test_unmapped_marker_rejected_by_generator():
    with pytest.raises(ValueError):
        invisible_format_embed("example", marker="x")
    with pytest.raises(ValueError):
        suspicious_whitespace_replace("Total 100", marker="x")
    with pytest.raises(ValueError):
        suspicious_whitespace_replace("no-space")


@pytest.mark.parametrize("name,text,verdict,category,count,sanitized", [
    ("persian_zwnj", "\u0645\u06cc\u200c\u0631\u0648\u0645", "suspicious", "ZERO_WIDTH", 1,
     "\u0645\u06cc\u0631\u0648\u0645"),
    ("indic_zwj", "\u0915\u094d\u200d\u0937", "suspicious", "ZERO_WIDTH", 1,
     "\u0915\u094d\u0937"),
    ("family_emoji", "\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466",
     "suspicious", "ZERO_WIDTH", 3, "\U0001f468\U0001f469\U0001f467\U0001f466"),
    ("england_flag", "\U0001f3f4" + "".join(chr(0xe0000 + ord(c)) for c in "gbeng") + "\U000e007f",
     "malicious", "TAG_CHARACTER", 6, "\U0001f3f4"),
    ("bidi_isolate", "Label: \u2067\u05e9\u05dc\u05d5\u05dd\u2069", "malicious", "BIDI_OVERRIDE", 2,
     "Label: \u05e9\u05dc\u05d5\u05dd"),
    ("nbspace", "Total:\u00a0100", "suspicious", "SUSPICIOUS_WHITESPACE", 1, "Total: 100"),
])
def test_legacy_context_probe(name, text, verdict, category, count, sanitized):
    report = analyze(text)
    assert report.verdict == verdict, name
    assert [f.category for f in report.findings] == [category] * count, name
    assert report.sanitized == sanitized, name


@pytest.mark.parametrize("text,expected", [
    ("a\u200b\u0301", "á"),
    ("\u0430\u0301", "á"),
])
def test_legacy_rewrite_is_idempotent(text, expected):
    # Canonicalization used to expose a second composition change on re-run
    # (e.g. 'a' + acute composing to 'á'); NFKC now runs after the
    # strip/map step, so the first pass already reaches the fixed point.
    assert canonicalize(text) == expected
    assert canonicalize(expected) == expected


def test_legacy_cli_json_fails_on_strict_utf8_lone_surrogate(monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    with pytest.raises(UnicodeEncodeError):
        main(["\ud800"])
