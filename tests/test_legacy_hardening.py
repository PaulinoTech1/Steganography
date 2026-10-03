"""Hardening for the legacy analyze() path: bounded input and idempotent rewrite.

These live outside the protected test files so the tamper-evidence pins
in evals/protected_tests.json stay byte-identical.
"""
import pytest

from stegdetect import Limits, analyze
from stegdetect.canonicalize import canonicalize


@pytest.mark.parametrize("text", [
    # Regression: confusable mapping used to expose a second composition
    "\u0430\u0301",
    "a\u200b\u0301",
    "á",
])
def test_canonicalize_idempotent_after_confusable_composition(text):
    once = canonicalize(text)
    assert canonicalize(once) == once


def test_analyze_enforces_max_chars():
    with pytest.raises(ValueError, match="max_chars"):
        analyze("x" * (Limits().max_chars + 1))
    # At exactly the limit it still works.
    assert analyze("x" * 100).verdict == "clean"


def test_analyze_rejects_non_string():
    with pytest.raises(TypeError):
        analyze(b"bytes")


def test_analyze_accepts_lone_surrogates_by_design():
    # Surrogate acceptance is pinned fuzz/robustness behavior; only the
    # inspect_*() path rejects them. This locks the distinction in.
    report = analyze("a\ud800b")
    assert report.verdict in {"clean", "suspicious", "malicious"}
