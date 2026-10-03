"""Extended homoglyph coverage: Armenian, Arabic, and Han lookalikes.

Curated from UTS #39 confusables.txt (v18.0). These are detection-only:
canonicalize() must not rewrite them, so legitimate text in these scripts
round-trips unchanged (pinned here, outside the protected test files).
"""
import pytest

from stegdetect import analyze
from stegdetect.canonicalize import canonicalize


@pytest.mark.parametrize("text", [
    "g\u0585\u0585gle",      # Armenian oh for 'o'
    "payp\u0561l",           # Armenian ayb in Latin word
    "paypa\u0627",           # Arabic alef for 'l'
    "H\u4e2bML",             # Han lookalike for 'Y'
    "\u054d\u054f\u0555\u0561\u0570\u0578\u057d\u0585",  # 8 Armenian confusables
])
def test_extended_confusables_detected(text):
    report = analyze(text)
    assert "MIXED_SCRIPT" in {f.category for f in report.findings}, text


@pytest.mark.parametrize("text", [
    "مرحبا بالعالم، كيف حالك اليوم؟",  # Arabic prose with alef/heh
    "Բարեւ աշխարհ, ինչպես ես?",        # Armenian prose
    "你好世界，今天过得怎么样？",            # Chinese prose
])
def test_legitimate_prose_stays_clean(text):
    report = analyze(text)
    assert report.verdict == "clean", report.findings
    assert report.findings == []


@pytest.mark.parametrize("text", [
    "مرحبا بالعالم، كيف حالك اليوم؟",
    "Բարեւ աշխարհ, ինչպես ես?",
])
def test_detection_only_confusables_not_rewritten(text):
    # Unlike Cyrillic/Greek, these scripts' lookalikes are flagged but
    # never mapped, so legitimate text is preserved byte-for-byte.
    assert canonicalize(text) == text
