"""False-positive battery: legitimate text that must stay clean.

A detector that cries wolf on Arabic, CJK, or emoji is worse than no
detector. Every sample here must produce verdict "clean" with zero
findings. If a sample ever trips, the detector changed, not the text.
"""
import pytest

from stegdetect import analyze

CLEAN_SAMPLES = {
    "arabic": "مرحبا بالعالم، كيف حالك اليوم؟",
    "hebrew": "שלום עולם, מה שלומך?",
    "chinese": "你好世界，今天过得怎么样？",
    "japanese": "こんにちは世界、お元気ですか。",
    "korean": "안녕하세요 세계",
    "thai": "สวัสดีครับ เป็นอย่างไรบ้าง",
    "devanagari": "नमस्ते दुनिया, आप कैसे हैं?",
    "emoji_heavy": "Great news! 🎉🚀 Launch went perfectly 🎊👏",
    # Note: subscript/superscript digits (², ₁) are intentionally absent:
    # NFKC canonicalization maps them to ASCII, so sanitized != text there.
    "math": "For x ∈ R, x ≥ 0 → ∑_{i=1}^{n} a_i ≤ 100 ∎",
    "code": "def foo(x):\n    # compute the thing\n    return x + 1",
    "german": "Grüße aus München, die Straße ist gesperrt",
    "french": "Café crème brûlée, naïve façade",
    "spanish": "El niño juega al fútbol",
    "code_switching": "Привет world, как дела today?",
    "empty": "",
    "plain_english": (
        "Please summarize the attached Q3 sales report. Focus on revenue "
        "by region and flag any quarter-over-quarter decline above 5%."
    ),
}


@pytest.mark.parametrize("name,text", CLEAN_SAMPLES.items())
def test_clean_sample_stays_clean(name, text):
    report = analyze(text)
    assert report.verdict == "clean", f"{name}: {report.findings}"
    assert report.findings == []


# Sanitized output is byte-identical only when there is nothing to
# normalize. Two exclusions, both by design:
#   chinese: fullwidth ，？ fold to ASCII under NFKC.
#   code_switching: confusable Cyrillic (р,е,а) folds to Latin lookalikes.
# In both cases the verdict stays clean; only the forwarded copy is
# normalized, which is the conservative choice.
ROUND_TRIP_STABLE = {k: v for k, v in CLEAN_SAMPLES.items()
                     if k not in ("chinese", "code_switching")}


@pytest.mark.parametrize("name,text", ROUND_TRIP_STABLE.items())
def test_clean_sample_round_trips_unchanged(name, text):
    assert analyze(text).sanitized == text
