"""Canonicalization: neutralize invisible/deceptive Unicode.

Detection identifies configured carriers. Canonicalization transforms them:
strip what is invisible, map confusables to their ASCII lookalikes,
collapse weird whitespace. This removes configured carriers, but does
not establish that the sanitized text is safe to forward to a model.

Run detection on the ORIGINAL text, then canonicalize. Never the
reverse: canonicalizing first would destroy the evidence.
"""
from __future__ import annotations

import unicodedata

from .unicode_scan import (
    BIDI_CONTROLS,
    CONFUSABLES,
    INVISIBLE_FORMAT,
    WEIRD_SPACES,
    ZERO_WIDTH,
    _is_tag,
)

_STRIP = set(ZERO_WIDTH) | set(BIDI_CONTROLS) | set(INVISIBLE_FORMAT)


def _nfkc(text: str) -> str:
    """NFKC without quadratic canonical ordering on hostile mark runs.

    Decompose one codepoint at a time (bounded Unicode expansion), then
    stably bucket non-starters by combining class between starters.
    There are at most 255 nonzero classes. NFC receives already ordered
    input, so its insertion ordering cannot encounter a descending run.
    Class-zero characters, including Hangul Jamo, stay in logical order
    for NFC composition. This preserves standard NFKC semantics.
    """
    if text.isascii():
        return text
    ordered: list[str] = []
    marks: dict[int, list[str]] = {}

    def flush() -> None:
        for cls in sorted(marks):
            ordered.extend(marks[cls])
        marks.clear()

    for ch in text:
        for part in unicodedata.normalize("NFKD", ch):
            cls = unicodedata.combining(part)
            if cls:
                marks.setdefault(cls, []).append(part)
            else:
                if marks:
                    flush()
                ordered.append(part)
    flush()
    return unicodedata.normalize("NFC", "".join(ordered))


def canonicalize(text: str) -> str:
    """Return a normalized copy with configured carriers removed or mapped."""
    text = _nfkc(text)
    out: list[str] = []
    for ch in text:
        if ch in _STRIP or _is_tag(ch):
            continue  # invisible carrier: drop it
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
            continue
        if ch in WEIRD_SPACES:
            out.append(" ")
            continue
        out.append(ch)
    return "".join(out)
