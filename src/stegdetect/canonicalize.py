"""Canonicalization: neutralize invisible/deceptive Unicode.

Detection tells you a payload is there. Canonicalization disarms it:
strip what is invisible, map confusables to their ASCII lookalikes,
collapse weird whitespace. The sanitized output is safe to forward to
the model.

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


def canonicalize(text: str) -> str:
    """Return a neutralized copy of text safe to pass to a model."""
    text = unicodedata.normalize("NFKC", text)
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
