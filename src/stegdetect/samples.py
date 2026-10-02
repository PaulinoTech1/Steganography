"""Attack-sample generators.

Builds steganographic payloads for testing the detector. This is the
"generate" half of the project: every detection rule should have a
generator that produces a sample it must catch. If you add a rule,
add a generator.

These exist so defenders can test. Keep them in the test harness,
not in the shipped CLI.
"""
from __future__ import annotations

from .unicode_scan import INVISIBLE_FORMAT, WEIRD_SPACES

ZWSP = "\u200b"  # bit 0
ZWNJ = "\u200c"  # bit 1

_HOMOGLYPHS = {
    "a": "а", "e": "е", "i": "і", "o": "о", "p": "р", "c": "с",
    "x": "х", "y": "у", "A": "А", "B": "В", "E": "Е", "K": "К",
    "M": "М", "H": "Н", "O": "О", "P": "Р", "C": "С", "T": "Т",
}

_GREEK_HOMOGLYPHS = {
    "a": "\u03b1", "e": "\u03b5", "i": "\u03b9", "o": "\u03bf", "k": "\u03ba", "v": "\u03bd",
    "p": "\u03c1", "t": "\u03c4", "x": "\u03c7", "z": "\u03b6",
    "A": "\u0391", "E": "\u0395", "I": "\u0399", "O": "\u039f", "K": "\u039a", "N": "\u039d",
    "P": "\u03a1", "T": "\u03a4", "Z": "\u0396",
}


def zero_width_encode(payload: str, cover: str = "Please summarize this document.") -> str:
    """Hide payload bits as zero-width chars appended to cover text."""
    bits = "".join(f"{ord(c):08b}" for c in payload)
    hidden = "".join(ZWSP if b == "0" else ZWNJ for b in bits)
    return cover + hidden


def homoglyph_swap(text: str) -> str:
    """Replace Latin letters with Cyrillic lookalikes."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def greek_homoglyph_swap(text: str) -> str:
    """Replace mapped Latin letters with Greek lookalikes; others stay intact."""
    return "".join(_GREEK_HOMOGLYPHS.get(ch, ch) for ch in text)


def invisible_format_embed(text: str, marker: str = "\u00ad") -> str:
    """Insert one configured invisible-format codepoint in the middle of text."""
    if marker not in INVISIBLE_FORMAT:
        raise ValueError("marker must be a configured invisible-format character")
    position = len(text) // 2
    return text[:position] + marker + text[position:]


def suspicious_whitespace_replace(text: str, marker: str = "\u00a0") -> str:
    """Replace the first ASCII space with a configured unusual space."""
    if marker not in WEIRD_SPACES:
        raise ValueError("marker must be a configured unusual space")
    position = text.find(" ")
    if position < 0:
        raise ValueError("text must contain an ASCII space")
    return text[:position] + marker + text[position + 1:]


def bidi_wrap(payload: str, cover: str = "Click here for details") -> str:
    """Wrap payload in a right-to-left override so display order lies."""
    return f"{cover} \u202e{payload}\u202c"


def tag_encode(payload: str, cover: str = "Invoice #1042 attached.") -> str:
    """Encode an ASCII payload with Unicode tags (U+E0000 block)."""
    hidden = "".join(chr(0xE0000 + ord(c)) for c in payload)
    return cover + hidden
