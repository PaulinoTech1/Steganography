"""Attack-sample generators.

Builds steganographic payloads for testing the detector. This is the
"generate" half of the project: every detection rule should have a
generator that produces a sample it must catch. If you add a rule,
add a generator.

These exist so defenders can test. Keep them in the test harness,
not in the shipped CLI.
"""
from __future__ import annotations

ZWSP = "\u200b"  # bit 0
ZWNJ = "\u200c"  # bit 1

_HOMOGLYPHS = {
    "a": "а", "e": "е", "i": "і", "o": "о", "p": "р", "c": "с",
    "x": "х", "y": "у", "A": "А", "B": "В", "E": "Е", "K": "К",
    "M": "М", "H": "Н", "O": "О", "P": "Р", "C": "С", "T": "Т",
}


def zero_width_encode(payload: str, cover: str = "Please summarize this document.") -> str:
    """Hide payload bits as zero-width chars appended to cover text."""
    bits = "".join(f"{ord(c):08b}" for c in payload)
    hidden = "".join(ZWSP if b == "0" else ZWNJ for b in bits)
    return cover + hidden


def homoglyph_swap(text: str) -> str:
    """Replace Latin letters with Cyrillic lookalikes."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def bidi_wrap(payload: str, cover: str = "Click here for details") -> str:
    """Wrap payload in a right-to-left override so display order lies."""
    return f"{cover} \u202e{payload}\u202c"


def tag_encode(payload: str, cover: str = "Invoice #1042 attached.") -> str:
    """Encode an ASCII payload with Unicode tags (U+E0000 block)."""
    hidden = "".join(chr(0xE0000 + ord(c)) for c in payload)
    return cover + hidden
