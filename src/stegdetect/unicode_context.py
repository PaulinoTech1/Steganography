"""Narrow, offline Unicode context recognition for an opt-in policy.

This annotates existing carrier evidence; it does not change the legacy
scanner or claim that a valid Unicode construction has benign intent.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import unicodedata

from .unicode_scan import INVISIBLE_FORMAT, ZERO_WIDTH, _is_tag


_DATA = Path(__file__).with_name("data") / "emoji-context-18.0.txt"
_CARRIER_NEIGHBORS = {"\u200c", "\u200d", "\ufe0e", "\ufe0f"}
_RTL_OPENERS = {"\u2067", "\u2068"}  # RLI and FSI; LRI stays under review.
_ISOLATE_OPENERS = _RTL_OPENERS | {"\u2066"}
_BIDI_CONTROLS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                  "\u2066", "\u2067", "\u2068", "\u2069"}
_DEVANAGARI_VIRAMA = "\u094d"


@dataclass(frozen=True)
class ContextSummary:
    recognized_zero_width: int = 0
    recognized_tags: int = 0
    recognized_bidi: int = 0
    unrecognized_zwj: int = 0

    @property
    def any_recognized(self) -> bool:
        return bool(self.recognized_zero_width or self.recognized_tags or
                    self.recognized_bidi)


@lru_cache(maxsize=1)
def _emoji_trie() -> dict:
    trie: dict = {}
    rows = 0
    for line in _DATA.read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        sequence = "".join(chr(int(value, 16)) for value in line.split())
        node = trie
        for char in sequence:
            node = node.setdefault(char, {})
        node[None] = True
        rows += 1
    if rows != 1617:
        raise ValueError("bundled Emoji 18 context data is incomplete")
    return trie


def _carrier_neighbor(char: str) -> bool:
    return char in _CARRIER_NEIGHBORS or _is_tag(char)


def _emoji_counts(text: str) -> tuple[int, int]:
    trie = _emoji_trie()
    zero_width = tags = 0
    i = 0
    while i < len(text):
        node = trie.get(text[i])
        if node is None:
            i += 1
            continue
        j = i + 1
        end = j if None in node else 0
        while j < len(text) and text[j] in node:
            node = node[text[j]]
            j += 1
            if None in node:
                end = j
        if (end and (i == 0 or not _carrier_neighbor(text[i - 1])) and
                (end == len(text) or not _carrier_neighbor(text[end]))):
            sequence = text[i:end]
            zero_width += sequence.count("\u200d")
            tags += sum(_is_tag(char) for char in sequence)
            i = end
        else:
            i += 1
    return zero_width, tags


def _joining_counts(text: str) -> tuple[int, int]:
    zwnj = zwj = 0
    for i in range(1, len(text) - 1):
        char = text[i]
        before, after = text[i - 1], text[i + 1]
        if (char == "\u200c" and before.isalpha() and after.isalpha() and
                0x0600 <= ord(before) <= 0x06FF and
                0x0600 <= ord(after) <= 0x06FF):
            zwnj += 1
        elif (char == "\u200d" and before == _DEVANAGARI_VIRAMA and
              after.isalpha() and 0x0900 <= ord(after) <= 0x097F):
            zwj += 1
    return zwnj, zwj


def _simple_rtl_body(text: str, start: int, end: int) -> bool:
    strong = False
    for char in text[start:end]:
        if (char in _BIDI_CONTROLS or char in ZERO_WIDTH or
                char in INVISIBLE_FORMAT or _carrier_neighbor(char) or char in "\r\n"):
            return False
        bidi = unicodedata.bidirectional(char)
        if bidi in ("R", "AL"):
            strong = True
        elif bidi == "ON" and not unicodedata.category(char).startswith("P"):
            return False
        elif bidi not in ("AN", "NSM", "WS", "CS", "ES", "ET", "ON"):
            return False
    return strong


def _isolate_count(text: str) -> int:
    recognized = depth = 0
    start = -1
    opener = ""
    nested = False
    for i, char in enumerate(text):
        if char in _ISOLATE_OPENERS:
            if depth == 0:
                start, opener, nested = i, char, False
            else:
                nested = True
            depth += 1
        elif char == "\u2069" and depth:
            depth -= 1
            if (depth == 0 and not nested and opener in _RTL_OPENERS and
                    _simple_rtl_body(text, start + 1, i)):
                recognized += 2
    return recognized


def recognize_context(text: str) -> ContextSummary:
    """Count exact recognized carriers after the bounded scan has completed."""
    emoji_zwj, tags = _emoji_counts(text)
    arabic_zwnj, indic_zwj = _joining_counts(text)
    recognized_zwj = emoji_zwj + indic_zwj
    return ContextSummary(recognized_zero_width=recognized_zwj + arabic_zwnj,
                          recognized_tags=tags,
                          recognized_bidi=_isolate_count(text),
                          unrecognized_zwj=text.count("\u200d") - recognized_zwj)
