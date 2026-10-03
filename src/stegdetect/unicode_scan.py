"""Unicode-layer steganography detection.

Scans text for invisible or deceptive Unicode constructs used to hide
prompt-injection payloads: zero-width characters, bidi overrides,
homoglyph (mixed-script) substitution, Unicode tag characters, and
unusual whitespace.

Deterministic by design: a codepoint is either present or it isn't.
No models, no probabilities, no training data. This is layer one of the
detector, meant to sit in front of any LLM call and catch the carrier
before the payload reaches the model.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
}

BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

INVISIBLE_FORMAT = {
    "\u00ad": "SOFT HYPHEN",
    "\u034f": "COMBINING GRAPHEME JOINER",
    "\u061c": "ARABIC LETTER MARK",
    "\u115f": "HANGUL CHOSEONG FILLER",
    "\u1160": "HANGUL JUNGSEONG FILLER",
    "\u3164": "HANGUL FILLER",
    "\u2800": "BRAILLE PATTERN BLANK",
}

WEIRD_SPACES = {
    "\u00a0": "NO-BREAK SPACE",
    "\u2000": "EN QUAD",
    "\u2001": "EM QUAD",
    "\u2002": "EN SPACE",
    "\u2003": "EM SPACE",
    "\u2004": "THREE-PER-EM SPACE",
    "\u2005": "FOUR-PER-EM SPACE",
    "\u2006": "SIX-PER-EM SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200a": "HAIR SPACE",
    "\u202f": "NARROW NO-BREAK SPACE",
    "\u205f": "MEDIUM MATHEMATICAL SPACE",
    "\u3000": "IDEOGRAPHIC SPACE",
}

# Minimum zero-width characters before we treat them as a bit-encoded
# payload rather than stray formatting.
ZW_CLUSTER_THRESHOLD = 4

# Common homoglyphs mapped to their Latin lookalike. Not exhaustive;
# it covers the Cyrillic and Greek characters most abused for filter
# evasion. Extend as new confusables are observed in the wild.
CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X",
    # Greek -> Latin
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "χ": "x", "ζ": "z",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "Ζ": "Z",
}

# Detection-only confusables: additional scripts' Latin lookalikes from
# UTS #39 confusables.txt (v18.0), curated to single letters. These are
# flagged by the mixed-script detector but deliberately NOT rewritten by
# canonicalize(), so legitimate Armenian/Arabic/CJK text is never mangled.
# Detection is density-gated (>=90% of foreign letters must be confusables),
# so real prose in these scripts is not flagged.
CONFUSABLES_DETECT_ONLY = {
    # Armenian -> Latin
    "\u054d": "S", "\u054f": "S", "\u0555": "O",
    "\u0561": "w", "\u0563": "q", "\u0566": "q", "\u0570": "h",
    "\u0575": "j", "\u0578": "n", "\u057c": "n", "\u057d": "u",
    "\u0581": "g", "\u0582": "i", "\u0584": "f", "\u0585": "o",
    # Arabic -> Latin
    "\u0627": "l", "\u0647": "o", "\u06be": "o", "\u06c1": "o",
    "\u06d5": "o",
    # Han -> Latin
    "\u4e05": "T", "\u4e2b": "Y",
}


def confusable_target(ch: str) -> str | None:
    """Return the Latin lookalike for a known confusable, if any."""
    return CONFUSABLES.get(ch, CONFUSABLES_DETECT_ONLY.get(ch))


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _script_of(ch: str) -> str:
    o = ord(ch)
    if o < 0x80:
        return "ASCII"
    if o <= 0x024F:
        return "Latin"
    if 0x0370 <= o <= 0x03FF:
        return "Greek"
    if 0x0400 <= o <= 0x052F:
        return "Cyrillic"
    if 0x0530 <= o <= 0x058F:
        return "Armenian"
    if 0x0590 <= o <= 0x05FF:
        return "Hebrew"
    if 0x0600 <= o <= 0x06FF:
        return "Arabic"
    if 0x4E00 <= o <= 0x9FFF or 0x3400 <= o <= 0x4DBF:
        return "Han"
    return "Other"


# Scripts whose Latin lookalikes the detector knows (CONFUSABLES plus
# CONFUSABLES_DETECT_ONLY). Keep in sync with both tables.
_FOREIGN_SCRIPTS = ("Cyrillic", "Greek", "Armenian", "Arabic", "Han")


@dataclass
class Finding:
    category: str
    severity: str  # low | medium | high
    offset: int
    length: int = 1
    detail: str = ""
    codepoints: str = ""

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "offset": self.offset,
            "length": self.length,
            "detail": self.detail,
            "codepoints": self.codepoints,
        }


def _cp(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def scan_unicode(text: str) -> list[Finding]:
    """Return findings for invisible/deceptive Unicode in text."""
    findings: list[Finding] = []
    zw_offsets: list[int] = []

    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            zw_offsets.append(i)
            findings.append(Finding(
                category="ZERO_WIDTH",
                severity="medium",  # upgraded below if clustered
                offset=i,
                detail=f"Invisible character: {ZERO_WIDTH[ch]}",
                codepoints=_cp(ch),
            ))
        elif ch in BIDI_CONTROLS:
            findings.append(Finding(
                category="BIDI_OVERRIDE",
                severity="high",
                offset=i,
                detail=f"Bidirectional control: {BIDI_CONTROLS[ch]}. "
                       "Displayed order may differ from logical order.",
                codepoints=_cp(ch),
            ))
        elif ch in INVISIBLE_FORMAT:
            findings.append(Finding(
                category="INVISIBLE_FORMAT",
                severity="medium",
                offset=i,
                detail=f"Invisible formatting character: {INVISIBLE_FORMAT[ch]}",
                codepoints=_cp(ch),
            ))
        elif _is_tag(ch):
            findings.append(Finding(
                category="TAG_CHARACTER",
                severity="high",
                offset=i,
                detail="Unicode tag character (U+E0000 block). Invisible and "
                       "a known covert-channel carrier.",
                codepoints=_cp(ch),
            ))
        elif ch in WEIRD_SPACES:
            findings.append(Finding(
                category="SUSPICIOUS_WHITESPACE",
                severity="low",
                offset=i,
                detail=f"Non-standard space: {WEIRD_SPACES[ch]}",
                codepoints=_cp(ch),
            ))

    # A cluster of zero-width characters is the classic bit-encoding
    # pattern (e.g. ZWSP=0, ZWNJ=1). Treat as high severity.
    if len(zw_offsets) >= ZW_CLUSTER_THRESHOLD:
        for f in findings:
            if f.category == "ZERO_WIDTH":
                f.severity = "high"
                f.detail += (" Cluster of "
                             f"{len(zw_offsets)} zero-width characters "
                             "suggests a bit-encoded hidden payload.")

    # Mixed-script / homoglyph detection. Two attack shapes:
    #
    #  Shape 1, isolated confusables: foreign-script lookalikes inside
    #  Latin/ASCII text ("раypal"). Almost never legitimate. Flagged only
    #  when nearly every foreign letter is a known confusable, so
    #  legitimate code-switching ("Привет world") passes.
    #
    #  Shape 2, full-alphabet substitution: text dominated by a foreign
    #  script where ~every letter is a Latin confusable. Real prose in
    #  that script almost always contains non-confusable letters, so
    #  >=90% confusable density at length is deliberate evasion.
    letters = [(i, ch) for i, ch in enumerate(text) if ch.isalpha()]
    if letters:
        total = len(letters)
        scripts: dict[str, int] = {}
        for _, ch in letters:
            s = _script_of(ch)
            scripts[s] = scripts.get(s, 0) + 1
        foreign = [(i, ch) for i, ch in letters
                   if _script_of(ch) in _FOREIGN_SCRIPTS]
        has_latin = any(_script_of(ch) in ("ASCII", "Latin")
                        for _, ch in letters)

        def flag(ch: str, i: int, detail: str) -> None:
            findings.append(Finding(
                category="MIXED_SCRIPT",
                severity="high",
                offset=i,
                detail=detail,
                codepoints=_cp(ch),
            ))

        if foreign:
            dom_foreign = max(
                (s for s in scripts if s in _FOREIGN_SCRIPTS),
                key=lambda s: scripts[s])
            confusable_n = sum(1 for _, ch in foreign
                               if confusable_target(ch) is not None)
            density = confusable_n / len(foreign)
            if (scripts[dom_foreign] / total >= 0.7 and len(foreign) >= 8
                    and density >= 0.9):
                # Shape 2: full-alphabet substitution.
                for i, ch in foreign:
                    flag(ch, i,
                         "Full-alphabet confusable substitution: "
                         f"{dom_foreign}-dominant text where "
                         f"{density:.0%} of letters are Latin lookalikes.")
            elif has_latin and density >= 0.9:
                # Shape 1: isolated confusables in Latin text.
                for i, ch in foreign:
                    target = confusable_target(ch)
                    if target is not None:
                        flag(ch, i,
                             f"Homoglyph: {_script_of(ch)} "
                             f"'{ch}' visually mimics Latin '{target}'.")

    return sorted(findings, key=lambda f: f.offset)
