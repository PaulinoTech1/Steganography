"""Two-pass Unicode scan with exact counts and capped retained evidence.

This mirrors the frozen legacy rules without materializing one Finding per
letter or retaining all carrier findings. Parity is tested against scan_unicode.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .unicode_scan import (
    BIDI_CONTROLS, CONFUSABLES, INVISIBLE_FORMAT, WEIRD_SPACES,
    ZERO_WIDTH, ZW_CLUSTER_THRESHOLD, Finding, _cp, _is_tag, _script_of,
)


@dataclass
class ScanResult:
    findings: tuple[Finding, ...]
    finding_count_total: int
    category_counts: dict[str, int]
    findings_truncated: bool
    has_high: bool
    has_explicit_override: bool
    zero_width_high: bool
    witness_complete: bool


def _statistics(text: str) -> tuple[int, bool, bool, float, str]:
    zero_width = 0
    total_letters = 0
    scripts: dict[str, int] = {}
    foreign_count = 0
    confusable_count = 0
    has_latin = False
    for ch in text:
        if ch in ZERO_WIDTH:
            zero_width += 1
        if not ch.isalpha():
            continue
        total_letters += 1
        script = _script_of(ch)
        scripts[script] = scripts.get(script, 0) + 1
        if script in ("ASCII", "Latin"):
            has_latin = True
        if script in ("Cyrillic", "Greek", "Armenian"):
            foreign_count += 1
            confusable_count += ch in CONFUSABLES
    density = confusable_count / foreign_count if foreign_count else 0.0
    dominant = (max((script for script in scripts
                     if script in ("Cyrillic", "Greek", "Armenian")),
                    key=lambda script: scripts[script]) if foreign_count else "")
    full_substitution = bool(total_letters and foreign_count >= 8 and density >= 0.9
                             and scripts[dominant] / total_letters >= 0.7)
    isolated = bool(foreign_count and has_latin and density >= 0.9 and not full_substitution)
    return zero_width, full_substitution, isolated, density, dominant


def _findings(text: str, stats: tuple[int, bool, bool, float, str]) -> Iterator[Finding]:
    zero_width, full_substitution, isolated, density, dominant = stats
    for offset, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            high = zero_width >= ZW_CLUSTER_THRESHOLD
            detail = f"Invisible character: {ZERO_WIDTH[ch]}"
            if high:
                detail += (f" Cluster of {zero_width} zero-width characters "
                           "suggests a bit-encoded hidden payload.")
            yield Finding(category="ZERO_WIDTH", severity="high" if high else "medium",
                          offset=offset, detail=detail, codepoints=_cp(ch))
        elif ch in BIDI_CONTROLS:
            yield Finding(category="BIDI_OVERRIDE", severity="high", offset=offset,
                          detail=f"Bidirectional control: {BIDI_CONTROLS[ch]}. "
                                 "Displayed order may differ from logical order.",
                          codepoints=_cp(ch))
        elif ch in INVISIBLE_FORMAT:
            yield Finding(category="INVISIBLE_FORMAT", severity="medium", offset=offset,
                          detail=f"Invisible formatting character: {INVISIBLE_FORMAT[ch]}",
                          codepoints=_cp(ch))
        elif _is_tag(ch):
            yield Finding(category="TAG_CHARACTER", severity="high", offset=offset,
                          detail="Unicode tag character (U+E0000 block). Invisible and "
                                 "a known covert-channel carrier.", codepoints=_cp(ch))
        elif ch in WEIRD_SPACES:
            yield Finding(category="SUSPICIOUS_WHITESPACE", severity="low", offset=offset,
                          detail=f"Non-standard space: {WEIRD_SPACES[ch]}", codepoints=_cp(ch))

        if not ch.isalpha() or _script_of(ch) not in ("Cyrillic", "Greek", "Armenian"):
            continue
        if full_substitution:
            detail = ("Full-alphabet confusable substitution: "
                      f"{dominant}-dominant text where "
                      f"{density:.0%} of letters are Latin lookalikes.")
        elif isolated and ch in CONFUSABLES:
            detail = (f"Homoglyph: {_script_of(ch)} "
                      f"'{ch}' visually mimics Latin '{CONFUSABLES[ch]}'.")
        else:
            continue
        yield Finding(category="MIXED_SCRIPT", severity="high", offset=offset,
                      detail=detail, codepoints=_cp(ch))


def scan_bounded(text: str, max_findings: int) -> ScanResult:
    """Scan entire admitted document, retaining at most max_findings details."""
    stats = _statistics(text)
    first: list[Finding] = []
    representatives: dict[str, Finding] = {}
    counts: dict[str, int] = {}
    total = 0
    has_high = False
    explicit = False
    for finding in _findings(text, stats):
        total += 1
        counts[finding.category] = counts.get(finding.category, 0) + 1
        has_high |= finding.severity == "high"
        is_explicit = (finding.category == "BIDI_OVERRIDE" and
                       text[finding.offset] in ("\u202d", "\u202e"))
        explicit |= is_explicit
        if len(first) < max_findings:
            first.append(finding)
        prior = representatives.get(finding.category)
        if prior is None or (is_explicit and
                             text[prior.offset] not in ("\u202d", "\u202e")):
            representatives[finding.category] = finding
    if len(representatives) > max_findings:
        return ScanResult((), total, counts, total > 0, has_high, explicit,
                          stats[0] >= ZW_CLUSTER_THRESHOLD, False)
    selected = {(f.category, f.offset): f for f in representatives.values()}
    for finding in first:
        if len(selected) >= max_findings:
            break
        selected.setdefault((finding.category, finding.offset), finding)
    retained = tuple(sorted(selected.values(), key=lambda finding: finding.offset))
    return ScanResult(retained, total, dict(sorted(counts.items())),
                      total > len(retained), has_high, explicit,
                      stats[0] >= ZW_CLUSTER_THRESHOLD, True)
