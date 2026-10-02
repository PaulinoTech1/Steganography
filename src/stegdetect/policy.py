"""Named decisions applied to Unicode evidence from the original text."""
from __future__ import annotations

from enum import Enum
from typing import Sequence

from .bounded_scan import ScanResult
from .unicode_context import ContextSummary
from .unicode_scan import Finding


class Policy(str, Enum):
    BALANCED = "balanced"
    LEGACY_VERDICT = "legacy_verdict"
    CONTEXTUAL = "contextual"


POLICY_IDS = {
    Policy.BALANCED: "balanced-v1",
    Policy.LEGACY_VERDICT: "legacy-verdict-v1",
    Policy.CONTEXTUAL: "contextual-v1",
}

_EXPLICIT_OVERRIDES = {"\u202d", "\u202e"}
_INFORMATIONAL = {"ZERO_WIDTH", "INVISIBLE_FORMAT", "SUSPICIOUS_WHITESPACE"}


def decide(text: str, findings: Sequence[Finding], policy: Policy) -> tuple[str, tuple[str, ...]]:
    """Return action and stable action-driving reason IDs, never a text rewrite."""
    if policy is Policy.LEGACY_VERDICT:
        if any(f.severity == "high" for f in findings):
            return "block", ("LEGACY_HIGH_FINDING",)
        if findings:
            return "review", ("LEGACY_FINDING",)
        return "allow", ("NO_FINDINGS",)

    if any(f.category == "BIDI_OVERRIDE" and text[f.offset] in _EXPLICIT_OVERRIDES
           for f in findings):
        return "block", ("BIDI_EXPLICIT_OVERRIDE",)

    review: set[str] = set()
    for finding in findings:
        if finding.category == "BIDI_OVERRIDE":
            review.add("BIDI_CONTROL")
        elif finding.category == "TAG_CHARACTER":
            review.add("TAG_CHARACTER")
        elif finding.category == "MIXED_SCRIPT":
            review.add("MIXED_SCRIPT")
        elif finding.category == "ZERO_WIDTH" and finding.severity == "high":
            review.add("ZERO_WIDTH_CLUSTER")
        elif finding.category not in _INFORMATIONAL:
            review.add("UNCLASSIFIED_EVIDENCE")
    if review:
        return "review", tuple(sorted(review))
    if findings:
        return "allow", ("INFORMATIONAL_CARRIER",)
    return "allow", ("NO_FINDINGS",)


def decide_bounded(scan: ScanResult, policy: Policy) -> tuple[str, tuple[str, ...]]:
    """Decide from whole-document counts, never from the retained detail subset."""
    if policy is Policy.LEGACY_VERDICT:
        if scan.has_high:
            return "block", ("LEGACY_HIGH_FINDING",)
        if scan.finding_count_total:
            return "review", ("LEGACY_FINDING",)
        return "allow", ("NO_FINDINGS",)
    if scan.has_explicit_override:
        return "block", ("BIDI_EXPLICIT_OVERRIDE",)
    counts = scan.category_counts
    review: set[str] = set()
    if counts.get("BIDI_OVERRIDE", 0):
        review.add("BIDI_CONTROL")
    for category in ("TAG_CHARACTER", "MIXED_SCRIPT"):
        if counts.get(category, 0):
            review.add(category)
    if scan.zero_width_high:
        review.add("ZERO_WIDTH_CLUSTER")
    if set(counts) - _INFORMATIONAL - {"BIDI_OVERRIDE", "TAG_CHARACTER", "MIXED_SCRIPT"}:
        review.add("UNCLASSIFIED_EVIDENCE")
    if review:
        return "review", tuple(sorted(review))
    if scan.finding_count_total:
        return "allow", ("INFORMATIONAL_CARRIER",)
    return "allow", ("NO_FINDINGS",)


def decide_contextual(scan: ScanResult, context: ContextSummary) -> tuple[str, tuple[str, ...]]:
    """Discount only validated context counts; retain all original evidence."""
    if scan.has_explicit_override:
        return "block", ("BIDI_EXPLICIT_OVERRIDE",)
    counts = scan.category_counts
    if (context.recognized_zero_width > counts.get("ZERO_WIDTH", 0) or
            context.recognized_tags > counts.get("TAG_CHARACTER", 0) or
            context.recognized_bidi > counts.get("BIDI_OVERRIDE", 0) or
            context.unrecognized_zwj < 0):
        raise ValueError("context counts exceed scanned evidence")
    review: set[str] = set()
    if counts.get("BIDI_OVERRIDE", 0) > context.recognized_bidi:
        review.add("BIDI_CONTROL")
    if counts.get("TAG_CHARACTER", 0) > context.recognized_tags:
        review.add("TAG_CHARACTER")
    if counts.get("MIXED_SCRIPT", 0):
        review.add("MIXED_SCRIPT")
    if context.unrecognized_zwj:
        review.add("UNRECOGNIZED_JOINER")
    if counts.get("ZERO_WIDTH", 0) - context.recognized_zero_width >= 4:
        review.add("ZERO_WIDTH_CLUSTER")
    if set(counts) - {"ZERO_WIDTH", "BIDI_OVERRIDE", "TAG_CHARACTER", "MIXED_SCRIPT",
                       "INVISIBLE_FORMAT", "SUSPICIOUS_WHITESPACE"}:
        review.add("UNCLASSIFIED_EVIDENCE")
    if review:
        return "review", tuple(sorted(review))
    if context.any_recognized:
        return "allow", ("RECOGNIZED_CONTEXT",)
    if scan.finding_count_total:
        return "allow", ("INFORMATIONAL_CARRIER",)
    return "allow", ("NO_FINDINGS",)
