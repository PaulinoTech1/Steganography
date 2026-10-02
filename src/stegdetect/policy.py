"""Named decisions applied to Unicode evidence from the original text."""
from __future__ import annotations

from enum import Enum
from typing import Sequence

from .unicode_scan import Finding


class Policy(str, Enum):
    BALANCED = "balanced"
    LEGACY_VERDICT = "legacy_verdict"


POLICY_IDS = {
    Policy.BALANCED: "balanced-v1",
    Policy.LEGACY_VERDICT: "legacy-verdict-v1",
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
