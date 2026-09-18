"""Analysis report: verdict, findings, sanitized output.

One function, one JSON-serializable result. Designed to sit in front of
any LLM API call: inspect the verdict, log the findings, forward the
sanitized text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .canonicalize import canonicalize
from .unicode_scan import Finding, scan_unicode

VERDICT_CLEAN = "clean"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"


@dataclass
class Report:
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    sanitized: str = ""
    stats: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "findings": [f.as_dict() for f in self.findings],
            "sanitized": self.sanitized,
            "stats": self.stats,
        }


def analyze(text: str) -> Report:
    findings = scan_unicode(text)
    sanitized = canonicalize(text)
    # Residual check: anything the canonicalizer could not neutralize?
    residual = scan_unicode(sanitized)
    residual_cats = sorted({f.category for f in residual})

    severities = {f.severity for f in findings}
    if "high" in severities:
        verdict = VERDICT_MALICIOUS
    elif "medium" in severities:
        verdict = VERDICT_SUSPICIOUS
    elif findings:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CLEAN

    stats = {
        "input_chars": len(text),
        "sanitized_chars": len(sanitized),
        "chars_removed": len(text) - len(sanitized),
        "finding_count": len(findings),
        "by_category": {},
        "by_severity": {},
        "residual_categories": residual_cats,
    }
    for f in findings:
        stats["by_category"][f.category] = stats["by_category"].get(f.category, 0) + 1
        stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1

    return Report(verdict=verdict, findings=findings,
                  sanitized=sanitized, stats=stats)
