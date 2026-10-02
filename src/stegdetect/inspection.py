"""Additive, preserve-only inspection API; legacy analyze() remains unchanged."""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .policy import POLICY_IDS, Policy, decide
from .unicode_scan import Finding, scan_unicode


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    category: str
    severity: str
    offset: int
    length: int
    detail: str
    codepoints: str

    @classmethod
    def from_finding(cls, finding: Finding) -> Evidence:
        return cls(rule_id=f"unicode.{finding.category.lower()}.v1",
                   category=finding.category, severity=finding.severity,
                   offset=finding.offset, length=finding.length,
                   detail=finding.detail, codepoints=finding.codepoints)

    def as_dict(self) -> dict:
        return vars(self).copy()


@dataclass(frozen=True)
class InspectionReport:
    schema_version: ClassVar[int] = 2
    findings_truncated: ClassVar[bool] = False
    transformation: ClassVar[str] = "preserve"
    policy_id: str
    status: str
    action: str | None
    reason_codes: tuple[str, ...]
    findings: tuple[Evidence, ...]
    finding_count_total: int
    scan_complete: bool
    candidate_text: str | None

    def as_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "status": self.status,
            "action": self.action,
            "reason_codes": list(self.reason_codes),
            "findings": [finding.as_dict() for finding in self.findings],
            "finding_count_total": self.finding_count_total,
            "findings_truncated": self.findings_truncated,
            "scan_complete": self.scan_complete,
            "candidate_text": self.candidate_text,
            "transformation": self.transformation,
        }


def inspect_text(text: str, *, policy: Policy = Policy.BALANCED) -> InspectionReport:
    """Inspect original text, then choose an action without changing that text.

    Only an allow decision exposes candidate_text. Review/block require the
    application to hold the document. There is no size cap in this P1 API.
    """
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy enum selected by the caller")
    policy_id = POLICY_IDS[policy]
    invalid_reason = None
    if not isinstance(text, str):
        invalid_reason = "INVALID_TYPE"
    elif any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        invalid_reason = "INVALID_UNICODE"
    if invalid_reason:
        return InspectionReport(policy_id=policy_id, status="invalid_input", action=None,
                                reason_codes=(invalid_reason,), findings=(), finding_count_total=0,
                                scan_complete=False, candidate_text=None)

    try:
        found = scan_unicode(text)
        action, reasons = decide(text, found, policy)
        evidence = tuple(Evidence.from_finding(finding) for finding in found)
    except Exception:
        return InspectionReport(policy_id=policy_id, status="error", action=None,
                                reason_codes=("SCAN_ERROR",), findings=(), finding_count_total=0,
                                scan_complete=False, candidate_text=None)
    return InspectionReport(policy_id=policy_id, status="complete", action=action,
                            reason_codes=reasons, findings=evidence,
                            finding_count_total=len(evidence), scan_complete=True,
                            candidate_text=text if action == "allow" else None)
