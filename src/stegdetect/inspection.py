"""Additive, preserve-only inspection API; legacy analyze() remains unchanged."""
from __future__ import annotations

from dataclasses import dataclass
import json
from types import MappingProxyType
from typing import ClassVar, Mapping

from .bounded_scan import scan_bounded
from .policy import POLICY_IDS, Policy, decide_bounded
from .unicode_scan import Finding


@dataclass(frozen=True)
class Limits:
    max_chars: int = 1_048_576
    max_input_bytes: int = 4_194_304
    max_findings: int = 256
    max_output_bytes: int = 16_777_216

    def __post_init__(self) -> None:
        for name, minimum in (("max_chars", 0), ("max_input_bytes", 1),
                              ("max_findings", 6), ("max_output_bytes", 512)):
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if value < minimum:
                raise ValueError(f"{name} must be at least {minimum}")


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
    schema_version: ClassVar[int] = 3
    transformation: ClassVar[str] = "preserve"
    policy_id: str
    status: str
    action: str | None
    reason_codes: tuple[str, ...]
    findings: tuple[Evidence, ...]
    finding_count_total: int
    category_counts: Mapping[str, int]
    findings_truncated: bool
    scan_complete: bool
    candidate_text: str | None
    max_output_bytes: int

    def as_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "status": self.status,
            "action": self.action,
            "reason_codes": list(self.reason_codes),
            "findings": [finding.as_dict() for finding in self.findings],
            "finding_count_total": self.finding_count_total,
            "category_counts": dict(self.category_counts),
            "findings_truncated": self.findings_truncated,
            "scan_complete": self.scan_complete,
            "candidate_text": self.candidate_text,
            "transformation": self.transformation,
        }

    def to_json(self) -> str:
        """Compact ASCII JSON, failing if the serialized payload exceeds the cap."""
        payload = json.dumps(self.as_dict(), ensure_ascii=True, separators=(",", ":"))
        if len(payload) > self.max_output_bytes:
            raise ValueError("inspection JSON exceeds max_output_bytes")
        return payload


def _held(policy_id: str, status: str, reason: str, limits: Limits, *,
          total: int = 0, counts: Mapping[str, int] | None = None,
          scan_complete: bool = False) -> InspectionReport:
    return InspectionReport(policy_id=policy_id, status=status, action=None,
                            reason_codes=(reason,), findings=(), finding_count_total=total,
                            category_counts=MappingProxyType(dict(counts or {})),
                            findings_truncated=total > 0, scan_complete=scan_complete,
                            candidate_text=None, max_output_bytes=limits.max_output_bytes)


def inspect_text(text: str, *, policy: Policy = Policy.BALANCED,
                 limits: Limits = Limits()) -> InspectionReport:
    """Inspect original text, then choose an action without changing that text.

    Only an allow decision exposes candidate_text. Review/block require the
    application to hold the document. Limits bound work after input allocation.
    """
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy enum selected by the caller")
    if not isinstance(limits, Limits):
        raise TypeError("limits must be a Limits instance selected by the caller")
    policy_id = POLICY_IDS[policy]
    if not isinstance(text, str):
        return _held(policy_id, "invalid_input", "INVALID_TYPE", limits)
    if len(text) > limits.max_chars:
        return _held(policy_id, "limit_exceeded", "INPUT_CHAR_LIMIT", limits)
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return _held(policy_id, "invalid_input", "INVALID_UNICODE", limits)

    try:
        scan = scan_bounded(text, limits.max_findings)
        if not scan.witness_complete:
            return _held(policy_id, "limit_exceeded", "EVIDENCE_LIMIT", limits,
                         total=scan.finding_count_total, counts=scan.category_counts,
                         scan_complete=True)
        action, reasons = decide_bounded(scan, policy)
        evidence = tuple(Evidence.from_finding(finding) for finding in scan.findings)
        report = InspectionReport(policy_id=policy_id, status="complete", action=action,
                                  reason_codes=reasons, findings=evidence,
                                  finding_count_total=scan.finding_count_total,
                                  category_counts=MappingProxyType(scan.category_counts),
                                  findings_truncated=scan.findings_truncated,
                                  scan_complete=True,
                                  candidate_text=text if action == "allow" else None,
                                  max_output_bytes=limits.max_output_bytes)
        try:
            report.to_json()
        except ValueError:
            return _held(policy_id, "limit_exceeded", "OUTPUT_BYTE_LIMIT", limits,
                         total=scan.finding_count_total, counts=scan.category_counts,
                         scan_complete=True)
        return report
    except Exception:
        return _held(policy_id, "error", "SCAN_ERROR", limits)


def inspect_bytes(data: bytes, *, policy: Policy = Policy.BALANCED,
                  limits: Limits = Limits()) -> InspectionReport:
    """Decode a bounded UTF-8 document before the same inspection contract."""
    if not isinstance(policy, Policy):
        raise TypeError("policy must be a Policy enum selected by the caller")
    if not isinstance(limits, Limits):
        raise TypeError("limits must be a Limits instance selected by the caller")
    policy_id = POLICY_IDS[policy]
    if not isinstance(data, bytes):
        return _held(policy_id, "invalid_input", "INVALID_TYPE", limits)
    if len(data) > limits.max_input_bytes:
        return _held(policy_id, "limit_exceeded", "INPUT_BYTE_LIMIT", limits)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _held(policy_id, "invalid_input", "INVALID_UTF8", limits)
    return inspect_text(text, policy=policy, limits=limits)
