"""stegdetect: pre-filter that catches steganographic prompt injection.

Scan text for invisible/deceptive Unicode carriers, get a verdict,
and get a canonicalized copy; plain-text injections remain out of scope.
"""
from .report import Report, analyze
from .inspection import Evidence, InspectionReport, inspect_text
from .policy import Policy

__all__ = ["analyze", "Report", "inspect_text", "InspectionReport", "Evidence", "Policy"]
__version__ = "0.1.0"
