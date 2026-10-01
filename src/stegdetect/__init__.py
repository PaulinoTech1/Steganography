"""stegdetect: pre-filter that catches steganographic prompt injection.

Scan text for invisible/deceptive Unicode carriers, get a verdict,
and get a canonicalized copy; plain-text injections remain out of scope.
"""
from .report import Report, analyze

__all__ = ["analyze", "Report"]
__version__ = "0.1.0"
