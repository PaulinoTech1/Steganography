"""stegdetect: pre-filter that catches steganographic prompt injection.

Scan text for invisible/deceptive Unicode carriers, get a verdict,
and get a sanitized copy safe to forward to a model.
"""
from .report import Report, analyze

__all__ = ["analyze", "Report"]
__version__ = "0.1.0"
