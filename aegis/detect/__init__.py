"""Detection package: secrets, pattern engine, chain detectors."""

from .engine import (Finding, analyze_trace, call_text,  # noqa: F401
                     pattern_scan)
from . import secrets  # noqa: F401

__all__ = ["Finding", "analyze_trace", "call_text", "pattern_scan", "secrets"]
