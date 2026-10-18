"""Aegis — defensive guard agent.

Deep, in-depth knowledge of the hacking world pointed entirely at defense:
detect attack techniques, block them live, and remediate. DEFENSIVE ONLY —
this package never generates exploit payloads or automates unauthorized
access. See docs/SCOPE_AND_LIMITS.md.
"""

__version__ = "0.5.0"

from . import guard  # noqa: F401  (in-process guard API: aegis.guard.create_session, ...)

__all__ = ["__version__", "guard"]
