"""Shared secret-value heuristic used to reject and redact credential-shaped text.

``SECRET_VALUE_RE`` lives here (rather than in ``cloud.specs``) so both the spec
submit gate and the prompt-disclosure renderer can guard against the same
credential shapes without importing a heavy module. ``cloud.specs`` re-exports
the name for its existing importers.
"""

from __future__ import annotations

import re

__all__ = ["SECRET_VALUE_RE"]

SECRET_VALUE_RE = re.compile(
    r"(sk-or-[A-Za-z0-9._-]{6,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|Bearer\s+[A-Za-z0-9._-]{12,})"
)
