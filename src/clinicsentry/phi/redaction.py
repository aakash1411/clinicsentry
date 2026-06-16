"""Redaction strategies for detected PHI.

Implements REDACT, PSEUDONYMIZE, GENERALIZE, SUPPRESS modes (README §6).
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass

from clinicsentry.phi.detectors import Hit

__all__ = [
    "RedactionMode",
    "RedactionResult",
    "apply_redaction",
]


class RedactionMode(str, enum.Enum):
    """Redaction strategy selector."""

    REDACT = "REDACT"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"
    SUPPRESS = "SUPPRESS"


@dataclass
class RedactionResult:
    """Outcome of applying redaction to a string."""

    text: str
    redacted_values: list[str]


_PSEUDONYM_PREFIX = {
    "PATIENT_NAME": "PT",
    "NAME": "PERSON",
    "EMAIL": "email",
    "PHONE": "phone",
    "SSN": "ssn",
    "MRN": "mrn",
    "NPI": "npi",
    "DEA": "dea",
    "DATE": "date",
    "ZIP": "zip",
    "URL": "url",
    "IP_ADDRESS": "ip",
}


def _pseudonym(value: str, phi_type: str, salt: str) -> str:
    """Stable pseudonym for ``value`` within a session-salt scope."""
    digest = hashlib.sha256(f"{salt}|{phi_type}|{value}".encode()).hexdigest()[:8]
    prefix = _PSEUDONYM_PREFIX.get(phi_type, phi_type.lower())
    return f"{prefix}_{digest}"


def _generalize(value: str, phi_type: str) -> str:
    """Reduce specificity per HIPAA Safe Harbor heuristics."""
    if phi_type == "DATE":
        # Year-only: pull a 4-digit year if present, else suppress.
        for token in value.replace("/", "-").split("-"):
            t = token.strip()
            if len(t) == 4 and t.isdigit():
                return t
        return "[DATE_YEAR_UNKNOWN]"
    if phi_type == "ZIP":
        digits = "".join(ch for ch in value if ch.isdigit())
        return digits[:3] + "**" if len(digits) >= 3 else "[ZIP]"
    return f"[{phi_type}]"


def apply_redaction(
    text: str,
    hits: list[Hit],
    mode: RedactionMode,
    overrides: dict[str, RedactionMode] | None = None,
    session_salt: str = "session",
) -> RedactionResult:
    """Apply ``mode`` (with per-PHI-type ``overrides``) to ``text``.

    Hits are applied right-to-left so character offsets remain valid.
    """
    if not hits:
        return RedactionResult(text=text, redacted_values=[])
    overrides = overrides or {}
    ordered = sorted(hits, key=lambda h: h.start, reverse=True)
    new_text = text
    redacted_values: list[str] = []
    for hit in ordered:
        eff_mode = overrides.get(hit.phi_type, mode)
        if eff_mode == RedactionMode.REDACT:
            replacement = f"[REDACTED:{hit.phi_type}]"
        elif eff_mode == RedactionMode.PSEUDONYMIZE:
            replacement = _pseudonym(hit.value, hit.phi_type, session_salt)
        elif eff_mode == RedactionMode.GENERALIZE:
            replacement = _generalize(hit.value, hit.phi_type)
        else:  # SUPPRESS
            replacement = ""
        new_text = new_text[: hit.start] + replacement + new_text[hit.end :]
        redacted_values.append(hit.value)
    return RedactionResult(text=new_text, redacted_values=redacted_values)
