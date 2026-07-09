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
    # Shadow mode: text passes through unchanged; findings and audit events
    # are still produced. For measuring would-be redactions on live traffic.
    AUDIT_ONLY = "AUDIT_ONLY"


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
        replacement = replacement_for(hit.value, hit.phi_type, eff_mode, session_salt)
        if replacement is not None:
            new_text = new_text[: hit.start] + replacement + new_text[hit.end :]
        redacted_values.append(hit.value)
    return RedactionResult(text=new_text, redacted_values=redacted_values)


def replacement_for(
    value: str,
    phi_type: str,
    mode: RedactionMode,
    session_salt: str = "session",
) -> str | None:
    """Return the replacement text for one hit, or None to leave it in place."""
    if mode == RedactionMode.AUDIT_ONLY:
        return None
    if mode == RedactionMode.REDACT:
        return f"[REDACTED:{phi_type}]"
    if mode == RedactionMode.PSEUDONYMIZE:
        return _pseudonym(value, phi_type, session_salt)
    if mode == RedactionMode.GENERALIZE:
        return _generalize(value, phi_type)
    return ""  # SUPPRESS


def shape_preserving(value: str, salt: str) -> str:
    """Replace digits with digits and letters with letters, keeping separators.

    The output is deterministic per ``(salt, value)`` so repeated occurrences
    map consistently within a session. This preserves *shape* for downstream
    format validators; it is pseudonymization, not encryption.
    """
    digest = hashlib.sha256(f"{salt}|shape|{value}".encode()).digest()
    out: list[str] = []
    i = 0
    for ch in value:
        b = digest[i % len(digest)]
        if ch.isdigit():
            out.append(str(b % 10))
            i += 1
        elif ch.isalpha():
            letter = chr(ord("a") + b % 26)
            out.append(letter.upper() if ch.isupper() else letter)
            i += 1
        else:
            out.append(ch)
    return "".join(out)


__all__ += ["shape_preserving", "replacement_for"]
