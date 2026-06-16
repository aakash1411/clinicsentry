"""Exception taxonomy per ADR-0008.

All ClinicSentry exceptions descend from :class:`ClinicSentryError`. Each
carries a stable ``code`` attribute usable in tests, dashboards, and
documentation. Messages MUST NOT contain PHI: reference field paths and
``tag_id`` values only.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "ClinicSentryError",
    "PolicyError",
    "PHIError",
    "PHIDetectionError",
    "RedactionError",
    "EscalationError",
    "EscalationRaised",
    "ConfidenceComputeError",
    "AuditError",
    "ChainIntegrityError",
    "BackendError",
    "MedDeviceError",
    "SafetyClassViolation",
    "DoseOutOfRange",
    "AuthorizationRequired",
    "EmergencyStopActive",
    "AdapterError",
]


class ClinicSentryError(Exception):
    """Base exception for the ClinicSentry package.

    All concrete exceptions set a class-level ``code`` attribute (e.g.
    ``"CG-PHI-001"``). Catching ``ClinicSentryError`` catches every package
    exception; catching a more specific subclass is preferred.
    """

    code: str = "CG-CORE-000"

    def __init__(self, message: str = "", *, context: dict[str, Any] | None = None) -> None:
        """Construct a typed exception.

        Args:
            message: human-readable description; MUST NOT contain PHI.
            context: optional structured context for observability (field
                paths, tag ids, sequence numbers). MUST NOT contain PHI.
        """
        super().__init__(message)
        self.context: dict[str, Any] = dict(context or {})


# --- Policy ---------------------------------------------------------------


class PolicyError(ClinicSentryError):
    """Malformed policy YAML, dict, or environment override."""

    code = "CG-POL-001"


# --- PHI ------------------------------------------------------------------


class PHIError(ClinicSentryError):
    """Base for PHI module failures."""

    code = "CG-PHI-000"


class PHIDetectionError(PHIError):
    """A detector raised internally; the input could not be scanned."""

    code = "CG-PHI-001"


class RedactionError(PHIError):
    """A redaction strategy failed (e.g., unknown category, generator error)."""

    code = "CG-PHI-002"


# --- Escalation -----------------------------------------------------------


class EscalationError(ClinicSentryError):
    """Base for escalation module failures."""

    code = "CG-ESC-000"


class EscalationRaised(EscalationError):
    """Control-flow signal: a registered action must not proceed.

    This is **not** an error condition; host frameworks should catch it and
    route to the configured escalation channel.
    """

    code = "CG-ESC-001"

    def __init__(self, decision: Any, *, context: dict[str, Any] | None = None) -> None:
        """Carry the offending :class:`EscalationDecision`."""
        super().__init__(message=f"escalation: {getattr(decision, 'action', '?')}", context=context)
        self.decision = decision


class ConfidenceComputeError(EscalationError):
    """A confidence signal computation failed."""

    code = "CG-ESC-002"


# --- Audit ----------------------------------------------------------------


class AuditError(ClinicSentryError):
    """Base for audit module failures."""

    code = "CG-AUD-000"


class ChainIntegrityError(AuditError):
    """Hash/HMAC mismatch on chain verification."""

    code = "CG-AUD-001"


class BackendError(AuditError):
    """Audit backend I/O failure (disk full, DB unreachable, etc.)."""

    code = "CG-AUD-002"


# --- MedDevice ------------------------------------------------------------


class MedDeviceError(ClinicSentryError):
    """Base for IEC 62304 / MedDevice module failures."""

    code = "CG-MED-000"


class SafetyClassViolation(MedDeviceError):
    """An action exceeds the declared software safety class ceiling."""

    code = "CG-MED-001"


class DoseOutOfRange(MedDeviceError):
    """A clinical action exceeds its declared dose / rate bounds."""

    code = "CG-MED-002"


class AuthorizationRequired(MedDeviceError):
    """Class B/C autonomous action requires a clinician authorization signature."""

    code = "CG-MED-003"


class EmergencyStopActive(MedDeviceError):
    """The emergency-stop flag is set; no action may proceed."""

    code = "CG-MED-004"


# --- Adapter --------------------------------------------------------------


class AdapterError(ClinicSentryError):
    """Framework adapter wiring or invocation failure."""

    code = "CG-ADP-001"
