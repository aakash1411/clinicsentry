"""ClinicSentry: framework-agnostic compliance middleware for clinical AI agents."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.minimum_necessary import minimum_necessary
from clinicsentry.types import (
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
    EscalationDecision,
    PHITag,
    RegulatoryReport,
)

__all__ = [
    "ClinicSentry",
    "AuditEvent",
    "AuditEventType",
    "ClinicalRiskTier",
    "EscalationDecision",
    "PHITag",
    "RegulatoryReport",
    "minimum_necessary",
]

# Single-sourced from pyproject.toml via installed package metadata.
try:
    __version__ = _dist_version("clinicsentry")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    __version__ = "0.0.0+unknown"
