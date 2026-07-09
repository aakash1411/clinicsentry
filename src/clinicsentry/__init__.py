"""ClinicSentry: framework-agnostic compliance middleware for clinical AI agents.

Everything importable from this module is the stable public API (see
docs/api-stability.md). Symbols under ``clinicsentry.<module>`` that are not
re-exported here are internal and may change between minor releases.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from clinicsentry.errors import ClinicSentryError, PolicyError
from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.custom import register_detector
from clinicsentry.phi.firewall import (
    PHIFinding,
    PHIFirewall,
    PHIScanResult,
    TokenizeResult,
)
from clinicsentry.phi.minimum_necessary import minimum_necessary
from clinicsentry.phi.redaction import RedactionMode
from clinicsentry.phi.streaming import StreamRedactor
from clinicsentry.policy import PolicyConfig, load_policy, policy_schema
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
    "ClinicSentryError",
    "PolicyError",
    "PolicyConfig",
    "load_policy",
    "policy_schema",
    "PHIFirewall",
    "PHIScanResult",
    "PHIFinding",
    "TokenizeResult",
    "StreamRedactor",
    "RedactionMode",
    "register_detector",
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
