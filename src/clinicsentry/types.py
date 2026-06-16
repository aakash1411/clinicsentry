"""Core type definitions for ClinicSentry.

These dataclasses and enums form the stable public schema referenced across all
modules. Keep additions backward compatible — every field that may be persisted
to an audit trail must be JSON-serializable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

__all__ = [
    "PHITag",
    "ClinicalRiskTier",
    "EscalationDecision",
    "AuditEventType",
    "AuditEvent",
    "RegulatoryReport",
]

# ---------------------------------------------------------------------------
# PHI tagging
# ---------------------------------------------------------------------------


@dataclass
class PHITag:
    """Tag attached to a piece of PHI for propagation tracking.

    See README §6 PHI Tagging and Propagation Graph.
    """

    phi_type: str
    source: str
    confidence: float
    redacted_value: str
    origin_agent: str = "unknown"
    propagation_path: list[str] = field(default_factory=list)
    tag_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "tag_id": self.tag_id,
            "phi_type": self.phi_type,
            "source": self.source,
            "confidence": self.confidence,
            "redacted_value": self.redacted_value,
            "origin_agent": self.origin_agent,
            "propagation_path": list(self.propagation_path),
        }


# ---------------------------------------------------------------------------
# Clinical risk tiering / escalation
# ---------------------------------------------------------------------------


class ClinicalRiskTier(str, enum.Enum):
    """Three-tier clinical risk taxonomy. README §7."""

    INFORMATIONAL = "informational"
    ADVISORY = "advisory"
    INTERVENTIONAL = "interventional"


@dataclass
class EscalationDecision:
    """Decision emitted by the Clinical Escalation Router. README §7."""

    action: str  # "proceed" | "escalate" | "block"
    tier: ClinicalRiskTier
    confidence: float
    confidence_breakdown: dict[str, float] = field(default_factory=dict)
    escalation_reason: str = ""
    escalation_channel: str = ""
    suggested_reviewer_role: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize."""
        return {
            "action": self.action,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "confidence_breakdown": dict(self.confidence_breakdown),
            "escalation_reason": self.escalation_reason,
            "escalation_channel": self.escalation_channel,
            "suggested_reviewer_role": self.suggested_reviewer_role,
        }


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


class AuditEventType(str, enum.Enum):
    """Audit event taxonomy. README §8."""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    USER_INPUT = "user_input"
    AGENT_LLM_CALL = "agent_llm_call"
    AGENT_LLM_RESPONSE = "agent_llm_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    INTER_AGENT_MESSAGE = "inter_agent_message"
    MCP_TOOL_CALL = "mcp_tool_call"
    A2A_MESSAGE = "a2a_message"
    PHI_DETECTED = "phi_detected"
    PHI_REDACTED = "phi_redacted"
    ESCALATION_TRIGGERED = "escalation_triggered"
    HUMAN_REVIEW_RESPONSE = "human_review_response"
    POLICY_VIOLATION = "policy_violation"
    MODULE_ERROR = "module_error"


def _utc_now() -> datetime:
    """Return current UTC time with microsecond precision."""
    return datetime.now(UTC)


@dataclass
class AuditEvent:
    """Immutable audit record. See README §8 Audit Event Schema."""

    event_type: AuditEventType
    session_id: str
    sequence_number: int
    agent_id: str = "unknown"
    agent_framework: str = "unknown"
    input_hash: str = ""
    output_hash: str = ""
    redacted_input: dict[str, Any] = field(default_factory=dict)
    redacted_output: dict[str, Any] = field(default_factory=dict)
    phi_tags_detected: list[str] = field(default_factory=list)
    risk_tier: ClinicalRiskTier | None = None
    confidence_score: float | None = None
    escalation_decision: dict[str, Any] | None = None
    prev_event_hash: str = ""
    signature: str = ""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict (deterministic ordering)."""
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence_number": self.sequence_number,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "agent_framework": self.agent_framework,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "redacted_input": self.redacted_input,
            "redacted_output": self.redacted_output,
            "phi_tags_detected": list(self.phi_tags_detected),
            "risk_tier": self.risk_tier.value if self.risk_tier else None,
            "confidence_score": self.confidence_score,
            "escalation_decision": self.escalation_decision,
            "prev_event_hash": self.prev_event_hash,
            "signature": self.signature,
        }


# ---------------------------------------------------------------------------
# Regulatory report
# ---------------------------------------------------------------------------


@dataclass
class RegulatoryReport:
    """FDA TPLC / IEC 62304 aligned session report. README §8."""

    report_metadata: dict[str, Any]
    session_summary: dict[str, Any]
    phi_handling_summary: dict[str, Any]
    clinical_decision_summary: dict[str, Any]
    compliance_attestation: dict[str, Any]
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    iec62304_section: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full report."""
        out = {
            "report_metadata": self.report_metadata,
            "session_summary": self.session_summary,
            "phi_handling_summary": self.phi_handling_summary,
            "clinical_decision_summary": self.clinical_decision_summary,
            "compliance_attestation": self.compliance_attestation,
            "anomalies": self.anomalies,
            "recommendations": self.recommendations,
        }
        if self.iec62304_section is not None:
            out["iec62304_section"] = self.iec62304_section
        return out
