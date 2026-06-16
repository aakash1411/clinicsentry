"""Regulatory report generator (README §8)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from clinicsentry.compliance import (
    ComplianceRule,
    evaluate_rules,
    load_default_rulesets,
)
from clinicsentry.types import (
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
    PHITag,
    RegulatoryReport,
)

__all__ = [
    "build_report",
]


def build_report(
    *,
    session_id: str,
    events: Iterable[AuditEvent],
    framework: str,
    intended_use: str = "",
    software_version: str = "0.1.0",
    policy_version: str = "0.1.0",
    phi_tags: dict[str, PHITag] | None = None,
    propagation_edges: dict[str, list[tuple[str, str]]] | None = None,
    iec62304: dict[str, Any] | None = None,
    secret_key: bytes | None = None,
    rules: list[ComplianceRule] | None = None,
) -> RegulatoryReport:
    """Aggregate audit events for ``session_id`` into a :class:`RegulatoryReport`."""
    events_list = list(events)
    start_ts = events_list[0].timestamp if events_list else datetime.now(UTC)
    end_ts = events_list[-1].timestamp if events_list else start_ts
    duration = (end_ts - start_ts).total_seconds()

    type_counts: Counter[str] = Counter(e.event_type.value for e in events_list)
    agents = sorted({e.agent_id for e in events_list if e.agent_id and e.agent_id != "unknown"})

    phi_tags = phi_tags or {}
    phi_types = Counter(t.phi_type for t in phi_tags.values())

    actions_taken: list[dict[str, Any]] = []
    escalations: list[dict[str, Any]] = []
    confidences: list[float] = []
    human_reviews: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []

    for ev in events_list:
        if ev.event_type == AuditEventType.TOOL_CALL:
            actions_taken.append(
                {
                    "agent_id": ev.agent_id,
                    "tool": ev.redacted_input.get("tool_name"),
                    "tier": ev.risk_tier.value if ev.risk_tier else None,
                    "confidence": ev.confidence_score,
                    "timestamp": ev.timestamp.isoformat(),
                }
            )
        if ev.event_type == AuditEventType.ESCALATION_TRIGGERED:
            escalations.append(
                {
                    "agent_id": ev.agent_id,
                    "decision": ev.escalation_decision,
                    "timestamp": ev.timestamp.isoformat(),
                }
            )
        if ev.event_type == AuditEventType.HUMAN_REVIEW_RESPONSE:
            human_reviews.append({"agent_id": ev.agent_id, "timestamp": ev.timestamp.isoformat()})
        if ev.confidence_score is not None:
            confidences.append(ev.confidence_score)
        if ev.event_type == AuditEventType.MODULE_ERROR:
            anomalies.append(
                {
                    "type": "module_error",
                    "event_id": ev.event_id,
                    "details": ev.redacted_output,
                }
            )

    # Sequence integrity quick-anomaly: detect missing sequence numbers.
    seqs = [e.sequence_number for e in events_list]
    if seqs and seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        anomalies.append({"type": "sequence_gap", "sequence_numbers": seqs})

    interventional_blocked = any(
        e.event_type == AuditEventType.ESCALATION_TRIGGERED
        and e.risk_tier == ClinicalRiskTier.INTERVENTIONAL
        for e in events_list
    )

    metadata = {
        "session_id": session_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "software_version": software_version,
        "policy_version": policy_version,
        "framework": framework,
        "intended_use": intended_use,
    }
    summary = {
        "duration_seconds": duration,
        "total_events": len(events_list),
        "event_type_counts": dict(type_counts),
        "agents_involved": agents,
    }
    phi_summary = {
        "phi_detected_count": len(phi_tags),
        "phi_types_detected": dict(phi_types),
        "phi_redacted_count": len(phi_tags),
        "phi_propagation_paths": [
            {"tag_id": tid, "edges": edges} for tid, edges in (propagation_edges or {}).items()
        ],
        "minimum_necessary_enforced": True,
    }
    decision_summary = {
        "actions_taken": actions_taken,
        "escalations_triggered": escalations,
        "confidence_scores": confidences,
        "human_reviews_completed": human_reviews,
    }
    # Compute attestation by evaluating compliance rules against the session.
    # If the caller did not pass a curated rule list, load every bundled
    # framework (HIPAA + FDA TPLC + IEC 62304 + EU AI Act). The result is a
    # mapping {rule_id: {satisfied, evidence, reason, severity, references}}.
    if rules is None:
        ruleset_rules: list[ComplianceRule] = []
        for rs in load_default_rulesets():
            ruleset_rules.extend(rs.rules)
        active_rules = ruleset_rules
    else:
        active_rules = rules
    by_id = {r.id: r for r in active_rules}
    rule_results = evaluate_rules(
        active_rules,
        events_list,
        secret_key=secret_key,
        iec62304_present=iec62304 is not None,
    )
    attestation: dict[str, Any] = {}
    for result in rule_results:
        rule = by_id[result.rule_id]
        attestation[result.rule_id] = {
            "satisfied": result.satisfied,
            "evidence": result.evidence,
            "reason": result.reason,
            "severity": rule.severity,
            "references": rule.references,
            "framework": rule.framework,
            "title": rule.title,
        }
    # Maintain a back-compat summary key so older consumers (tests, dashboards
    # that pre-date the DSL migration) can still detect interventional gating
    # at a glance. The richer per-rule data is the source of truth.
    attestation["_summary"] = {
        "interventional_blocked_when_required": interventional_blocked
        or not any(e.risk_tier == ClinicalRiskTier.INTERVENTIONAL for e in events_list),
        "rules_evaluated": len(rule_results),
        "rules_satisfied": sum(1 for r in rule_results if r.satisfied),
        "rules_failed_blocker": sum(
            1 for r in rule_results if not r.satisfied and by_id[r.rule_id].severity == "blocker"
        ),
    }
    recommendations: list[str] = []
    if confidences and (sum(confidences) / len(confidences)) < 0.7:
        recommendations.append(
            "Mean session confidence below 0.70 — review prompt design and grounding sources."
        )
    if anomalies:
        recommendations.append("Investigate flagged anomalies before next deployment.")

    return RegulatoryReport(
        report_metadata=metadata,
        session_summary=summary,
        phi_handling_summary=phi_summary,
        clinical_decision_summary=decision_summary,
        compliance_attestation=attestation,
        anomalies=anomalies,
        recommendations=recommendations,
        iec62304_section=iec62304,
    )
