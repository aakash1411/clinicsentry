"""Tests for the compliance attestation rule engine (ADR-0007)."""

from __future__ import annotations

from pathlib import Path

import pytest

from clinicsentry.audit.backend import InMemoryAuditBackend
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.report import build_report
from clinicsentry.compliance import (
    ComplianceRule,
    evaluate_rules,
    load_default_rulesets,
    load_ruleset,
)
from clinicsentry.types import AuditEvent, AuditEventType, ClinicalRiskTier

RULES_DIR = Path(__file__).resolve().parents[1] / "src/clinicsentry/compliance/rules"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    seq: int,
    event_type: AuditEventType = AuditEventType.AGENT_LLM_CALL,
    risk_tier: ClinicalRiskTier | None = None,
    agent_id: str = "agent-x",
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        session_id="s1",
        sequence_number=seq,
        agent_id=agent_id,
        agent_framework="test",
        risk_tier=risk_tier,
        signature="sig-" + str(seq),  # non-empty so signature_present passes
    )


def _emit_session(
    secret_key: bytes, n_events: int = 3
) -> tuple[list[AuditEvent], InMemoryAuditBackend]:
    """Emit ``n_events`` through an AuditChain so signatures + prev-hashes are valid."""
    backend = InMemoryAuditBackend()
    chain = AuditChain(session_id="s1", secret_key=secret_key, backend=backend)
    events: list[AuditEvent] = []
    for i in range(n_events):
        ev = AuditEvent(
            event_type=AuditEventType.AGENT_LLM_CALL,
            session_id="s1",
            sequence_number=0,  # filled in by chain.emit
            agent_id=f"agent-{i}",
            agent_framework="test",
        )
        events.append(chain.emit(ev))
    return events, backend


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_load_hipaa_ruleset() -> None:
    rs = load_ruleset(RULES_DIR / "hipaa.yaml")
    assert rs.name == "hipaa"
    assert len(rs.rules) == 5
    ids = {r.id for r in rs.rules}
    assert "HIPAA-164.312-a-1" in ids
    assert "HIPAA-164.502-b" in ids


def test_load_all_rulesets() -> None:
    sets = load_default_rulesets()
    names = {rs.name for rs in sets}
    assert names == {"hipaa", "fda_tplc", "iec62304", "eu_ai_act"}


def test_rule_severity_levels_preserved() -> None:
    rs = load_ruleset(RULES_DIR / "hipaa.yaml")
    severities = {r.severity for r in rs.rules}
    assert "blocker" in severities


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------


def test_every_event_has_agent_id_passes() -> None:
    rule = ComplianceRule(
        id="t1",
        title="t",
        predicate="every_event.has(agent_id)",
    )
    events = [_make_event(1), _make_event(2)]
    results = evaluate_rules([rule], events)
    assert results[0].satisfied
    assert len(results[0].evidence) == 2


def test_every_event_has_agent_id_fails_when_missing() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="every_event.has(agent_id)")
    events = [_make_event(1, agent_id=""), _make_event(2)]
    results = evaluate_rules([rule], events)
    assert not results[0].satisfied
    assert "missing" in results[0].reason


def test_event_count_threshold() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="event_count >= 2")
    events = [_make_event(1), _make_event(2), _make_event(3)]
    assert evaluate_rules([rule], events)[0].satisfied
    assert not evaluate_rules([rule], events[:1])[0].satisfied


def test_chain_verifies_passes_with_valid_chain() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="chain_verifies")
    secret = b"k" * 32
    events, backend = _emit_session(secret)
    results = evaluate_rules([rule], events, secret_key=secret, backend=backend)
    assert results[0].satisfied, results[0].reason


def test_chain_verifies_fails_without_secret_key() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="chain_verifies")
    events, _ = _emit_session(b"k" * 32)
    results = evaluate_rules([rule], events, secret_key=None)
    assert not results[0].satisfied
    assert "secret_key" in results[0].reason


def test_no_gaps_in_sequence_detects_gap() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="no_gaps_in_sequence")
    events = [_make_event(1), _make_event(2), _make_event(4)]  # gap at 3
    results = evaluate_rules([rule], events)
    assert not results[0].satisfied


def test_phi_redacted_when_detected_fails_when_not_redacted() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="phi_redacted_when_detected")
    events = [_make_event(1, event_type=AuditEventType.PHI_DETECTED)]
    results = evaluate_rules([rule], events)
    assert not results[0].satisfied


def test_phi_redacted_when_detected_passes_when_paired() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="phi_redacted_when_detected")
    events = [
        _make_event(1, event_type=AuditEventType.PHI_DETECTED),
        _make_event(2, event_type=AuditEventType.PHI_REDACTED),
    ]
    results = evaluate_rules([rule], events)
    assert results[0].satisfied


def test_escalation_for_interventional_passes_when_escalated() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="escalation_triggered_for_interventional")
    events = [
        _make_event(
            1,
            event_type=AuditEventType.TOOL_CALL,
            risk_tier=ClinicalRiskTier.INTERVENTIONAL,
        ),
        _make_event(2, event_type=AuditEventType.ESCALATION_TRIGGERED),
    ]
    results = evaluate_rules([rule], events)
    assert results[0].satisfied


def test_escalation_for_interventional_fails_when_unescalated() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="escalation_triggered_for_interventional")
    events = [
        _make_event(
            1,
            event_type=AuditEventType.TOOL_CALL,
            risk_tier=ClinicalRiskTier.INTERVENTIONAL,
        ),
    ]
    results = evaluate_rules([rule], events)
    assert not results[0].satisfied


def test_unknown_predicate_returns_unsatisfied() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="nonexistent_check")
    results = evaluate_rules([rule], [_make_event(1)])
    assert not results[0].satisfied
    assert "unknown predicate" in results[0].reason


def test_unsupported_predicate_shape_returns_unsatisfied() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="1 + 1")
    results = evaluate_rules([rule], [_make_event(1)])
    assert not results[0].satisfied


def test_predicate_with_syntax_error_returns_unsatisfied() -> None:
    rule = ComplianceRule(id="t1", title="t", predicate="event_count >=")  # incomplete
    results = evaluate_rules([rule], [_make_event(1)])
    assert not results[0].satisfied
    assert "parse error" in results[0].reason


# ---------------------------------------------------------------------------
# End-to-end: build_report uses the DSL
# ---------------------------------------------------------------------------


def test_build_report_emits_rule_ids_as_attestation_keys() -> None:
    secret = b"k" * 32
    events, _ = _emit_session(secret)
    report = build_report(
        session_id="s1",
        events=events,
        framework="test",
        secret_key=secret,
    )
    # Every rule across the four bundled frameworks should appear as a key.
    assert "HIPAA-164.312-b" in report.compliance_attestation
    assert "FDA-TPLC-III-B-1" in report.compliance_attestation
    assert "IEC-62304-5.1" in report.compliance_attestation
    assert "EU-AI-ACT-Art-9-2" in report.compliance_attestation
    # Each entry is the rich rule-result dict.
    entry = report.compliance_attestation["HIPAA-164.312-b"]
    assert isinstance(entry, dict)
    assert "satisfied" in entry
    assert "evidence" in entry
    assert "reason" in entry
    assert "severity" in entry


def test_build_report_summary_counts_match() -> None:
    secret = b"k" * 32
    events, _ = _emit_session(secret)
    report = build_report(
        session_id="s1",
        events=events,
        framework="test",
        secret_key=secret,
    )
    summary = report.compliance_attestation["_summary"]
    n_rules = sum(1 for k in report.compliance_attestation if not k.startswith("_"))
    assert summary["rules_evaluated"] == n_rules
    assert summary["rules_satisfied"] + summary["rules_failed_blocker"] <= n_rules


def test_build_report_chain_verifies_fails_without_key() -> None:
    secret = b"k" * 32
    events, _ = _emit_session(secret)
    # Same events but no secret_key supplied — chain_verifies must fail.
    report = build_report(session_id="s1", events=events, framework="test")
    assert not report.compliance_attestation["HIPAA-164.312-e-2"]["satisfied"]


def test_build_report_iec62304_present_flag_drives_rule() -> None:
    """A rule using iec62304_traceability_present should respond to the flag."""
    rule = ComplianceRule(
        id="IEC-CUSTOM-TRACE",
        title="custom",
        predicate="iec62304_traceability_present",
    )
    secret = b"k" * 32
    events, _ = _emit_session(secret)
    # No iec62304 section → fail.
    r1 = evaluate_rules([rule], events, iec62304_present=False)
    assert not r1[0].satisfied
    # With section → pass.
    r2 = evaluate_rules([rule], events, iec62304_present=True)
    assert r2[0].satisfied


def test_load_ruleset_rejects_missing_required_keys(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad\nrules:\n  - title: 'no id or predicate'\n")
    with pytest.raises(ValueError, match="missing required keys"):
        load_ruleset(bad)
