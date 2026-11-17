"""Regression tests: attestations must reflect controls that actually ran.

Covers PHI evidence events, risk-tier stamping and enforcement on tool calls,
bound single-use clinician approvals, human-review recording, and
not-applicable rule outcomes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

import pytest

from clinicsentry import ClinicalRiskTier, ClinicSentry, RedactionMode
from clinicsentry.adapters.mcp_proxy import BLOCKED_ERROR_CODE, MCPProxyAdapter
from clinicsentry.compliance import ComplianceRule, evaluate_rules
from clinicsentry.errors import (
    AuthorizationRequired,
    ClinicSentryError,
    DoseOutOfRange,
    EscalationRaised,
)
from clinicsentry.meddevice import (
    ClinicianAuthError,
    ClinicianAuthValidator,
    arguments_hash,
    sign_interventional_authorization,
)
from clinicsentry.meddevice.clinician_auth import AuthorizationToken
from clinicsentry.meddevice.mode import DoseRange, EmergencyStop, SoftwareSafetyClass
from clinicsentry.types import AuditEvent, AuditEventType

KEY = b"k" * 32
PHI_NOTE = {"note": "Patient Jane Doe (MRN 12345678), SSN 123-45-6789"}


def _types(guard: ClinicSentry) -> list[AuditEventType]:
    return [e.event_type for e in guard.audit_backend.read_session(guard.session_id)]


def _rule(guard: ClinicSentry, rule_id: str) -> dict[str, Any]:
    report = guard.end_session()
    return report.compliance_attestation[rule_id]  # type: ignore[no-any-return]


def _interventional_guard(**meddevice: Any) -> ClinicSentry:
    guard = ClinicSentry(framework="test")
    guard.meddevice.config.authorized_clinician_keys = {"dr": KEY}
    for k, v in meddevice.items():
        setattr(guard.meddevice.config, k, v)

    @guard.register_action(tier=ClinicalRiskTier.INTERVENTIONAL, description="adjust insulin")
    def adjust_insulin(payload: dict[str, Any]) -> None:
        return None

    return guard


def _approve(guard: ClinicSentry, nonce: str = "n1", arguments: dict[str, Any] | None = None):
    issued = int(time.time())
    sig = sign_interventional_authorization(
        KEY,
        action_name="adjust_insulin",
        clinician_id="dr",
        session_id=guard.session_id,
        nonce=nonce,
        issued_at=issued,
        args_hash=arguments_hash(arguments) if arguments is not None else "",
    )
    guard.approve_interventional(
        "adjust_insulin",
        clinician_id="dr",
        signature=sig,
        nonce=nonce,
        issued_at=issued,
        arguments=arguments,
    )


# --- PHI evidence -----------------------------------------------------------


def test_scan_emits_phi_evidence_and_hipaa_rule_is_exercised() -> None:
    guard = ClinicSentry(framework="test")
    guard.firewall.scan(PHI_NOTE, origin_agent="intake")
    types = _types(guard)
    assert AuditEventType.PHI_DETECTED in types
    assert AuditEventType.PHI_REDACTED in types
    result = _rule(guard, "HIPAA-164.502-b")
    assert result["satisfied"]
    assert result["applicable"]
    assert result["evidence"]
    phi = guard.last_report.phi_handling_summary  # type: ignore[union-attr]
    assert phi["phi_detected_count"] >= 2
    assert phi["phi_redacted_count"] == phi["phi_detected_count"]
    assert phi["phi_unredacted_count"] == 0
    assert "minimum_necessary_enforced" not in phi


def test_phi_events_never_contain_values() -> None:
    guard = ClinicSentry(framework="test")
    guard.firewall.scan(PHI_NOTE, origin_agent="intake")
    for ev in guard.audit_backend.read_session(guard.session_id):
        if ev.event_type in {AuditEventType.PHI_DETECTED, AuditEventType.PHI_REDACTED}:
            blob = json.dumps(ev.to_dict())
            assert "123-45-6789" not in blob
            assert "12345678" not in blob
            assert "Jane" not in blob


def test_audit_only_mode_fails_minimum_necessary_rule() -> None:
    guard = ClinicSentry(framework="test")
    guard.firewall.mode = RedactionMode.AUDIT_ONLY
    guard.firewall.scan(PHI_NOTE, origin_agent="intake")
    assert AuditEventType.PHI_REDACTED not in _types(guard)
    result = _rule(guard, "HIPAA-164.502-b")
    assert not result["satisfied"]
    assert guard.last_report.phi_handling_summary["phi_unredacted_count"] > 0  # type: ignore[union-attr]


def test_tags_without_phi_evidence_is_an_instrumentation_failure() -> None:
    rule = ComplianceRule(id="t", title="t", predicate="phi_redacted_when_detected")
    ev = AuditEvent(
        event_type=AuditEventType.TOOL_CALL,
        session_id="s",
        sequence_number=1,
        phi_tags_detected=["tag-1"],
    )
    (res,) = evaluate_rules([rule], [ev])
    assert not res.satisfied
    assert res.applicable


def test_partial_redaction_fails() -> None:
    rule = ComplianceRule(id="t", title="t", predicate="phi_redacted_when_detected")
    events = [
        AuditEvent(
            event_type=AuditEventType.PHI_DETECTED,
            session_id="s",
            sequence_number=1,
            redacted_input={"count": 3},
        ),
        AuditEvent(
            event_type=AuditEventType.PHI_REDACTED,
            session_id="s",
            sequence_number=2,
            redacted_input={"count": 2},
        ),
    ]
    (res,) = evaluate_rules([rule], events)
    assert not res.satisfied


def test_rules_without_preconditions_are_not_applicable() -> None:
    guard = ClinicSentry(framework="test")
    report = guard.end_session()
    for rule_id in ("HIPAA-164.502-b", "IEC-62304-9", "EU-AI-ACT-Art-14-1"):
        entry = report.compliance_attestation[rule_id]
        assert entry["satisfied"]
        assert not entry["applicable"]
    assert report.compliance_attestation["_summary"]["rules_not_applicable"] >= 3


# --- Interventional enforcement ---------------------------------------------


def test_interventional_tool_call_without_approval_is_blocked() -> None:
    guard = _interventional_guard()
    with pytest.raises(EscalationRaised):
        asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 2}))
    types = _types(guard)
    assert AuditEventType.ESCALATION_TRIGGERED in types
    assert AuditEventType.TOOL_CALL not in types


def test_approved_interventional_call_is_stamped_and_attested() -> None:
    guard = _interventional_guard()
    _approve(guard)
    asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 2}))
    events = list(guard.audit_backend.read_session(guard.session_id))
    call = next(e for e in events if e.event_type == AuditEventType.TOOL_CALL)
    assert call.risk_tier == ClinicalRiskTier.INTERVENTIONAL
    assert any(
        e.event_type == AuditEventType.HUMAN_REVIEW_RESPONSE
        and e.redacted_input.get("mechanism") == "hmac"
        for e in events
    )
    result = _rule(guard, "IEC-62304-9")
    assert result["satisfied"]
    assert result["applicable"]
    report = guard.last_report
    assert report.clinical_decision_summary["actions_taken"][0]["tier"] == "interventional"  # type: ignore[union-attr]


def test_approval_is_single_use() -> None:
    guard = _interventional_guard()
    _approve(guard)
    asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 2}))
    with pytest.raises(EscalationRaised):
        asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 2}))


def test_replayed_approval_signature_is_rejected() -> None:
    guard = _interventional_guard()
    issued = int(time.time())
    sig = sign_interventional_authorization(
        KEY,
        action_name="adjust_insulin",
        clinician_id="dr",
        session_id=guard.session_id,
        nonce="n1",
        issued_at=issued,
    )
    kwargs = {"clinician_id": "dr", "signature": sig, "nonce": "n1", "issued_at": issued}
    guard.approve_interventional("adjust_insulin", **kwargs)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationRequired):
        guard.approve_interventional("adjust_insulin", **kwargs)  # type: ignore[arg-type]
    assert AuditEventType.POLICY_VIOLATION in _types(guard)


def test_approval_signed_for_another_session_is_rejected() -> None:
    guard = _interventional_guard()
    issued = int(time.time())
    sig = sign_interventional_authorization(
        KEY,
        action_name="adjust_insulin",
        clinician_id="dr",
        session_id="other-session",
        nonce="n1",
        issued_at=issued,
    )
    with pytest.raises(AuthorizationRequired):
        guard.approve_interventional(
            "adjust_insulin", clinician_id="dr", signature=sig, nonce="n1", issued_at=issued
        )


def test_stale_and_future_dated_approvals_are_rejected() -> None:
    guard = _interventional_guard()
    for offset in (-10_000, 10_000):
        issued = int(time.time()) + offset
        sig = sign_interventional_authorization(
            KEY,
            action_name="adjust_insulin",
            clinician_id="dr",
            session_id=guard.session_id,
            nonce=f"n{offset}",
            issued_at=issued,
        )
        with pytest.raises(AuthorizationRequired):
            guard.approve_interventional(
                "adjust_insulin",
                clinician_id="dr",
                signature=sig,
                nonce=f"n{offset}",
                issued_at=issued,
            )


def test_argument_bound_approval_rejects_different_arguments() -> None:
    guard = _interventional_guard()
    _approve(guard, arguments={"units": 2})
    with pytest.raises(EscalationRaised):
        asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 20}))
    _approve(guard, nonce="n2", arguments={"units": 2})
    asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"units": 2}))


def test_approval_for_non_interventional_action_is_rejected() -> None:
    guard = ClinicSentry(framework="test")
    with pytest.raises(ValueError):
        guard.approve_interventional(
            "unknown", clinician_id="dr", signature="x", nonce="n", issued_at=0
        )


def test_one_escalation_cannot_cover_two_calls() -> None:
    rule = ComplianceRule(id="t", title="t", predicate="escalation_triggered_for_interventional")

    def ev(seq: int, et: AuditEventType, agent: str) -> AuditEvent:
        return AuditEvent(
            event_type=et,
            session_id="s",
            sequence_number=seq,
            agent_id=agent,
            risk_tier=ClinicalRiskTier.INTERVENTIONAL,
        )

    events = [
        ev(1, AuditEventType.ESCALATION_TRIGGERED, "a"),
        ev(2, AuditEventType.TOOL_CALL, "a"),
        ev(3, AuditEventType.TOOL_CALL, "a"),
    ]
    assert not evaluate_rules([rule], events)[0].satisfied
    other = [ev(1, AuditEventType.ESCALATION_TRIGGERED, "b"), ev(2, AuditEventType.TOOL_CALL, "a")]
    assert not evaluate_rules([rule], other)[0].satisfied


# --- MedDevice runtime checks -----------------------------------------------


def test_dose_out_of_range_blocks_tool_call() -> None:
    guard = ClinicSentry(framework="test")
    guard.meddevice.config.enabled = True
    guard.meddevice.config.software_safety_class = SoftwareSafetyClass.B
    guard.meddevice.config.dose_ranges = [DoseRange("units", 0.0, 5.0)]
    asyncio.run(guard.adapter.intercept_tool_call("suggest_dose", {"units": 3}))
    with pytest.raises(DoseOutOfRange):
        asyncio.run(guard.adapter.intercept_tool_call("suggest_dose", {"units": 50}))
    with pytest.raises(DoseOutOfRange):
        asyncio.run(guard.adapter.intercept_tool_call("suggest_dose", {"units": "50"}))
    violations = [
        e
        for e in guard.audit_backend.read_session(guard.session_id)
        if e.event_type == AuditEventType.POLICY_VIOLATION
    ]
    assert len(violations) == 2
    assert violations[0].redacted_input == {"reason": "dose_out_of_range", "parameter": "units"}


def test_undeclared_numeric_parameter_fails_closed_for_interventional() -> None:
    guard = _interventional_guard(
        enabled=True,
        software_safety_class=SoftwareSafetyClass.C,
        dose_ranges=[DoseRange("units", 0.0, 5.0)],
    )
    _approve(guard)
    with pytest.raises(DoseOutOfRange):
        asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {"unts": 2}))


def test_rate_limit_blocks_interventional_calls() -> None:
    guard = _interventional_guard(
        enabled=True, software_safety_class=SoftwareSafetyClass.C, rate_limit_per_hour=1
    )
    _approve(guard, nonce="a")
    asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {}))
    _approve(guard, nonce="b")
    with pytest.raises(DoseOutOfRange):
        asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", {}))


def test_emergency_stop_is_a_clinicsentry_error() -> None:
    guard = ClinicSentry(framework="test")
    guard.meddevice.emergency_stop()
    with pytest.raises(ClinicSentryError):
        asyncio.run(guard.adapter.intercept_tool_call("anything", {}))
    assert issubclass(EmergencyStop, RuntimeError)


# --- MCP proxy --------------------------------------------------------------


def test_mcp_proxy_returns_jsonrpc_error_for_blocked_call() -> None:
    guard = _interventional_guard()
    proxy = MCPProxyAdapter(guard)
    called: list[str] = []

    async def upstream(text: str) -> str:
        called.append(text)
        return json.dumps({"jsonrpc": "2.0", "id": 7, "result": {}})

    req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "adjust_insulin", "arguments": {"units": 2}},
    }
    resp = json.loads(asyncio.run(proxy.handle_request(json.dumps(req), upstream)))
    assert resp["error"]["code"] == BLOCKED_ERROR_CODE
    assert resp["id"] == 7
    assert called == []

    _approve(guard, nonce="m1")
    asyncio.run(proxy.handle_request(json.dumps(req), upstream))
    assert len(called) == 1
    mcp = [
        e
        for e in guard.audit_backend.read_session(guard.session_id)
        if e.event_type == AuditEventType.MCP_TOOL_CALL
    ]
    assert mcp[0].risk_tier == ClinicalRiskTier.INTERVENTIONAL


# --- Human review -----------------------------------------------------------


def _advisory_guard() -> ClinicSentry:
    guard = ClinicSentry(framework="test")

    @guard.register_action(tier=ClinicalRiskTier.ADVISORY, required_fields={"note"})
    def summarize(payload: dict[str, Any]) -> None:
        return None

    @guard.register_action(tier=ClinicalRiskTier.ADVISORY)
    def other(payload: dict[str, Any]) -> None:
        return None

    decision = guard.evaluate_action("summarize", output_text="x", provided_fields=set())
    assert decision.action != "proceed"
    return guard


def test_human_review_closes_advisory_escalation() -> None:
    guard = _advisory_guard()
    guard.record_human_review("summarize", reviewer_id="rn-1", decision="approved")
    result = _rule(guard, "EU-AI-ACT-Art-14-1")
    assert result["satisfied"]
    assert result["applicable"]


def test_review_of_a_different_action_does_not_count() -> None:
    guard = _advisory_guard()
    guard.record_human_review("other", reviewer_id="rn-1", decision="approved")
    assert not _rule(guard, "EU-AI-ACT-Art-14-1")["satisfied"]


def test_human_review_validates_decision_and_redacts_rationale() -> None:
    guard = _advisory_guard()
    with pytest.raises(ValueError):
        guard.record_human_review("summarize", reviewer_id="rn-1", decision="maybe")
    ev = guard.record_human_review(
        "summarize", reviewer_id="rn-1", decision="modified", rationale="SSN 123-45-6789"
    )
    assert "123-45-6789" not in json.dumps(ev.to_dict())


# --- Ed25519 token path -----------------------------------------------------


def _ed25519() -> tuple[Any, bytes]:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub


def _token(priv: Any, **overrides: Any) -> tuple[str, bytes]:
    fields: dict[str, Any] = {
        "clinician_id": "dr",
        "session_id": "s1",
        "action_name": "adjust_insulin",
        "issued_at": int(time.time()),
        "nonce": "t1",
    }
    fields.update(overrides)
    tok = AuthorizationToken(**fields)
    return base64.b64encode(tok.encode()).decode(), priv.sign(tok.encode())


def test_token_binding_freshness_and_replay() -> None:
    priv, pub = _ed25519()
    validator = ClinicianAuthValidator(public_keys={"dr": pub})
    blob, sig = _token(priv, issued_at=int(time.time()) + 3600)
    with pytest.raises(ClinicianAuthError, match="future"):
        validator.validate(blob, sig)
    blob, sig = _token(priv, nonce="t2")
    with pytest.raises(ClinicianAuthError, match="session"):
        validator.validate(blob, sig, expected_session_id="other")
    with pytest.raises(ClinicianAuthError, match="action"):
        validator.validate(blob, sig, expected_action="other")
    with pytest.raises(ClinicianAuthError, match="arguments"):
        validator.validate(blob, sig, expected_args_hash="abc")
    assert validator.validate(blob, sig, expected_session_id="s1").nonce == "t2"
    with pytest.raises(ClinicianAuthError, match="replay"):
        validator.validate(blob, sig)


def test_guard_token_approval_unlocks_one_call() -> None:
    priv, pub = _ed25519()
    guard = _interventional_guard()
    validator = ClinicianAuthValidator(public_keys={"dr": pub})
    args = {"units": 2}
    blob, sig = _token(priv, session_id=guard.session_id, args_hash=arguments_hash(args))
    guard.approve_interventional_token(blob, sig, validator, arguments=args)
    asyncio.run(guard.adapter.intercept_tool_call("adjust_insulin", args))
    other_blob, other_sig = _token(priv, session_id="elsewhere", nonce="t9")
    with pytest.raises(AuthorizationRequired):
        guard.approve_interventional_token(other_blob, other_sig, validator)
