"""Integration tests covering the top-level :class:`ClinicSentry` facade."""

from __future__ import annotations

from pathlib import Path

import pytest

from clinicsentry import ClinicalRiskTier, ClinicSentry
from clinicsentry.policy import load_policy

POLICY_PATH = Path(__file__).resolve().parent.parent / "examples" / "policy.yaml"


def test_end_to_end_session_yields_valid_report() -> None:
    guard = ClinicSentry(policy=load_policy(POLICY_PATH), framework="test")

    @guard.register_action(
        tier=ClinicalRiskTier.INFORMATIONAL,
        description="Summarize note",
        required_fields={"note"},
    )
    def summarize(payload: dict) -> str:
        return "ok"

    scan = guard.firewall.scan(
        {"note": "Patient John Doe MRN: 12345678 SSN: 123-45-6789"},
        origin_agent="t1",
    )
    assert "123-45-6789" not in str(scan.redacted)

    decision = guard.evaluate_action(
        "summarize",
        output_text="Brief summary",
        reasoning_text="Confidence: 95%",
        provided_fields={"note"},
    )
    assert decision.action == "proceed"

    report = guard.end_session(intended_use="integration test")
    ok, errors = guard.verify_audit_chain()
    assert ok, errors
    assert report.compliance_attestation["HIPAA-164.312-b"]["satisfied"]
    assert report.iec62304_section is not None
    assert report.iec62304_section["software_safety_class"] == "B"


def test_class_b_rejects_interventional_registration_via_guard() -> None:
    guard = ClinicSentry(policy=load_policy(POLICY_PATH), framework="test")
    with pytest.raises(ValueError):

        @guard.register_action(tier=ClinicalRiskTier.INTERVENTIONAL, description="pump")
        def pump_set() -> None: ...


# ---------------------------------------------------------------------------
# Lifecycle: context manager + idempotent end_session
# ---------------------------------------------------------------------------


def test_context_manager_ends_session_automatically() -> None:
    with ClinicSentry(framework="test") as guard:
        guard.firewall.scan("SSN: 123-45-6789", origin_agent="t")
    events = list(guard.audit_backend.read_session(guard.session_id))
    assert events[-1].event_type.value == "session_end"
    assert guard.last_report is not None
    ok, errors = guard.verify_audit_chain()
    assert ok, errors


def test_context_manager_audits_exception_then_ends_session() -> None:
    guard_ref = ClinicSentry(framework="test")
    with pytest.raises(RuntimeError, match="boom"), guard_ref:
        raise RuntimeError("boom")
    events = list(guard_ref.audit_backend.read_session(guard_ref.session_id))
    types = [e.event_type.value for e in events]
    assert "module_error" in types
    assert types[-1] == "session_end"
    # The audited error must carry the exception class only, never the message.
    err = next(e for e in events if e.event_type.value == "module_error")
    assert err.redacted_input == {"exception_type": "RuntimeError"}


def test_end_session_is_idempotent() -> None:
    guard = ClinicSentry(framework="test")
    guard.end_session()
    guard.end_session()
    events = list(guard.audit_backend.read_session(guard.session_id))
    assert [e.event_type.value for e in events].count("session_end") == 1
    ok, errors = guard.verify_audit_chain()
    assert ok, errors


def test_unregistered_action_escalates_through_guard() -> None:
    guard = ClinicSentry(framework="test")
    decision = guard.evaluate_action("not_registered", reasoning_text="Confidence: 99%")
    assert decision.action == "escalate"


def test_ephemeral_key_with_persistent_backend_warns(tmp_path) -> None:
    import warnings as _warnings

    from clinicsentry.audit.backend import SqliteAuditBackend

    backend = SqliteAuditBackend(str(tmp_path / "a.sqlite"))
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        ClinicSentry(framework="test", audit_backend=backend)
    assert any("ephemeral HMAC key" in str(w.message) for w in caught)


def test_explicit_key_with_persistent_backend_does_not_warn(tmp_path) -> None:
    import os as _os
    import warnings as _warnings

    from clinicsentry.audit.backend import SqliteAuditBackend

    backend = SqliteAuditBackend(str(tmp_path / "b.sqlite"))
    with _warnings.catch_warnings(record=True) as caught:
        _warnings.simplefilter("always")
        ClinicSentry(framework="test", audit_backend=backend, secret_key=_os.urandom(32))
    assert not [w for w in caught if "ephemeral HMAC key" in str(w.message)]
