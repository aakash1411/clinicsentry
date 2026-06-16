"""Tests for the HTML/PDF report renderer."""

from __future__ import annotations

from clinicsentry.audit.pdf_report import render_report_html
from clinicsentry.audit.report import build_report
from clinicsentry.types import AuditEvent, AuditEventType


def test_render_report_html_includes_session_and_attestation_sections() -> None:
    events = [
        AuditEvent(
            event_type=AuditEventType.SESSION_START,
            session_id="s1",
            sequence_number=1,
        ),
        AuditEvent(
            event_type=AuditEventType.SESSION_END,
            session_id="s1",
            sequence_number=2,
        ),
    ]
    report = build_report(
        session_id="s1",
        events=events,
        framework="test",
        policy_version="v1",
        phi_tags={},
        propagation_edges={},
    )
    html = render_report_html(report)
    assert "ClinicSentry Regulatory Report" in html
    assert "Session Summary" in html
    assert "Compliance Attestation" in html
    assert "s1" in html


def test_render_report_html_renders_pass_fail_classes_for_attestations() -> None:
    events = [
        AuditEvent(event_type=AuditEventType.SESSION_START, session_id="s2", sequence_number=1)
    ]
    report = build_report(
        session_id="s2",
        events=events,
        framework="test",
        policy_version="v1",
        phi_tags={},
        propagation_edges={},
    )
    html = render_report_html(report)
    assert "attest-pass" in html or "attest-fail" in html
