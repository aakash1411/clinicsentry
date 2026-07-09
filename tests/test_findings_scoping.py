"""B1 + B12: structured findings with field paths, and field-path scoping."""

from __future__ import annotations

from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.firewall import PHIFirewall


def test_findings_expose_type_span_confidence_path_action() -> None:
    fw = PHIFirewall()
    scan = fw.scan({"note": "SSN 123-45-6789"})
    assert scan.has_phi
    assert scan.by_type == {"SSN": 1}
    f = scan.findings[0]
    assert (f.phi_type, f.field_path, f.action) == ("SSN", "note", "REDACT")
    assert f.replacement == "[REDACTED:SSN]"
    assert "SSN 123-45-6789"[f.start : f.end] == "123-45-6789"
    assert f.confidence == 0.99


def test_field_paths_through_nested_containers() -> None:
    fw = PHIFirewall()
    scan = fw.scan({"messages": [{"content": "jane@example.com"}, {"content": "clean"}]})
    paths = [f.field_path for f in scan.findings]
    assert paths == ["messages.0.content"]


def test_no_phi_result_reports_false() -> None:
    scan = PHIFirewall().scan({"note": "all clear today"})
    assert not scan.has_phi
    assert scan.by_type == {}


def test_findings_serialize() -> None:
    scan = PHIFirewall().scan("SSN 123-45-6789")
    d = scan.findings[0].to_dict()
    assert d["phi_type"] == "SSN"
    assert d["action"] == "REDACT"


# --- B12: field-path scoping ---------------------------------------------------


def test_skip_fields_leave_subtree_unscanned() -> None:
    fw = PHIFirewall(skip_fields=["public_kb_snippet", "citation.*"])
    payload = {
        "public_kb_snippet": "hotline 555-123-4567",
        "citation": {"url": "https://example.com/kb"},
        "user": "reach me at 415-555-1234",
    }
    scan = fw.scan(payload)
    assert scan.redacted["public_kb_snippet"] == "hotline 555-123-4567"
    assert scan.redacted["citation"]["url"] == "https://example.com/kb"
    assert "415-555-1234" not in str(scan.redacted["user"])


def test_always_redact_fields_redact_wholesale() -> None:
    fw = PHIFirewall(always_redact_fields=["raw_user_transcript"])
    scan = fw.scan({"raw_user_transcript": "totally innocuous", "note": "fine"})
    assert scan.redacted["raw_user_transcript"] == "[REDACTED:FIELD]"
    assert scan.redacted["note"] == "fine"
    assert any(f.action == "ALWAYS_REDACT" for f in scan.findings)


def test_always_redact_wins_over_skip() -> None:
    fw = PHIFirewall(skip_fields=["x"], always_redact_fields=["x"])
    scan = fw.scan({"x": "anything"})
    assert scan.redacted["x"] == "[REDACTED:FIELD]"


def test_scoping_via_policy() -> None:
    guard = ClinicSentry(
        policy={
            "phi_firewall": {
                "skip_fields": ["public_kb_snippet"],
                "always_redact_fields": ["raw_user_transcript"],
            }
        },
        framework="test",
    )
    scan = guard.firewall.scan(
        {"public_kb_snippet": "call 555-123-4567", "raw_user_transcript": "hello"}
    )
    assert scan.redacted["public_kb_snippet"] == "call 555-123-4567"
    assert scan.redacted["raw_user_transcript"] == "[REDACTED:FIELD]"
