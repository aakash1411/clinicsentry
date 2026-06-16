"""PHI Firewall tests covering string, FHIR, HL7, and redaction paths."""

from __future__ import annotations

from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.phi.minimum_necessary import minimum_necessary
from clinicsentry.phi.redaction import RedactionMode


def test_regex_redacts_common_identifiers() -> None:
    fw = PHIFirewall()
    text = "Call 415-555-1212 or email a@b.com. SSN 123-45-6789. NPI 1234567890."
    result = fw.scan(text)
    assert "415-555-1212" not in result.redacted
    assert "a@b.com" not in result.redacted
    assert "123-45-6789" not in result.redacted
    assert "1234567890" not in result.redacted
    types = {t.phi_type for t in result.tags}
    assert {"PHONE", "EMAIL", "SSN", "NPI"} <= types


def test_generalize_date_to_year() -> None:
    fw = PHIFirewall(
        mode=RedactionMode.REDACT,
        overrides={"DATE": RedactionMode.GENERALIZE},
    )
    result = fw.scan("Visit on 2025-04-12 for follow-up.")
    assert "2025" in result.redacted
    assert "04-12" not in result.redacted


def test_pseudonymize_is_session_stable() -> None:
    fw = PHIFirewall(mode=RedactionMode.PSEUDONYMIZE, session_salt="s1")
    a = fw.scan("Email me at user@example.com").redacted
    b = fw.scan("Email me at user@example.com").redacted
    assert a == b


def test_fhir_patient_resource_redaction() -> None:
    fw = PHIFirewall()
    res = {
        "resourceType": "Patient",
        "id": "pt1",
        "name": [{"family": "Doe", "given": ["John"]}],
        "birthDate": "1980-01-15",
        "telecom": [{"system": "phone", "value": "415-555-1212"}],
    }
    result = fw.scan(res)
    assert result.redacted["name"] == "[REDACTED:name]"
    assert result.redacted["birthDate"] == "[REDACTED:birthDate]"
    types = {t.phi_type for t in result.tags}
    assert any(t.startswith("FHIR_") for t in types)


def test_hl7_pid_segment_detected() -> None:
    fw = PHIFirewall()
    msg = (
        "MSH|^~\\&|SEND|FAC|RECV|FAC|202504121200||ADT^A01|MSGID1|P|2.5\r"
        "PID|1||MR12345^^^FAC^MR||DOE^JOHN||19800115|M|||123 MAIN ST^^SF^CA^94110||"
        "(415)555-1212"
    )
    result = fw.scan(msg)
    assert "MR12345" not in result.redacted
    assert "DOE^JOHN" not in result.redacted


def test_minimum_necessary_strips_other_fields() -> None:
    @minimum_necessary(["patient.mrn"], purpose="test")
    def tool(payload: dict) -> dict:
        return payload

    out = tool({"patient": {"mrn": "M1", "name": "X"}, "other": 1})
    assert out == {"patient": {"mrn": "M1"}}


def test_propagation_graph_records_edges() -> None:
    fw = PHIFirewall()
    res = fw.scan("Call 415-555-1212", origin_agent="A")
    tag = res.tags[0]
    fw.propagation.propagate(tag.tag_id, "A", "B")
    fw.propagation.propagate(tag.tag_id, "B", "C")
    assert fw.propagation.edges[tag.tag_id] == [("A", "B"), ("B", "C")]
    assert fw.propagation.tags[tag.tag_id].propagation_path[-1] == "C"


# ---------------------------------------------------------------------------
# Container / payload-shape edge cases
# ---------------------------------------------------------------------------


def test_scan_tuple_preserves_shape_and_redacts() -> None:
    fw = PHIFirewall()
    result = fw.scan(("SSN: 123-45-6789", "clean"), origin_agent="t")
    assert isinstance(result.redacted, tuple)
    assert "123-45-6789" not in result.redacted[0]
    assert result.redacted[1] == "clean"


def test_scan_set_redacts_members() -> None:
    fw = PHIFirewall()
    result = fw.scan({"jane@example.com", "clean"}, origin_agent="t")
    assert isinstance(result.redacted, set)
    assert "jane@example.com" not in result.redacted
    assert "clean" in result.redacted


def test_scan_dict_keys_are_scanned() -> None:
    fw = PHIFirewall()
    result = fw.scan({"jane@example.com": "value"}, origin_agent="t")
    assert "jane@example.com" not in result.redacted
    assert any(t.phi_type == "EMAIL" for t in result.tags)


def test_scan_utf8_bytes_redacted() -> None:
    fw = PHIFirewall()
    result = fw.scan(b"SSN: 123-45-6789", origin_agent="t")
    assert isinstance(result.redacted, bytes)
    assert b"123-45-6789" not in result.redacted


def test_scan_opaque_binary_passes_through() -> None:
    fw = PHIFirewall()
    blob = bytes([0xFF, 0xFE, 0x00, 0x01])
    result = fw.scan(blob, origin_agent="t")
    assert result.redacted == blob
    assert not result.tags


def test_scan_depth_bomb_fails_closed() -> None:
    fw = PHIFirewall(max_depth=8)
    payload: object = "SSN: 123-45-6789"
    for _ in range(50):
        payload = [payload]
    result = fw.scan(payload, origin_agent="t")
    assert "123-45-6789" not in str(result.redacted)
    assert any(t.phi_type == "SCAN_DEPTH_EXCEEDED" for t in result.tags)


def test_scan_scalars_pass_through() -> None:
    fw = PHIFirewall()
    for scalar in (None, True, 42, 3.14):
        assert fw.scan(scalar, origin_agent="t").redacted == scalar


def test_overlapping_hits_redact_span_union() -> None:
    """An overlap conflict must never leave a fragment of either hit visible."""
    from clinicsentry.phi.detectors import Hit, _dedupe_overlaps

    a = Hit(phi_type="URL", start=0, end=30, value="x" * 30, confidence=0.95)
    b = Hit(phi_type="EMAIL", start=10, end=35, value="y" * 25, confidence=0.99)
    merged = _dedupe_overlaps([a, b])
    assert len(merged) == 1
    assert merged[0].start == 0
    assert merged[0].end == 35
    assert merged[0].phi_type == "EMAIL"
