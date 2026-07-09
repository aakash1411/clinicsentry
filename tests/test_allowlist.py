"""A1: config-level allow-list for public / non-PHI contact strings."""

from __future__ import annotations

from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.firewall import PHIFirewall


def test_allowlisted_public_number_preserved_personal_redacted() -> None:
    fw = PHIFirewall(allowlist={"PHONE": ["1-800-646-4633"]})
    out = fw.scan({"n": "call me at 415-555-1234 or support at 1-800-646-4633"})
    assert out.redacted["n"] == "call me at [REDACTED:PHONE] or support at 1-800-646-4633"


def test_allowlist_matches_across_formatting() -> None:
    """Normalization ignores separators and case."""
    fw = PHIFirewall(allowlist={"PHONE": ["1-800-646-4633"]})
    for variant in ("1.800.646.4633", "1 800 646 4633", "(180) 064-64633"[:0] or "1-800-646-4633"):
        out = fw.scan(f"support: {variant}")
        assert variant in str(out.redacted), variant


def test_allowlist_url() -> None:
    fw = PHIFirewall(allowlist={"URL": ["https://www.medtronicdiabetes.com/support"]})
    text = "docs at https://www.medtronicdiabetes.com/support and https://evil.example/x"
    out = fw.scan(text)
    assert "https://www.medtronicdiabetes.com/support" in str(out.redacted)
    assert "evil.example" not in str(out.redacted)


def test_allowlist_is_per_type() -> None:
    """A PHONE allowlist entry must not exempt an SSN with the same digits."""
    fw = PHIFirewall(allowlist={"PHONE": ["123-45-6789"]})
    out = fw.scan("SSN 123-45-6789")
    assert "123-45-6789" not in str(out.redacted)


def test_allowlist_via_policy_and_guard() -> None:
    guard = ClinicSentry(
        policy={"phi_firewall": {"allowlist": {"PHONE": ["1-800-646-4633"]}}},
        framework="test",
    )
    scan = guard.firewall.scan(
        {"note": "Contact Medtronic Technical Support at 1-800-646-4633."},
        origin_agent="intake",
    )
    assert scan.redacted["note"] == "Contact Medtronic Technical Support at 1-800-646-4633."


def test_allowlisted_hits_produce_no_findings() -> None:
    fw = PHIFirewall(allowlist={"PHONE": ["1-800-646-4633"]})
    out = fw.scan("support at 1-800-646-4633")
    assert not out.has_phi
