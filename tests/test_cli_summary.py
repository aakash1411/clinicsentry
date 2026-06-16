"""Tests for the CLI compliance summary renderer."""

from __future__ import annotations

from clinicsentry.cli import _render_compliance_summary


def test_summary_renders_overall_counts() -> None:
    """The header line must reflect the ``_summary`` counters."""
    attestation = {
        "_summary": {
            "rules_evaluated": 14,
            "rules_satisfied": 10,
            "rules_failed_blocker": 4,
        },
        "HIPAA-1": {
            "satisfied": True,
            "severity": "blocker",
            "framework": "hipaa",
            "reason": "ok",
        },
    }
    out = _render_compliance_summary(attestation)
    assert "10/14 rules satisfied" in out
    assert "4 blocker failure" in out


def test_summary_groups_by_framework() -> None:
    """Each framework should get a per-framework satisfied/total row."""
    attestation = {
        "HIPAA-1": {"satisfied": True, "severity": "blocker", "framework": "hipaa", "reason": ""},
        "HIPAA-2": {"satisfied": False, "severity": "blocker", "framework": "hipaa", "reason": "x"},
        "FDA-1": {"satisfied": True, "severity": "warning", "framework": "fda_tplc", "reason": ""},
    }
    out = _render_compliance_summary(attestation)
    assert "hipaa: 1/2" in out
    assert "fda_tplc: 1/1" in out


def test_summary_lists_only_blocker_failures() -> None:
    """Failures with severity != blocker should not appear in the failures block."""
    attestation = {
        "BLOCK-FAIL": {
            "satisfied": False,
            "severity": "blocker",
            "framework": "hipaa",
            "reason": "missing agent_id",
        },
        "WARN-FAIL": {
            "satisfied": False,
            "severity": "warning",
            "framework": "hipaa",
            "reason": "soft",
        },
    }
    out = _render_compliance_summary(attestation)
    assert "BLOCK-FAIL" in out
    assert "missing agent_id" in out
    assert "WARN-FAIL" not in out


def test_summary_skips_underscore_keys() -> None:
    """Bookkeeping keys must never appear as if they were rules."""
    attestation = {
        "_summary": {"rules_evaluated": 1, "rules_satisfied": 1, "rules_failed_blocker": 0},
        "_internal": {"anything": True},
        "RULE-1": {"satisfied": True, "severity": "blocker", "framework": "hipaa", "reason": ""},
    }
    out = _render_compliance_summary(attestation)
    assert "_internal" not in out
    assert "RULE-1" not in out  # passing rules aren't listed individually
    assert "hipaa: 1/1" in out


def test_summary_handles_empty_attestation() -> None:
    """An empty attestation must not raise."""
    assert _render_compliance_summary({}) == ""
