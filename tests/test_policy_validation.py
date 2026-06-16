"""Strict policy-loading validation tests (PolicyError taxonomy, ADR-0008/0012)."""

from __future__ import annotations

import pytest

from clinicsentry.errors import PolicyError
from clinicsentry.policy import load_policy


def test_empty_policy_uses_safe_defaults() -> None:
    cfg = load_policy({})
    assert cfg.on_unregistered_action == "escalate"
    assert cfg.decode_encoded is True
    assert cfg.meddevice.strict_dose_ranges is True


def test_unknown_top_level_key_rejected() -> None:
    """A typo'd block name must not silently disable enforcement."""
    with pytest.raises(PolicyError, match="meddevice_mod"):
        load_policy({"meddevice_mod": {"enabled": True}})


def test_unknown_nested_key_rejected() -> None:
    with pytest.raises(PolicyError, match="use_presidio_typo"):
        load_policy({"phi_firewall": {"use_presidio_typo": True}})


def test_invalid_redaction_mode_raises_policy_error() -> None:
    with pytest.raises(PolicyError, match="phi_firewall.mode"):
        load_policy({"phi_firewall": {"mode": "OBLITERATE"}})


def test_invalid_override_mode_raises_policy_error() -> None:
    with pytest.raises(PolicyError, match="overrides"):
        load_policy({"phi_firewall": {"overrides": {"SSN": "nope"}}})


def test_threshold_out_of_range_rejected() -> None:
    with pytest.raises(PolicyError, match="1.01"):
        load_policy({"escalation": {"thresholds": {"advisory": 80}}})


def test_threshold_unknown_tier_rejected() -> None:
    with pytest.raises(PolicyError, match="tier"):
        load_policy({"escalation": {"thresholds": {"catastrophic": 0.5}}})


def test_threshold_non_numeric_rejected() -> None:
    with pytest.raises(PolicyError, match="number"):
        load_policy({"escalation": {"thresholds": {"advisory": "high"}}})


def test_invalid_on_unregistered_action_rejected() -> None:
    with pytest.raises(PolicyError, match="on_unregistered_action"):
        load_policy({"escalation": {"on_unregistered_action": "allow"}})


def test_dose_range_min_greater_than_max_rejected() -> None:
    with pytest.raises(PolicyError, match="min"):
        load_policy(
            {
                "meddevice_mode": {
                    "enabled": True,
                    "dose_ranges": [{"parameter": "basal", "min": 5.0, "max": 1.0}],
                }
            }
        )


def test_dose_range_requires_parameter_name() -> None:
    with pytest.raises(PolicyError, match="parameter"):
        load_policy({"meddevice_mode": {"enabled": True, "dose_ranges": [{"min": 0, "max": 1}]}})


def test_invalid_safety_class_rejected() -> None:
    with pytest.raises(PolicyError, match="software_safety_class"):
        load_policy({"meddevice_mode": {"software_safety_class": "D"}})


def test_negative_retention_rejected() -> None:
    with pytest.raises(PolicyError, match="retention_years"):
        load_policy({"audit": {"retention_years": -1}})


def test_zero_rate_limit_rejected() -> None:
    with pytest.raises(PolicyError, match="rate_limit_per_hour"):
        load_policy({"meddevice_mode": {"rate_limit_per_hour": 0}})


def test_non_mapping_policy_rejected() -> None:
    with pytest.raises(PolicyError, match="mapping"):
        load_policy("- just\n- a\n- list\n")


def test_malformed_yaml_string_raises_policy_error() -> None:
    with pytest.raises(PolicyError, match="YAML"):
        load_policy("phi_firewall: {mode: [unclosed")


def test_max_depth_must_be_positive_int() -> None:
    with pytest.raises(PolicyError, match="max_depth"):
        load_policy({"phi_firewall": {"max_depth": 0}})
    with pytest.raises(PolicyError, match="max_depth"):
        load_policy({"phi_firewall": {"max_depth": "deep"}})


def test_valid_full_policy_parses() -> None:
    cfg = load_policy(
        {
            "version": "0.2.0",
            "phi_firewall": {"mode": "PSEUDONYMIZE", "decode_encoded": False, "max_depth": 16},
            "escalation": {
                "thresholds": {"advisory": 0.9},
                "on_unregistered_action": "tier_default",
            },
            "audit": {"backend": "sqlite", "path": "/tmp/a.sqlite"},
            "meddevice_mode": {
                "enabled": True,
                "software_safety_class": "C",
                "strict_dose_ranges": False,
                "dose_ranges": [{"parameter": "basal", "min": 0.0, "max": 5.0, "unit": "U/hr"}],
                "rate_limit_per_hour": 6,
            },
        }
    )
    assert cfg.max_scan_depth == 16
    assert cfg.decode_encoded is False
    assert cfg.on_unregistered_action == "tier_default"
    assert cfg.meddevice.strict_dose_ranges is False
    assert cfg.meddevice.dose_ranges[0].unit == "U/hr"


# ---------------------------------------------------------------------------
# Environment overrides (ADR-0012)
# ---------------------------------------------------------------------------


def test_env_override_simple_key(monkeypatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_AUDIT_BACKEND", "sqlite")
    cfg = load_policy({"audit": {"backend": "memory"}})
    assert cfg.audit.backend == "sqlite"


def test_env_override_section_with_underscore(monkeypatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_PHI_FIREWALL_MODE", "PSEUDONYMIZE")
    cfg = load_policy({})
    assert cfg.phi_mode.value == "PSEUDONYMIZE"


def test_env_override_nested_key_double_underscore(monkeypatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_ESCALATION_THRESHOLDS__ADVISORY", "0.9")
    cfg = load_policy({})
    from clinicsentry.types import ClinicalRiskTier

    assert cfg.escalation_thresholds[ClinicalRiskTier.ADVISORY] == 0.9


def test_env_override_parses_yaml_scalars(monkeypatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_MEDDEVICE_MODE_ENABLED", "true")
    cfg = load_policy({})
    assert cfg.meddevice.enabled is True


def test_env_override_is_validated(monkeypatch) -> None:
    """A bad env value must fail load, not silently misconfigure."""
    monkeypatch.setenv("CLINICSENTRY_PHI_FIREWALL_MODE", "OBLITERATE")
    with pytest.raises(PolicyError, match="phi_firewall.mode"):
        load_policy({})


def test_env_override_opt_out(monkeypatch) -> None:
    monkeypatch.setenv("CLINICSENTRY_AUDIT_BACKEND", "sqlite")
    cfg = load_policy({}, apply_env=False)
    assert cfg.audit.backend == "memory"


def test_unrelated_clinicsentry_env_vars_ignored(monkeypatch) -> None:
    """Secret-bearing vars (HMAC key, DSN) are not policy fields."""
    monkeypatch.setenv("CLINICSENTRY_HMAC_KEY", "deadbeef")
    monkeypatch.setenv("CLINICSENTRY_DSN", "postgres://x")
    cfg = load_policy({})
    assert cfg.audit.backend == "memory"
