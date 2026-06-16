"""Mutation-killing tests for :mod:`clinicsentry.meddevice.mode`.

Targets the surviving mutants identified by mutmut: dataclass defaults,
enum values, boundary conditions in dose validation and rate limiting, the
``report_section`` payload structure, registration AND/OR logic, ``reset``
clearing state, and ``validate_dose`` default for unknown parameters.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

import pytest

from clinicsentry.meddevice.mode import (
    DoseRange,
    EmergencyStop,
    MedDeviceConfig,
    MedDeviceMode,
    SoftwareSafetyClass,
)
from clinicsentry.types import ClinicalRiskTier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _Action:
    name: str
    tier: ClinicalRiskTier
    iec62304_requirement: str | None = None
    required_fields: set[str] = field(default_factory=set)


def _enabled_cfg(cls: SoftwareSafetyClass = SoftwareSafetyClass.B, **kw: object) -> MedDeviceConfig:
    base: dict[str, object] = {"enabled": True, "software_safety_class": cls}
    base.update(kw)
    return MedDeviceConfig(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SoftwareSafetyClass enum values
# ---------------------------------------------------------------------------


def test_software_safety_class_values_are_literal_letters() -> None:
    """Kills XX-corruption mutants on enum string values."""
    assert SoftwareSafetyClass.A.value == "A"
    assert SoftwareSafetyClass.B.value == "B"
    assert SoftwareSafetyClass.C.value == "C"


# ---------------------------------------------------------------------------
# DoseRange
# ---------------------------------------------------------------------------


def test_dose_range_default_unit_is_empty_string() -> None:
    """Kills ``unit: str = ""`` → ``= None`` mutant."""
    dr = DoseRange(parameter="rate", min_value=0.0, max_value=5.0)
    assert dr.unit == ""


def test_dose_range_validate_inclusive_at_both_bounds() -> None:
    dr = DoseRange(parameter="rate", min_value=0.0, max_value=5.0)
    assert dr.validate(0.0) is True
    assert dr.validate(5.0) is True
    assert dr.validate(2.5) is True


def test_dose_range_validate_rejects_below_min_and_above_max() -> None:
    dr = DoseRange(parameter="rate", min_value=0.0, max_value=5.0)
    assert dr.validate(-0.001) is False
    assert dr.validate(5.001) is False


# ---------------------------------------------------------------------------
# MedDeviceConfig defaults
# ---------------------------------------------------------------------------


def test_config_defaults() -> None:
    """Kills mutants flipping dataclass defaults (False→True, ""→None, etc.)."""
    cfg = MedDeviceConfig()
    assert cfg.enabled is False
    assert cfg.software_safety_class is SoftwareSafetyClass.A
    assert cfg.device_type == ""
    assert cfg.intended_use == ""
    assert cfg.manufacturer == ""
    assert cfg.udi == ""
    assert cfg.dose_ranges == []
    assert cfg.rate_limit_per_hour is None
    assert cfg.authorized_clinician_keys == {}


def test_config_authorized_keys_default_is_mutable_dict() -> None:
    """Default-factory dict must be unique per instance and mutable."""
    a = MedDeviceConfig()
    b = MedDeviceConfig()
    a.authorized_clinician_keys["doc"] = b"k"
    assert "doc" not in b.authorized_clinician_keys


# ---------------------------------------------------------------------------
# Registration enforcement (Class A/B/C ceilings)
# ---------------------------------------------------------------------------


def test_registration_disabled_short_circuits() -> None:
    """When config.enabled is False, all registrations pass through."""
    mode = MedDeviceMode(config=MedDeviceConfig(enabled=False))
    mode.validate_registration(_Action("x", ClinicalRiskTier.INTERVENTIONAL))


def test_class_a_rejects_advisory_and_interventional() -> None:
    """Kills the ``and`` → ``or`` flip in Class A check and XX-string mutants.

    The error string is asserted in exact form so XX-corruption mutants on the
    error literal also die.
    """
    mode = MedDeviceMode(config=_enabled_cfg(SoftwareSafetyClass.A))
    mode.validate_registration(_Action("info", ClinicalRiskTier.INFORMATIONAL))
    with pytest.raises(ValueError) as ex:
        mode.validate_registration(_Action("adv", ClinicalRiskTier.ADVISORY))
    msg = str(ex.value)
    assert "XX" not in msg
    assert msg == "MedDevice Class A forbids non-informational action 'adv'"
    with pytest.raises(ValueError) as ex2:
        mode.validate_registration(_Action("interv", ClinicalRiskTier.INTERVENTIONAL))
    assert "XX" not in str(ex2.value)


def test_class_b_rejects_only_interventional() -> None:
    """Kills XX-corruption of the Class B error literal."""
    mode = MedDeviceMode(config=_enabled_cfg(SoftwareSafetyClass.B))
    mode.validate_registration(_Action("info", ClinicalRiskTier.INFORMATIONAL))
    mode.validate_registration(_Action("adv", ClinicalRiskTier.ADVISORY))
    with pytest.raises(ValueError) as ex:
        mode.validate_registration(_Action("interv", ClinicalRiskTier.INTERVENTIONAL))
    msg = str(ex.value)
    assert "XX" not in msg
    assert msg == "MedDevice Class B forbids interventional action 'interv'"


def test_class_c_allows_all_tiers() -> None:
    mode = MedDeviceMode(config=_enabled_cfg(SoftwareSafetyClass.C))
    mode.validate_registration(_Action("info", ClinicalRiskTier.INFORMATIONAL))
    mode.validate_registration(_Action("adv", ClinicalRiskTier.ADVISORY))
    mode.validate_registration(_Action("interv", ClinicalRiskTier.INTERVENTIONAL))


def test_registration_records_iec_traceability_when_present() -> None:
    mode = MedDeviceMode(config=_enabled_cfg(SoftwareSafetyClass.C))
    mode.validate_registration(
        _Action("dose_adjust", ClinicalRiskTier.INTERVENTIONAL, iec62304_requirement="SR-007"),
    )
    assert mode.iec_traceability == {"dose_adjust": "SR-007"}


# ---------------------------------------------------------------------------
# Emergency stop / reset
# ---------------------------------------------------------------------------


def test_emergency_stop_then_assert_running_raises_with_exact_message() -> None:
    """Kills XX-corruption of the EmergencyStop message literal."""
    mode = MedDeviceMode(config=_enabled_cfg())
    mode.emergency_stop()
    with pytest.raises(EmergencyStop) as ex:
        mode.assert_running()
    msg = str(ex.value)
    assert "XX" not in msg
    assert msg == "ClinicSentry emergency stop engaged"


def test_meddevice_mode_internal_fields_are_not_init_kwargs() -> None:
    """The three private fields are declared ``init=False``.

    Kills ``init=False`` → ``init=True`` mutants by asserting that the public
    constructor refuses these kwargs.
    """
    cfg = _enabled_cfg()
    for kwarg in ("_emergency", "_changes_this_window", "iec_traceability"):
        with pytest.raises(TypeError):
            MedDeviceMode(config=cfg, **{kwarg: object()})  # type: ignore[arg-type]


def test_reset_clears_emergency_flag_and_counter() -> None:
    """Kills ``self._emergency = False`` → ``= True`` mutant in reset()."""
    mode = MedDeviceMode(config=_enabled_cfg(rate_limit_per_hour=2))
    mode.emergency_stop()
    mode.record_device_change()
    mode.reset()
    # After reset, assert_running must succeed and counter must be cleared.
    mode.assert_running()
    # If counter weren't cleared, the second change would fail rate-limit.
    assert mode.record_device_change() is True
    assert mode.record_device_change() is True
    assert mode.record_device_change() is False  # 3rd > limit of 2


# ---------------------------------------------------------------------------
# Dose validation
# ---------------------------------------------------------------------------


def test_validate_dose_unknown_parameter_fails_closed_by_default() -> None:
    """With ranges configured, an undeclared parameter is rejected (strict default)."""
    mode = MedDeviceMode(
        config=_enabled_cfg(
            dose_ranges=[DoseRange(parameter="rate", min_value=0.0, max_value=5.0)],
        )
    )
    assert mode.validate_dose("unknown-parameter", 100.0) is False


def test_validate_dose_unknown_parameter_permissive_opt_out() -> None:
    """Kills ``return True`` → ``return False`` mutant on the non-strict path."""
    mode = MedDeviceMode(
        config=_enabled_cfg(
            dose_ranges=[DoseRange(parameter="rate", min_value=0.0, max_value=5.0)],
            strict_dose_ranges=False,
        )
    )
    assert mode.validate_dose("unknown-parameter", 100.0) is True


def test_validate_dose_no_ranges_configured_is_permissive() -> None:
    """Strict mode only applies when at least one range is declared."""
    mode = MedDeviceMode(config=_enabled_cfg(dose_ranges=[]))
    assert mode.validate_dose("anything", 1.0) is True


def test_validate_dose_known_parameter_respects_range() -> None:
    mode = MedDeviceMode(
        config=_enabled_cfg(
            dose_ranges=[DoseRange(parameter="rate", min_value=0.0, max_value=5.0)],
        )
    )
    assert mode.validate_dose("rate", 2.5) is True
    assert mode.validate_dose("rate", 10.0) is False


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_record_device_change_no_limit_returns_true() -> None:
    """When ``rate_limit_per_hour`` is None, every call returns True without counting."""
    mode = MedDeviceMode(config=_enabled_cfg(rate_limit_per_hour=None))
    for _ in range(50):
        assert mode.record_device_change() is True


def test_record_device_change_enforces_limit() -> None:
    """Equal to limit returns True; exceeding returns False."""
    mode = MedDeviceMode(config=_enabled_cfg(rate_limit_per_hour=3))
    assert mode.record_device_change() is True
    assert mode.record_device_change() is True
    assert mode.record_device_change() is True
    assert mode.record_device_change() is False


# ---------------------------------------------------------------------------
# Interventional authorization (Class C HMAC)
# ---------------------------------------------------------------------------


def test_authorize_interventional_disabled_returns_true() -> None:
    mode = MedDeviceMode(config=MedDeviceConfig(enabled=False))
    assert mode.authorize_interventional("act", "doc", "anything") is True


def test_authorize_interventional_non_class_c_returns_true() -> None:
    """Classes A and B don't gate on signature."""
    for cls in (SoftwareSafetyClass.A, SoftwareSafetyClass.B):
        mode = MedDeviceMode(config=_enabled_cfg(cls))
        assert mode.authorize_interventional("act", "doc", "anything") is True


def test_authorize_interventional_class_c_unknown_clinician_returns_false() -> None:
    mode = MedDeviceMode(config=_enabled_cfg(SoftwareSafetyClass.C))
    assert mode.authorize_interventional("act", "unknown", "sig") is False


def test_authorize_interventional_class_c_matching_signature_returns_true() -> None:
    key = b"k" * 32
    mode = MedDeviceMode(
        config=_enabled_cfg(
            SoftwareSafetyClass.C,
            authorized_clinician_keys={"doc": key},
        )
    )
    sig = hmac.new(key, b"act", hashlib.sha256).hexdigest()
    assert mode.authorize_interventional("act", "doc", sig) is True


def test_authorize_interventional_class_c_wrong_signature_returns_false() -> None:
    mode = MedDeviceMode(
        config=_enabled_cfg(
            SoftwareSafetyClass.C,
            authorized_clinician_keys={"doc": b"k" * 32},
        )
    )
    assert mode.authorize_interventional("act", "doc", "0" * 64) is False


# ---------------------------------------------------------------------------
# report_section payload structure
# ---------------------------------------------------------------------------


def test_report_section_disabled_is_empty() -> None:
    """When config.enabled is False, report_section returns an empty dict."""
    mode = MedDeviceMode(config=MedDeviceConfig(enabled=False))
    assert mode.report_section() == {}


def test_report_section_keys_are_exactly_as_documented() -> None:
    """Kills XX-corruption of any of the report-section keys.

    The set of keys is asserted exactly: a renamed key shows up as either
    missing or extra and fails this assertion.
    """
    mode = MedDeviceMode(
        config=_enabled_cfg(
            SoftwareSafetyClass.B,
            device_type="insulin_pump",
            intended_use="closed-loop glucose control",
            manufacturer="Acme Medical Devices",
            udi="01234567890123",
            rate_limit_per_hour=6,
        )
    )
    payload = mode.report_section()
    assert set(payload.keys()) == {
        "software_safety_class",
        "device_type",
        "intended_use",
        "manufacturer",
        "udi",
        "iec62304_traceability",
        "rate_limit_per_hour",
        "device_changes_this_session",
        "emergency_stop_engaged",
    }
    assert payload["software_safety_class"] == "B"
    assert payload["device_type"] == "insulin_pump"
    assert payload["intended_use"] == "closed-loop glucose control"
    assert payload["manufacturer"] == "Acme Medical Devices"
    assert payload["udi"] == "01234567890123"
    assert payload["rate_limit_per_hour"] == 6
    assert payload["device_changes_this_session"] == 0
    assert payload["emergency_stop_engaged"] is False


def test_report_section_reflects_emergency_and_counter_state() -> None:
    mode = MedDeviceMode(config=_enabled_cfg(rate_limit_per_hour=5))
    mode.record_device_change()
    mode.record_device_change()
    mode.emergency_stop()
    payload = mode.report_section()
    assert payload["device_changes_this_session"] == 2
    assert payload["emergency_stop_engaged"] is True
