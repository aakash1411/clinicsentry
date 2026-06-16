"""MedDevice mode enforcement tests."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from clinicsentry.escalation.router import RegisteredAction
from clinicsentry.meddevice.mode import (
    DoseRange,
    EmergencyStop,
    MedDeviceConfig,
    MedDeviceMode,
    SoftwareSafetyClass,
)
from clinicsentry.types import ClinicalRiskTier


def test_class_a_blocks_advisory_registration() -> None:
    mode = MedDeviceMode(
        config=MedDeviceConfig(enabled=True, software_safety_class=SoftwareSafetyClass.A)
    )
    with pytest.raises(ValueError):
        mode.validate_registration(RegisteredAction(name="x", tier=ClinicalRiskTier.ADVISORY))


def test_class_b_blocks_interventional_registration() -> None:
    mode = MedDeviceMode(
        config=MedDeviceConfig(enabled=True, software_safety_class=SoftwareSafetyClass.B)
    )
    with pytest.raises(ValueError):
        mode.validate_registration(RegisteredAction(name="x", tier=ClinicalRiskTier.INTERVENTIONAL))


def test_class_c_authorization_signature() -> None:
    key = b"k" * 32
    mode = MedDeviceMode(
        config=MedDeviceConfig(
            enabled=True,
            software_safety_class=SoftwareSafetyClass.C,
            authorized_clinician_keys={"dr_smith": key},
        )
    )
    sig = hmac.new(key, b"set_basal", hashlib.sha256).hexdigest()
    assert mode.authorize_interventional("set_basal", "dr_smith", sig)
    assert not mode.authorize_interventional("set_basal", "dr_smith", "bad")
    assert not mode.authorize_interventional("set_basal", "unknown", sig)


def test_dose_range_validation() -> None:
    mode = MedDeviceMode(
        config=MedDeviceConfig(
            enabled=True,
            software_safety_class=SoftwareSafetyClass.B,
            dose_ranges=[DoseRange("basal", 0.0, 5.0)],
        )
    )
    assert mode.validate_dose("basal", 2.5)
    assert not mode.validate_dose("basal", 10.0)


def test_emergency_stop_blocks_actions() -> None:
    mode = MedDeviceMode(config=MedDeviceConfig(enabled=True))
    mode.emergency_stop()
    with pytest.raises(EmergencyStop):
        mode.assert_running()


def test_validate_dose_rejects_non_finite_values() -> None:
    mode = MedDeviceMode(
        config=MedDeviceConfig(
            enabled=True,
            software_safety_class=SoftwareSafetyClass.B,
            dose_ranges=[DoseRange("basal", 0.0, 5.0)],
        )
    )
    assert not mode.validate_dose("basal", float("nan"))
    assert not mode.validate_dose("basal", float("inf"))
    assert not mode.validate_dose("basal", float("-inf"))


def test_rate_limit_uses_rolling_hour_window(monkeypatch) -> None:
    import clinicsentry.meddevice.mode as mode_mod

    clock = {"now": 1000.0}
    monkeypatch.setattr(mode_mod.time, "monotonic", lambda: clock["now"])
    mode = MedDeviceMode(config=MedDeviceConfig(enabled=True, rate_limit_per_hour=2))
    assert mode.record_device_change() is True
    assert mode.record_device_change() is True
    assert mode.record_device_change() is False  # 3rd within the hour
    clock["now"] += 3601.0  # old entries age out of the window
    assert mode.record_device_change() is True
