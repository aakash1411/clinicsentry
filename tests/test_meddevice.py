"""MedDevice mode enforcement tests."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from clinicsentry.escalation.router import RegisteredAction
from clinicsentry.meddevice.mode import (
    DoseRange,
    EmergencyStop,
    MedDeviceConfig,
    MedDeviceMode,
    SoftwareSafetyClass,
    sign_interventional_authorization,
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
    now = int(time.time())
    bound = {"session_id": "s1", "nonce": "n1", "issued_at": now}
    sig = sign_interventional_authorization(
        key, action_name="set_basal", clinician_id="dr_smith", **bound
    )
    assert not mode.authorize_interventional("set_basal", "dr_smith", "bad", **bound)
    assert not mode.authorize_interventional("set_basal", "unknown", sig, **bound)
    assert mode.authorize_interventional("set_basal", "dr_smith", sig, **bound)
    # Single use: the same signature/nonce cannot be replayed.
    assert not mode.authorize_interventional("set_basal", "dr_smith", sig, **bound)
    # Legacy unbound signature over the bare action name is rejected.
    legacy = hmac.new(key, b"set_basal", hashlib.sha256).hexdigest()
    assert not mode.authorize_interventional("set_basal", "dr_smith", legacy)


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
