"""IEC 62304 / SaMD safety enforcement (README §9)."""

from __future__ import annotations

import enum
import hashlib
import hmac
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from clinicsentry.types import ClinicalRiskTier

__all__ = [
    "SoftwareSafetyClass",
    "DoseRange",
    "MedDeviceConfig",
    "EmergencyStop",
    "MedDeviceMode",
    "ActionLike",
]


@runtime_checkable
class ActionLike(Protocol):
    """Structural type for a registered action.

    Defined locally so :mod:`clinicsentry.meddevice` does not depend on
    :mod:`clinicsentry.escalation` (ADR-0001). Any object exposing these
    attributes — including :class:`clinicsentry.escalation.RegisteredAction`
    — duck-types into this protocol.
    """

    name: str
    tier: ClinicalRiskTier
    iec62304_requirement: str | None
    required_fields: set[str]


class SoftwareSafetyClass(str, enum.Enum):
    """IEC 62304 software safety classification."""

    A = "A"
    B = "B"
    C = "C"


@dataclass
class DoseRange:
    """Allowed range for a closed-loop device parameter."""

    parameter: str
    min_value: float
    max_value: float
    unit: str = ""

    def validate(self, value: float) -> bool:
        """True if ``value`` is finite and within the inclusive range."""
        return math.isfinite(value) and self.min_value <= value <= self.max_value


@dataclass
class MedDeviceConfig:
    """Static device-mode configuration loaded from policy."""

    enabled: bool = False
    software_safety_class: SoftwareSafetyClass = SoftwareSafetyClass.A
    device_type: str = ""
    intended_use: str = ""
    manufacturer: str = ""
    udi: str = ""
    dose_ranges: list[DoseRange] = field(default_factory=list)
    rate_limit_per_hour: int | None = None
    authorized_clinician_keys: dict[str, bytes] = field(default_factory=dict)
    # When dose ranges are configured, a parameter without a declared range is
    # rejected (fail closed) — a typo in the parameter name must not silently
    # bypass validation. Set False to restore permissive pass-through.
    strict_dose_ranges: bool = True


class EmergencyStop(RuntimeError):
    """Raised when the kill-switch has been engaged."""


@dataclass
class MedDeviceMode:
    """Runtime enforcement layer for MedDevice mode."""

    config: MedDeviceConfig
    _emergency: bool = field(default=False, init=False)
    _changes_this_window: int = field(default=0, init=False)
    _change_times: deque[float] = field(default_factory=deque, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    iec_traceability: dict[str, str] = field(default_factory=dict, init=False)

    #: Rolling rate-limit window in seconds.
    RATE_WINDOW_SECONDS = 3600.0

    # ------------------------------------------------------------------
    # Registration-time enforcement
    # ------------------------------------------------------------------

    def validate_registration(self, action: ActionLike) -> None:
        """Enforce class-based action registration constraints (README §9 5a).

        Class A: only INFORMATIONAL allowed.
        Class B: ADVISORY ceiling — INTERVENTIONAL registrations are rejected.
        Class C: anything is allowed but interventional invocations need signed auth.
        """
        if not self.config.enabled:
            return
        cls = self.config.software_safety_class
        if cls == SoftwareSafetyClass.A and action.tier != ClinicalRiskTier.INFORMATIONAL:
            raise ValueError(f"MedDevice Class A forbids non-informational action '{action.name}'")
        if cls == SoftwareSafetyClass.B and action.tier == ClinicalRiskTier.INTERVENTIONAL:
            raise ValueError(f"MedDevice Class B forbids interventional action '{action.name}'")
        if action.iec62304_requirement:
            self.iec_traceability[action.name] = action.iec62304_requirement

    # ------------------------------------------------------------------
    # Runtime enforcement
    # ------------------------------------------------------------------

    def emergency_stop(self) -> None:
        """Engage the kill-switch — all subsequent actions raise."""
        self._emergency = True

    def reset(self) -> None:
        """Clear the kill-switch (test/debug only)."""
        self._emergency = False
        self._changes_this_window = 0
        self._change_times.clear()

    def assert_running(self) -> None:
        """Raise if the kill-switch is engaged."""
        if self._emergency:
            raise EmergencyStop("ClinicSentry emergency stop engaged")

    def authorize_interventional(
        self,
        action_name: str,
        clinician_id: str,
        signature: str,
    ) -> bool:
        """Verify a Class C interventional action authorization signature.

        The clinician must be present in ``config.authorized_clinician_keys`` and
        ``signature`` must be the HMAC-SHA256 of ``action_name`` under their key.
        """
        if not self.config.enabled:
            return True
        if self.config.software_safety_class != SoftwareSafetyClass.C:
            return True
        key = self.config.authorized_clinician_keys.get(clinician_id)
        if not key:
            return False
        expected = hmac.new(key, action_name.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def validate_dose(self, parameter: str, value: float) -> bool:
        """Validate a device parameter modification against configured ranges.

        Non-finite values (NaN, ±inf) always fail. When ranges are configured
        and ``strict_dose_ranges`` is set (the default), a parameter without a
        declared range fails closed.
        """
        if not math.isfinite(value):
            return False
        for dr in self.config.dose_ranges:
            if dr.parameter == parameter:
                return dr.validate(value)
        return not (self.config.strict_dose_ranges and self.config.dose_ranges)

    def record_device_change(self) -> bool:
        """Record a device change; return False if the rolling 1-hour limit is exceeded."""
        if self.config.rate_limit_per_hour is None:
            return True
        now = time.monotonic()
        cutoff = now - self.RATE_WINDOW_SECONDS
        with self._lock:
            while self._change_times and self._change_times[0] < cutoff:
                self._change_times.popleft()
            self._change_times.append(now)
            self._changes_this_window = len(self._change_times)
            return self._changes_this_window <= self.config.rate_limit_per_hour

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report_section(self) -> dict[str, Any]:
        """Material added to the regulatory report when device mode is enabled."""
        if not self.config.enabled:
            return {}
        return {
            "software_safety_class": self.config.software_safety_class.value,
            "device_type": self.config.device_type,
            "intended_use": self.config.intended_use,
            "manufacturer": self.config.manufacturer,
            "udi": self.config.udi,
            "iec62304_traceability": dict(self.iec_traceability),
            "rate_limit_per_hour": self.config.rate_limit_per_hour,
            "device_changes_this_session": self._changes_this_window,
            "emergency_stop_engaged": self._emergency,
        }
