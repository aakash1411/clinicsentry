"""A4: custom detector registration (decorator + config)."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from clinicsentry.errors import PolicyError
from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.custom import CustomRegexDetector, register_detector
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.policy import load_policy


@register_detector(label="PUMP_SERIAL", mode="REDACT")
def pump_serial(text: str) -> Iterator[tuple[int, int, float]]:
    for m in re.finditer(r"\b(?:CSN)[\s:#-]*([A-Z0-9]{6,})\b", text):
        yield m.start(), m.end(), 0.95


def test_decorator_detector_through_guard() -> None:
    guard = ClinicSentry(framework="bot", detectors=[pump_serial])
    out = guard.firewall.scan("pump CSN: AB99887766 attached")
    assert out.redacted == "pump [REDACTED:PUMP_SERIAL] attached"
    assert any(f.phi_type == "PUMP_SERIAL" for f in out.findings)


def test_decorator_detector_through_firewall() -> None:
    fw = PHIFirewall(custom_detectors=[pump_serial])
    assert "[REDACTED:PUMP_SERIAL]" in str(fw.scan("CSN XYZ123456").redacted)


def test_decorated_function_still_callable() -> None:
    spans = list(pump_serial("CSN ABCDEF123"))
    assert spans
    assert spans[0][2] == 0.95


def test_register_detector_rejects_bad_label() -> None:
    with pytest.raises(ValueError, match="label"):
        register_detector(label="not a label!")


def test_config_regex_detector() -> None:
    # confidence above DEVICE_ID's 0.92 so the custom label wins the overlap
    # with the built-in serial detector on the same span.
    cfg = load_policy(
        {
            "phi_firewall": {
                "custom_detectors": [
                    {
                        "label": "PUMP_SERIAL",
                        "pattern": r"\b(?:SN|serial)[\s:#-]*[A-Z0-9]{6,}\b",
                        "flags": ["IGNORECASE"],
                        "mode": "REDACT",
                        "confidence": 0.99,
                    }
                ]
            }
        }
    )
    guard = ClinicSentry(policy=cfg, framework="bot")
    out = guard.firewall.scan("my serial: NG998877A")
    assert "[REDACTED:PUMP_SERIAL]" in str(out.redacted)


def test_custom_and_builtin_overlap_still_redacts() -> None:
    """Whoever wins the overlap, the identifier itself must never survive."""
    cfg = load_policy(
        {
            "phi_firewall": {
                "custom_detectors": [
                    {"label": "PUMP_SERIAL", "pattern": r"\bSN[\s:#-]*[A-Z0-9]{6,}\b"}
                ]
            }
        }
    )
    guard = ClinicSentry(policy=cfg, framework="bot")
    out = guard.firewall.scan("pump SN NG998877A")
    assert "NG998877A" not in str(out.redacted)


def test_config_detector_mode_override_applies() -> None:
    cfg = load_policy(
        {
            "phi_firewall": {
                "custom_detectors": [
                    {"label": "CASE_ID", "pattern": r"\bCASE-\d{6}\b", "mode": "SUPPRESS"}
                ]
            }
        }
    )
    guard = ClinicSentry(policy=cfg, framework="bot")
    out = guard.firewall.scan("ref CASE-123456 closed")
    assert out.redacted == "ref  closed"


def test_invalid_custom_pattern_rejected_at_load() -> None:
    with pytest.raises(PolicyError, match="invalid pattern"):
        load_policy(
            {"phi_firewall": {"custom_detectors": [{"label": "X", "pattern": "(unclosed"}]}}
        )


def test_invalid_flag_rejected_at_load() -> None:
    with pytest.raises(PolicyError, match="unknown flag"):
        load_policy(
            {
                "phi_firewall": {
                    "custom_detectors": [{"label": "X", "pattern": "x", "flags": ["TURBO"]}]
                }
            }
        )


def test_custom_regex_detector_out_of_range_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        CustomRegexDetector.from_config({"label": "X", "pattern": "x", "confidence": 2})


def test_custom_detector_span_bounds_are_clamped() -> None:
    @register_detector(label="BROKEN")
    def broken(text: str) -> Iterator[tuple[int, int, float]]:
        yield -5, 999999, 0.9

    fw = PHIFirewall(custom_detectors=[broken])
    out = fw.scan("short text")
    assert out.redacted == "short text"  # invalid span discarded, not crash
