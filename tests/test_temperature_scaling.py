"""Tests for post-hoc temperature scaling calibration."""

from __future__ import annotations

import pytest

from clinicsentry.escalation.temperature_scaling import TemperatureScaler, _logit, _sigmoid

# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------


def test_sigmoid_logit_roundtrip() -> None:
    """sigmoid(logit(p)) should return p."""
    for p in [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99]:
        assert abs(_sigmoid(_logit(p)) - p) < 1e-10


def test_sigmoid_extreme_values() -> None:
    """Sigmoid should be numerically stable at extremes."""
    assert _sigmoid(100.0) == pytest.approx(1.0, abs=1e-10)
    assert _sigmoid(-100.0) == pytest.approx(0.0, abs=1e-10)
    assert _sigmoid(0.0) == pytest.approx(0.5, abs=1e-10)


# ---------------------------------------------------------------------------
# TemperatureScaler tests
# ---------------------------------------------------------------------------


def test_identity_when_temperature_is_one() -> None:
    """T=1.0 should be the identity transform."""
    scaler = TemperatureScaler(temperature=1.0)
    for p in [0.1, 0.3, 0.5, 0.7, 0.9]:
        assert scaler.calibrate(p) == pytest.approx(p, abs=1e-10)


def test_overconfident_model_gets_temperature_above_one() -> None:
    """A model that predicts 0.95 for everything but is correct only 50% should get T > 1."""
    probs = [0.95] * 100
    labels = [True] * 50 + [False] * 50
    scaler = TemperatureScaler()
    scaler.fit(probs, labels)
    assert scaler.temperature > 1.0
    # Calibrated output should be closer to 0.5
    calibrated = scaler.calibrate(0.95)
    assert calibrated < 0.95


def test_underconfident_model_gets_temperature_below_one() -> None:
    """A model that predicts 0.55 but is correct 95% should get T < 1."""
    probs = [0.55] * 100
    labels = [True] * 95 + [False] * 5
    scaler = TemperatureScaler()
    scaler.fit(probs, labels)
    assert scaler.temperature < 1.0
    # Calibrated output should be pushed away from 0.5
    calibrated = scaler.calibrate(0.55)
    assert calibrated > 0.55


def test_well_calibrated_model_temperature_near_one() -> None:
    """A model that predicts 0.7 and is correct 70% should get T ~ 1."""
    probs = [0.7] * 100
    labels = [True] * 70 + [False] * 30
    scaler = TemperatureScaler()
    scaler.fit(probs, labels)
    assert 0.5 < scaler.temperature < 2.0


def test_transform_applies_to_list() -> None:
    """Transform should apply calibration to each element."""
    scaler = TemperatureScaler(temperature=2.0)
    raw = [0.1, 0.5, 0.9]
    calibrated = scaler.transform(raw)
    assert len(calibrated) == 3
    for r, c in zip(raw, calibrated, strict=False):
        assert c == pytest.approx(scaler.calibrate(r), abs=1e-10)


def test_fit_returns_self() -> None:
    """Fit should return self for method chaining."""
    scaler = TemperatureScaler()
    result = scaler.fit([0.5, 0.5], [True, False])
    assert result is scaler


def test_is_fitted_flag() -> None:
    """is_fitted should be False before fit and True after."""
    scaler = TemperatureScaler()
    assert scaler.is_fitted is False
    scaler.fit([0.5, 0.5], [True, False])
    assert scaler.is_fitted is True


def test_fit_rejects_mismatched_lengths() -> None:
    """Fit should raise ValueError if probs and labels have different lengths."""
    scaler = TemperatureScaler()
    with pytest.raises(ValueError, match="same length"):
        scaler.fit([0.5, 0.5], [True])


def test_fit_rejects_empty_data() -> None:
    """Fit should raise ValueError on empty input."""
    scaler = TemperatureScaler()
    with pytest.raises(ValueError, match="empty"):
        scaler.fit([], [])


def test_temperature_scaling_preserves_ranking() -> None:
    """Temperature scaling must preserve the relative ordering of probabilities."""
    scaler = TemperatureScaler(temperature=3.0)
    probs = [0.1, 0.3, 0.5, 0.7, 0.9]
    calibrated = scaler.transform(probs)
    for i in range(len(calibrated) - 1):
        assert calibrated[i] < calibrated[i + 1]


def test_calibrate_at_half_unchanged_by_any_temperature() -> None:
    """p=0.5 should map to 0.5 regardless of temperature (logit(0.5) = 0)."""
    for t in [0.1, 0.5, 1.0, 2.0, 5.0]:
        scaler = TemperatureScaler(temperature=t)
        assert scaler.calibrate(0.5) == pytest.approx(0.5, abs=1e-10)
