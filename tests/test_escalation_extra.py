"""Tests for confidence signals 5-8 and escalation channels."""

from __future__ import annotations

import math

import pytest

from clinicsentry.escalation import (
    GuidelineAdherenceSignal,
    GuidelineRule,
    HistoricalConsistencySignal,
    InMemoryReviewQueue,
    OverridePredictionSignal,
    UncertaintySignal,
    calibrate_thresholds,
)
from clinicsentry.types import ClinicalRiskTier, EscalationDecision

# --- Signal 5: historical consistency -------------------------------------


def test_historical_consistency_returns_negative_one_when_empty() -> None:
    sig = HistoricalConsistencySignal()
    assert sig.score("s1", [1.0, 0.0, 0.0]) == -1.0


def test_historical_consistency_returns_one_for_identical_repeat() -> None:
    sig = HistoricalConsistencySignal()
    sig.update("s1", [1.0, 0.0, 0.0])
    assert sig.score("s1", [1.0, 0.0, 0.0]) == pytest.approx(1.0)


def test_historical_consistency_respects_window_size() -> None:
    sig = HistoricalConsistencySignal(window_size=2)
    for _ in range(5):
        sig.update("s1", [0.0, 1.0])
    history = sig._per_session["s1"]
    assert len(history) == 2


# --- Signal 6: uncertainty ------------------------------------------------


def test_uncertainty_signal_returns_negative_one_when_missing() -> None:
    assert UncertaintySignal().score(None) == -1.0


def test_uncertainty_signal_temperature_softens_overconfidence() -> None:
    raw = UncertaintySignal(temperature=1.0).score(math.log(0.95))
    softened = UncertaintySignal(temperature=2.0).score(math.log(0.95))
    assert raw > softened


# --- Signal 7: guideline adherence ----------------------------------------


def test_guideline_adherence_perfect_score_when_all_rules_pass() -> None:
    rules = [
        GuidelineRule(id="g1", description="mentions dosage", predicate=lambda t: "mg" in t),
        GuidelineRule(id="g2", description="mentions schedule", predicate=lambda t: "daily" in t),
    ]
    signal = GuidelineAdherenceSignal(rules=rules)
    assert signal.score("Take 500mg daily") == pytest.approx(1.0)
    assert signal.violations("Take 500mg daily") == []


def test_guideline_adherence_reports_violations() -> None:
    rules = [
        GuidelineRule(id="g1", description="dosage", predicate=lambda t: "mg" in t),
        GuidelineRule(id="g2", description="schedule", predicate=lambda t: "daily" in t),
    ]
    signal = GuidelineAdherenceSignal(rules=rules)
    assert signal.score("Take 500mg as needed") == pytest.approx(0.5)
    violations = signal.violations("Take 500mg as needed")
    assert {r.id for r in violations} == {"g2"}


# --- Signal 8: override prediction ----------------------------------------


def test_override_prediction_uncalibrated_returns_negative_one() -> None:
    sig = OverridePredictionSignal()
    assert sig.score({"x": 1.0}) == -1.0


def test_override_prediction_inverts_probability() -> None:
    # Trained: high feature → high override probability → low score.
    sig = OverridePredictionSignal(weights={"low_confidence_flag": 5.0}, intercept=-1.0)
    score_low = sig.score({"low_confidence_flag": 1.0})
    score_high = sig.score({"low_confidence_flag": 0.0})
    assert score_low < score_high


# --- Threshold calibration ------------------------------------------------


def test_calibrate_thresholds_picks_threshold_separating_correct_from_wrong() -> None:
    samples = [
        (0.95, True),
        (0.92, True),
        (0.85, True),
        (0.50, False),
        (0.40, False),
        (0.30, False),
    ]
    result = calibrate_thresholds(samples)
    assert 0.5 <= result["threshold"] <= 0.9
    assert result["f1"] >= 0.9


def test_calibrate_thresholds_handles_empty_history() -> None:
    result = calibrate_thresholds([])
    assert result["threshold"] == 0.7


# --- Review queue channel -------------------------------------------------


def test_inmemory_review_queue_enqueues_and_resolves() -> None:
    queue = InMemoryReviewQueue(sla_hours=24)
    decision = EscalationDecision(action="escalate", tier=ClinicalRiskTier.ADVISORY, confidence=0.6)
    queue.dispatch(decision, session_id="s1", action_name="recommend_basal")
    pending = queue.pending()
    assert len(pending) == 1
    review_id = pending[0].review_id
    assert queue.resolve(review_id)
    assert queue.pending() == []


def test_inmemory_review_queue_tracks_overdue_entries() -> None:
    queue = InMemoryReviewQueue(sla_hours=-1)  # Already overdue.
    decision = EscalationDecision(action="escalate", tier=ClinicalRiskTier.ADVISORY, confidence=0.6)
    queue.dispatch(decision, session_id="s1", action_name="recommend_basal")
    assert len(queue.overdue()) == 1
