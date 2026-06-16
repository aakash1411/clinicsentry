"""Additional confidence signals (5–8) plus threshold calibration helpers.

These signals are opt-in: the base :class:`ConfidenceScorer` is unchanged.
Wire them in by extending the scorer's ``weights`` dict and providing the
matching inputs.

Signals implemented here:

5. **Historical consistency** — cosine similarity of the current output's
   embedding against the session's prior outputs. Higher is more consistent.
6. **Uncertainty quantification** — temperature-scaled probability of the
   top-1 token; calibrated via Platt scaling if calibration data is provided.
7. **Clinical guideline adherence** — fraction of guideline rules that match
   the current output (rule engine).
8. **Clinician override prediction** — logistic regression on session
   features; output is *1 - predicted override probability*.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

__all__ = [
    "HistoricalConsistencySignal",
    "UncertaintySignal",
    "GuidelineRule",
    "GuidelineAdherenceSignal",
    "OverridePredictionSignal",
    "calibrate_thresholds",
]


# ---------------------------------------------------------------------------
# Signal 5: historical consistency
# ---------------------------------------------------------------------------


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity for equal-length vectors; 0 if either is null."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na > 0 and nb > 0 else 0.0


@dataclass
class HistoricalConsistencySignal:
    """Maintain a rolling window of past output embeddings per session.

    The signal value is the mean cosine similarity of the new embedding against
    every embedding currently in the window. New sessions (no history) return
    -1 so the scorer drops the signal from the weighted average.
    """

    window_size: int = 8
    _per_session: dict[str, list[list[float]]] = field(default_factory=dict, init=False)

    def update(self, session_id: str, embedding: Sequence[float]) -> None:
        """Add an embedding to the session's history."""
        history = self._per_session.setdefault(session_id, [])
        history.append(list(embedding))
        if len(history) > self.window_size:
            del history[: len(history) - self.window_size]

    def score(self, session_id: str, embedding: Sequence[float]) -> float:
        """Return mean cosine similarity vs. prior embeddings (or -1 if none)."""
        history = self._per_session.get(session_id, [])
        if not history:
            return -1.0
        return sum(_cosine(embedding, h) for h in history) / len(history)


# ---------------------------------------------------------------------------
# Signal 6: uncertainty quantification (temperature scaling)
# ---------------------------------------------------------------------------


@dataclass
class UncertaintySignal:
    """Temperature-scaled top-1 probability calibration.

    Args:
        temperature: T > 1 softens the distribution (reduces overconfidence);
            T < 1 sharpens it. Default 1.5 matches common LLM miscalibration.
    """

    temperature: float = 1.5

    def score(self, top_logprob: float | None) -> float:
        """Return calibrated probability in [0, 1], or -1 if input missing.

        With ``T = 1`` returns the raw probability. With ``T > 1`` the
        probability is softened (overconfidence reduced) via ``p ** T``: for a
        well-calibrated model T ~= 1; for typical overconfident LLMs T > 1.
        """
        if top_logprob is None:
            return -1.0
        prob = math.exp(top_logprob)
        calibrated = prob if self.temperature == 1.0 else prob**self.temperature
        return float(min(1.0, max(0.0, calibrated)))


# ---------------------------------------------------------------------------
# Signal 7: clinical guideline adherence
# ---------------------------------------------------------------------------


@dataclass
class GuidelineRule:
    """A single guideline rule: ``predicate`` returns True iff the rule fires."""

    id: str
    description: str
    predicate: Callable[[str], bool]
    severity: str = "info"  # info | warning | blocker


@dataclass
class GuidelineAdherenceSignal:
    """Score = fraction of applicable rules whose predicate is satisfied."""

    rules: list[GuidelineRule]

    def score(self, output_text: str) -> float:
        """Return adherence ratio, or -1 if no rules apply."""
        if not self.rules:
            return -1.0
        passed = sum(1 for r in self.rules if r.predicate(output_text))
        return passed / len(self.rules)

    def violations(self, output_text: str) -> list[GuidelineRule]:
        """Return the rules that *failed* (for explanation in the audit log)."""
        return [r for r in self.rules if not r.predicate(output_text)]


# ---------------------------------------------------------------------------
# Signal 8: clinician override prediction
# ---------------------------------------------------------------------------


@dataclass
class OverridePredictionSignal:
    """Logistic regression on session-level features.

    The model is trivially small (intercept + linear weights) so it can be
    shipped as a JSON blob without a heavyweight ML dependency. Training is
    out-of-band; this class only does inference.
    """

    weights: dict[str, float] = field(default_factory=dict)
    intercept: float = 0.0

    def predict_override_probability(self, features: dict[str, float]) -> float:
        """Return P(override) in [0, 1]."""
        if not self.weights:
            return -1.0
        z = self.intercept + sum(self.weights.get(k, 0.0) * float(v) for k, v in features.items())
        return 1.0 / (1.0 + math.exp(-z))

    def score(self, features: dict[str, float]) -> float:
        """Return ``1 - P(override)`` so 'high' = 'agent likely correct'."""
        p = self.predict_override_probability(features)
        if p < 0:
            return -1.0
        return 1.0 - p


# ---------------------------------------------------------------------------
# Threshold calibration
# ---------------------------------------------------------------------------


DEFAULT_GRID: tuple[float, ...] = tuple(round(x * 0.05, 2) for x in range(2, 19))


def calibrate_thresholds(
    historical: Iterable[tuple[float, bool]],
    grid: Sequence[float] = DEFAULT_GRID,
) -> dict[str, float]:
    """Grid-search escalation thresholds maximising F1 on historical data.

    Args:
        historical: iterable of ``(confidence, was_correct)`` pairs.
        grid: candidate threshold values to test.

    Returns:
        A dict with the best ``threshold`` and the achieved ``f1``,
        ``precision``, ``recall``.
    """
    samples = list(historical)
    if not samples:
        return {"threshold": 0.7, "f1": 0.0, "precision": 0.0, "recall": 0.0}

    best = {"threshold": grid[0], "f1": -1.0, "precision": 0.0, "recall": 0.0}
    for t in grid:
        tp = fp = fn = tn = 0
        for confidence, correct in samples:
            predicted_correct = confidence >= t
            if predicted_correct and correct:
                tp += 1
            elif predicted_correct and not correct:
                fp += 1
            elif not predicted_correct and correct:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        if f1 > best["f1"]:
            best = {"threshold": t, "f1": f1, "precision": precision, "recall": recall}
    return best
