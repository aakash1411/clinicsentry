"""Post-hoc temperature scaling for confidence calibration.

Temperature scaling (Guo et al., 2017) fits a single scalar parameter *T* such
that calibrated probabilities are ``sigmoid(logit(p) / T)``. This is the
simplest post-hoc calibration method and preserves the **ranking** of
confidence scores — it only rescales the magnitudes to reduce ECE.

Usage::

    from clinicsentry.escalation.temperature_scaling import TemperatureScaler

    scaler = TemperatureScaler()
    scaler.fit(validation_probs, validation_labels)

    calibrated = scaler.transform(raw_probs)
    # or on a single value:
    calibrated_single = scaler.calibrate(0.92)

The fit uses Brent's bracketed minimization of NLL (negative log-likelihood)
so no external optimization library is needed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

__all__ = [
    "TemperatureScaler",
]

_EPS = 1e-15


def _logit(p: float) -> float:
    """Inverse sigmoid (logit function)."""
    p = max(_EPS, min(1.0 - _EPS, p))
    return math.log(p / (1.0 - p))


def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def _nll(temperature: float, probs: list[float], labels: list[bool]) -> float:
    """Negative log-likelihood of labels given temperature-scaled probs."""
    total = 0.0
    for p, lbl in zip(probs, labels, strict=False):
        scaled = _sigmoid(_logit(p) / temperature)
        if lbl:
            total -= math.log(max(scaled, _EPS))
        else:
            total -= math.log(max(1.0 - scaled, _EPS))
    return total / max(1, len(probs))


def _brent_minimize(
    func: object,
    a: float,
    b: float,
    *,
    tol: float = 1e-6,
    max_iter: int = 100,
) -> float:
    """Brent's method for 1-D minimization on [a, b].

    Finds the temperature T in [a, b] that minimizes ``func(T)``.
    Uses the golden-section + parabolic interpolation approach.
    """
    f = func
    golden = 0.381966011250105  # (3 - sqrt(5)) / 2
    x = w = v = a + golden * (b - a)
    fx = fw = fv = f(x)  # type: ignore[operator]
    d = e = 0.0

    for _ in range(max_iter):
        midpoint = 0.5 * (a + b)
        tol1 = tol * abs(x) + _EPS
        tol2 = 2.0 * tol1

        if abs(x - midpoint) <= (tol2 - 0.5 * (b - a)):
            break

        # Try parabolic interpolation
        if abs(e) > tol1:
            r = (x - w) * (fx - fv)
            q = (x - v) * (fx - fw)
            p_val = (x - v) * q - (x - w) * r
            q = 2.0 * (q - r)
            if q > 0:
                p_val = -p_val
            else:
                q = -q
            r = e
            e = d

            if abs(p_val) < abs(0.5 * q * r) and p_val > q * (a - x) and p_val < q * (b - x):
                d = p_val / q
                u = x + d
                if (u - a) < tol2 or (b - u) < tol2:
                    d = tol1 if x < midpoint else -tol1
            else:
                e = (a if x >= midpoint else b) - x
                d = golden * e
        else:
            e = (a if x >= midpoint else b) - x
            d = golden * e

        u = x + (d if abs(d) >= tol1 else (tol1 if d > 0 else -tol1))
        fu = f(u)  # type: ignore[operator]

        if fu <= fx:
            if u >= x:
                a = x
            else:
                b = x
            v, w, x = w, x, u
            fv, fw, fx = fw, fx, fu
        else:
            if u < x:
                a = u
            else:
                b = u
            if fu <= fw or w == x:
                v, w = w, u
                fv, fw = fw, fu
            elif fu <= fv or v in (x, w):
                v = u
                fv = fu

    return x


@dataclass
class TemperatureScaler:
    """Post-hoc Platt / temperature scaling calibrator.

    After calling :meth:`fit` with a validation set of ``(prob, label)`` pairs,
    :meth:`calibrate` rescales any raw probability to improve calibration.

    The fitted temperature ``T`` is stored in :attr:`temperature`.
    ``T > 1`` means the model is overconfident (probabilities are pushed toward
    0.5); ``T < 1`` means the model is underconfident.

    Args:
        temperature: Initial temperature (1.0 = identity transform).
        t_min: Lower bound for temperature search.
        t_max: Upper bound for temperature search.
    """

    temperature: float = 1.0
    t_min: float = 0.01
    t_max: float = 10.0
    _is_fitted: bool = field(default=False, init=False, repr=False)

    def fit(self, probs: list[float], labels: list[bool]) -> TemperatureScaler:
        """Fit the temperature parameter by minimizing NLL.

        Args:
            probs: Raw predicted probabilities (0–1).
            labels: Ground-truth binary labels.

        Returns:
            self, for method chaining.
        """
        if len(probs) != len(labels):
            raise ValueError(
                f"probs ({len(probs)}) and labels ({len(labels)}) must have same length"
            )
        if not probs:
            raise ValueError("Cannot fit on empty data")

        def objective(t: float) -> float:
            return _nll(t, probs, labels)

        self.temperature = _brent_minimize(objective, self.t_min, self.t_max)
        self._is_fitted = True
        return self

    def calibrate(self, prob: float) -> float:
        """Apply temperature scaling to a single probability.

        Args:
            prob: Raw predicted probability.

        Returns:
            Calibrated probability.
        """
        return _sigmoid(_logit(prob) / self.temperature)

    def transform(self, probs: list[float]) -> list[float]:
        """Apply temperature scaling to a list of probabilities.

        Args:
            probs: Raw predicted probabilities.

        Returns:
            List of calibrated probabilities.
        """
        return [self.calibrate(p) for p in probs]

    @property
    def is_fitted(self) -> bool:
        """Return True if :meth:`fit` has been called."""
        return self._is_fitted
