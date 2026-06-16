"""Performance utilities: caching, latency budget enforcement, profiling helpers.

Latency budgets per ADR-0013 + plan §3G:

- Firewall scan ≤ 20 ms p95
- Escalation decide ≤ 10 ms p95
- Audit append ≤ 5 ms p95
- Total middleware overhead ≤ 50 ms p95

These are *targets*, not contracts. :class:`LatencyBudget` records observed
durations and reports breaches via the Prometheus metrics shim.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from clinicsentry.observability.metrics import Metrics

__all__ = [
    "LatencyBudget",
    "BUDGETS_MS",
    "scan_cache",
    "timed",
]


# Default budgets in milliseconds for the four hot-path operations.
BUDGETS_MS: dict[str, float] = {
    "firewall.scan": 20.0,
    "escalation.decide": 10.0,
    "audit.append": 5.0,
    "total": 50.0,
}


F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class LatencyBudget:
    """Rolling-window p95 latency tracker for a named operation."""

    name: str
    budget_ms: float
    window_size: int = 1024
    _samples: deque[float] = field(default_factory=deque, init=False)
    _metrics: Metrics = field(default_factory=Metrics, init=False)

    def record(self, duration_ms: float) -> bool:
        """Record a sample; return True iff the running p95 is within budget."""
        self._samples.append(duration_ms)
        while len(self._samples) > self.window_size:
            self._samples.popleft()
        hist = self._metrics.histogram(
            "operation_seconds",
            "Operation duration per ClinicSentry hot-path step.",
            labels=("operation",),
        )
        with contextlib.suppress(Exception):  # metrics no-ops never raise in practice
            hist.labels(operation=self.name).observe(duration_ms / 1000.0)
        return self.p95() <= self.budget_ms

    def p95(self) -> float:
        """Return the 95th-percentile sample (0 if no samples)."""
        if not self._samples:
            return 0.0
        ordered = sorted(self._samples)
        idx = int(0.95 * (len(ordered) - 1))
        return ordered[idx]


# ---------------------------------------------------------------------------
# LRU cache for PHI scan results
# ---------------------------------------------------------------------------


def _stable_key(value: Any) -> str:
    """Hash any JSON-serializable value to a stable cache key."""
    blob = json.dumps(value, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


@functools.lru_cache(maxsize=2048)
def _cached_scan(key: str, scanner: Callable[[Any], Any], frozen_payload: str) -> Any:
    """Internal LRU helper. Do not call directly."""
    return scanner(json.loads(frozen_payload))


def scan_cache(scanner: Callable[[Any], Any], payload: Any) -> Any:
    """Run ``scanner(payload)`` with an LRU cache keyed by payload content.

    Suitable for hot-path scans where repeated identical inputs (system
    prompts, header boilerplate) dominate. Cache size is fixed at 2048 entries.
    """
    frozen = json.dumps(payload, sort_keys=True, default=str)
    return _cached_scan(_stable_key(payload), scanner, frozen)


# ---------------------------------------------------------------------------
# Decorator that times a function and records to a LatencyBudget
# ---------------------------------------------------------------------------


def timed(budget: LatencyBudget) -> Callable[[F], F]:
    """Decorator: measure wall-clock time and record into ``budget``."""

    def decorate(func: F) -> F:
        """Wrap ``func`` with timing."""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            """Time the call and feed the result into the budget."""
            t0 = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                budget.record((time.perf_counter() - t0) * 1000.0)

        return wrapper  # type: ignore[return-value]

    return decorate
