"""Prometheus metrics shim — no-op when prometheus-client is absent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

__all__ = ["Metrics"]


@dataclass
class Metrics:
    """Lazy Prometheus metric registry.

    Provides ``Counter`` and ``Histogram`` instruments tracking ClinicSentry
    operational signals. When ``prometheus_client`` is unavailable, every
    instrument call becomes a no-op so library users never need to branch.
    """

    namespace: str = "clinicsentry"
    _available: bool = field(default=False, init=False)
    _counters: dict[str, Any] = field(default_factory=dict, init=False)
    _histograms: dict[str, Any] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        """Try to import prometheus-client; record availability."""
        try:
            import prometheus_client  # noqa: F401

            self._available = True
        except ImportError:
            self._available = False

    # Class-level caches so duplicate Metrics() construction reuses already-registered instruments.
    _global_counters: ClassVar[dict[str, Any]] = {}
    _global_histograms: ClassVar[dict[str, Any]] = {}

    def counter(self, name: str, documentation: str, labels: tuple[str, ...] = ()) -> Any:
        """Return (and lazily create) a Prometheus Counter."""
        if not self._available:
            return _NoopMetric()
        full = f"{self.namespace}_{name}"
        if full in Metrics._global_counters:
            return Metrics._global_counters[full]
        from prometheus_client import Counter

        instrument = Counter(full, documentation, labels)
        Metrics._global_counters[full] = instrument
        return instrument

    def histogram(
        self,
        name: str,
        documentation: str,
        labels: tuple[str, ...] = (),
        buckets: tuple[float, ...] = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    ) -> Any:
        """Return (and lazily create) a Prometheus Histogram."""
        if not self._available:
            return _NoopMetric()
        full = f"{self.namespace}_{name}"
        if full in Metrics._global_histograms:
            return Metrics._global_histograms[full]
        from prometheus_client import Histogram

        instrument = Histogram(full, documentation, labels, buckets=buckets)
        Metrics._global_histograms[full] = instrument
        return instrument


class _NoopMetric:
    """No-op metric that mimics prometheus_client's instrument API."""

    def labels(self, *_args: Any, **_kwargs: Any) -> _NoopMetric:
        """Return self so chained calls are no-ops."""
        return self

    def inc(self, _amount: float = 1.0) -> None:
        """No-op increment."""

    def observe(self, _value: float) -> None:
        """No-op observation."""
