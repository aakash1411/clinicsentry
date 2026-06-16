"""Observability hooks for ClinicSentry (ADR-0013).

Three optional dependencies, each gracefully absent:

- ``opentelemetry-*`` → :func:`span` context manager emits OTEL spans.
- ``prometheus-client`` → :class:`Metrics` exposes Counter/Histogram instruments.
- ``structlog`` → :func:`get_logger` returns a JSON-structured logger.

When any of these is missing the corresponding helper degrades to a no-op.
"""

from clinicsentry.observability.logging import get_logger
from clinicsentry.observability.metrics import Metrics
from clinicsentry.observability.tracing import span

__all__ = ["get_logger", "Metrics", "span"]
