"""OpenTelemetry audit exporter.

Wraps any :class:`AuditBackend` and additionally emits one OTLP span per audit
event. Spans are named ``clinicsentry.audit.<event_type>`` and carry
attributes prefixed ``clinicsentry.*`` per ADR-0013.

When ``opentelemetry-api`` is not installed, this backend silently degrades to
a plain wrapper that only delegates to the inner backend.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from clinicsentry.audit.backend import AuditBackend
from clinicsentry.types import AuditEvent

__all__ = ["OTELAuditBackend"]


class OTELAuditBackend(AuditBackend):
    """Delegating backend that also emits an OTEL span per appended event."""

    def __init__(
        self,
        inner: AuditBackend,
        *,
        tracer_name: str = "clinicsentry",
        tracer: Any | None = None,
    ) -> None:
        """Construct the exporter.

        Args:
            inner: any concrete :class:`AuditBackend` for persistence.
            tracer_name: instrumentation name for ``trace.get_tracer``.
            tracer: pre-configured tracer; useful in tests.
        """
        self._inner = inner
        if tracer is None:
            try:  # pragma: no cover - optional dep
                from opentelemetry import trace

                tracer = trace.get_tracer(tracer_name)
            except ImportError:  # pragma: no cover
                tracer = None
        self._tracer = tracer

    def append(self, event: AuditEvent) -> None:
        """Persist via the inner backend and emit a corresponding span."""
        self._inner.append(event)
        if self._tracer is None:
            return
        with self._tracer.start_as_current_span(
            f"clinicsentry.audit.{event.event_type.value}"
        ) as span:  # pragma: no cover - span no-op without exporter
            span.set_attribute("clinicsentry.event_id", event.event_id)
            span.set_attribute("clinicsentry.session_id", event.session_id)
            span.set_attribute("clinicsentry.sequence_number", event.sequence_number)
            span.set_attribute("clinicsentry.agent_id", event.agent_id)
            span.set_attribute("clinicsentry.agent_framework", event.agent_framework)
            span.set_attribute("clinicsentry.phi_tag_count", len(event.phi_tags_detected))
            if event.risk_tier is not None:
                span.set_attribute("clinicsentry.risk_tier", event.risk_tier.value)
            if event.confidence_score is not None:
                span.set_attribute("clinicsentry.confidence_score", event.confidence_score)

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Delegate to the inner backend."""
        return self._inner.read_session(session_id)

    def _iter_session_ids(self) -> Iterator[str]:
        """Delegate to the inner backend."""
        return self._inner._iter_session_ids()
