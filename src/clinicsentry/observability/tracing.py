"""OTEL span helper that degrades to a no-op when OTEL is absent."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

__all__ = ["span"]


@contextlib.contextmanager
def span(name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
    """Yield an active OTEL span if opentelemetry-api is installed, else None.

    Usage::

        with span("clinicsentry.firewall.scan", {"phi_count": 3}) as s:
            ...  # work; ``s`` may be None when OTEL is absent
    """
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("clinicsentry")
        with tracer.start_as_current_span(name) as current:
            for k, v in (attributes or {}).items():
                current.set_attribute(f"clinicsentry.{k}", v)
            yield current
    except ImportError:
        yield None
