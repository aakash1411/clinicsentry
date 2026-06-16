"""LangGraph adapter (best-effort).

LangGraph is an optional dependency. The adapter exposes the same interface as
:class:`GenericAdapter` and provides a ``wrap`` helper that, when LangGraph is
present, registers ``before_node`` / ``after_node`` callbacks on a StateGraph.

If LangGraph is not installed, ``wrap`` raises :class:`ImportError` while the
adapter's interception methods remain functional for use as in-process
middleware (e.g., callable from custom node implementations).
"""

from __future__ import annotations

from typing import Any

from clinicsentry.adapters.base import GenericAdapter

__all__ = [
    "LangGraphAdapter",
]


class LangGraphAdapter(GenericAdapter):
    """Adapter specialization for LangGraph StateGraph workflows."""

    framework_name = "langgraph"

    def wrap(self, graph: Any) -> Any:  # pragma: no cover - thin LangGraph integration
        """Attach ClinicSentry interception to a StateGraph instance.

        We monkey-patch the graph's compiled ``ainvoke`` / ``invoke`` to scan I/O.
        A future revision should switch to LangGraph's official callback handlers
        once their public API stabilizes (target: ``langgraph >= 0.3``).
        """
        try:
            from langgraph.graph import StateGraph  # noqa: F401
        except Exception as exc:  # pragma: no cover
            raise ImportError(
                "LangGraph is not installed. `pip install clinicsentry[langgraph]`."
            ) from exc

        original_invoke = getattr(graph, "invoke", None)
        original_ainvoke = getattr(graph, "ainvoke", None)
        adapter = self

        if original_invoke is not None:

            def wrapped_invoke(state: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
                scanned = adapter.guard.firewall.scan(state, origin_agent=adapter.framework_name)
                result = original_invoke(scanned.redacted, *args, **kwargs)
                out_scan = adapter.guard.firewall.scan(result, origin_agent=adapter.framework_name)
                return out_scan.redacted

            graph.invoke = wrapped_invoke

        if original_ainvoke is not None:

            async def wrapped_ainvoke(state: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
                scanned = adapter.guard.firewall.scan(state, origin_agent=adapter.framework_name)
                result = await original_ainvoke(scanned.redacted, *args, **kwargs)
                out_scan = adapter.guard.firewall.scan(result, origin_agent=adapter.framework_name)
                return out_scan.redacted

            graph.ainvoke = wrapped_ainvoke

        return graph
