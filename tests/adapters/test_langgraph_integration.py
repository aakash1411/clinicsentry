"""Real-SDK compatibility check for :class:`LangGraphAdapter`."""

from __future__ import annotations

import pytest

try:
    import langgraph  # noqa: F401

    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_LANGGRAPH, reason="langgraph not installed"),
]


def test_langgraph_adapter_imports_and_constructs() -> None:
    """The adapter must import and construct without touching the SDK."""
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.langgraph import LangGraphAdapter

    guard = ClinicSentry(framework="test")
    adapter = LangGraphAdapter(guard)
    assert adapter.framework_name == "langgraph"


def test_langgraph_adapter_wrap_accepts_invoke_compatible_object() -> None:
    """The ``wrap`` method must accept any object with ``invoke`` / ``ainvoke``."""
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.langgraph import LangGraphAdapter

    class _MinimalGraph:
        def invoke(self, state: dict, *_a: object, **_kw: object) -> dict:
            return state

        async def ainvoke(self, state: dict, *_a: object, **_kw: object) -> dict:
            return state

    guard = ClinicSentry(framework="test")
    adapter = LangGraphAdapter(guard)
    wrapped = adapter.wrap(_MinimalGraph())
    assert wrapped is not None
    # The wrapped invoke must be callable and pass through the result.
    result = wrapped.invoke({"k": "v"})
    assert result == {"k": "v"}
