"""OpenAI Agents SDK adapter.

The OpenAI Agents SDK exposes :class:`RunHooks` with hooks for
``on_tool_start``, ``on_tool_end``, ``on_agent_handoff``, and
``on_run_start``/``on_run_end``. We provide a :class:`OpenAIAgentsRunHooks`
implementation that delegates to the :class:`OpenAIAgentsAdapter`.
"""

from __future__ import annotations

from typing import Any

from clinicsentry.adapters.base import GenericAdapter

__all__ = ["OpenAIAgentsAdapter", "build_run_hooks"]


class OpenAIAgentsAdapter(GenericAdapter):
    """Adapter specialization for the OpenAI Agents SDK."""

    framework_name = "openai_agents"

    def wrap(self, runner: Any) -> Any:
        """Attach hooks to an ``agents.Runner`` instance.

        Args:
            runner: a ``Runner`` or compatible orchestrator.

        Returns:
            The runner with hooks attached.

        Raises:
            ImportError: if the agents SDK is missing.
        """
        try:  # pragma: no cover
            import agents  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "openai-agents is not installed. `pip install 'clinicsentry[openai-agents]'`."
            ) from exc
        runner.hooks = build_run_hooks(self)
        return runner


def build_run_hooks(adapter: OpenAIAgentsAdapter) -> Any:
    """Return a ``RunHooks`` instance wired to ``adapter``.

    Defined as a function rather than a class to defer the SDK import.
    """
    base: type
    try:  # pragma: no cover
        from agents import RunHooks as _RunHooks

        base = _RunHooks
    except ImportError:  # pragma: no cover
        base = object

    class _Hooks(base):  # type: ignore[misc]
        """RunHooks subclass that routes everything through ClinicSentry."""

        async def on_run_start(self, *args: Any, **kwargs: Any) -> None:
            """No-op; session_start is already emitted by ClinicSentry.__init__."""

        async def on_run_end(self, *args: Any, **kwargs: Any) -> None:
            """No-op; users call ``guard.end_session()`` explicitly."""

        async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
            """Pre-tool: scan tool inputs and audit."""
            args = getattr(context, "tool_arguments", {}) or {}
            scanned = await adapter.intercept_tool_call(getattr(tool, "name", "tool"), args)
            if hasattr(context, "tool_arguments"):
                context.tool_arguments = scanned

        async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> Any:
            """Post-tool: scan tool outputs and audit."""
            return await adapter.intercept_tool_result(
                getattr(tool, "name", "tool"),
                result if isinstance(result, dict) else {"value": result},
            )

        async def on_agent_handoff(
            self, context: Any, from_agent: Any, to_agent: Any, payload: Any
        ) -> Any:
            """Propagate PHI tags across handoffs."""
            data = payload if isinstance(payload, dict) else {"value": payload}
            return await adapter.intercept_agent_message(
                getattr(from_agent, "name", "from"),
                getattr(to_agent, "name", "to"),
                data,
            )

    return _Hooks()
