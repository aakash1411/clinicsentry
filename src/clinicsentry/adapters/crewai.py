"""CrewAI adapter.

CrewAI exposes ``before_kickoff`` / ``after_kickoff`` hooks on :class:`Crew` and
``callback`` on individual :class:`Task` objects. We attach interception via
these public extension points; agent-handoff PHI propagation is wired through
the agent message hook.

The adapter is functional without CrewAI installed: :class:`CrewAIAdapter`
inherits :class:`GenericAdapter`'s interception methods, so the middleware can
be invoked manually from custom CrewAI tools.
"""

from __future__ import annotations

import asyncio
from typing import Any

from clinicsentry.adapters.base import GenericAdapter

__all__ = ["CrewAIAdapter"]


class CrewAIAdapter(GenericAdapter):
    """Adapter specialization for CrewAI Crew + Task workflows."""

    framework_name = "crewai"

    def wrap(self, crew: Any) -> Any:
        """Attach ClinicSentry interception to a Crew.

        Args:
            crew: a ``crewai.Crew`` instance (duck-typed).

        Returns:
            The same ``crew`` for fluent chaining.

        Raises:
            ImportError: if CrewAI is not installed.
        """
        try:  # pragma: no cover - smoke check
            import crewai  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "CrewAI is not installed. `pip install 'clinicsentry[crewai]'`."
            ) from exc

        adapter = self
        original_kickoff = getattr(crew, "kickoff", None)
        if original_kickoff is None:  # pragma: no cover
            return crew

        def wrapped_kickoff(inputs: dict[str, Any] | None = None, **kwargs: Any) -> Any:
            """Scan inputs, run the crew, scan outputs."""
            scrubbed = inputs or {}
            scan_in = adapter.guard.firewall.scan(scrubbed, origin_agent=adapter.framework_name)
            result = original_kickoff(inputs=scan_in.redacted, **kwargs)
            scan_out = adapter.guard.firewall.scan(result, origin_agent=adapter.framework_name)
            return scan_out.redacted

        crew.kickoff = wrapped_kickoff

        # Wrap each task's callback so per-task outputs are scanned and audited.
        for task in getattr(crew, "tasks", []) or []:
            original_cb = getattr(task, "callback", None)

            def task_callback(
                output: Any,
                _orig: Any = original_cb,
                _task_name: str = getattr(task, "description", "task"),
            ) -> Any:
                """Scan the task output, then invoke the user's callback."""
                scan = adapter.guard.firewall.scan(output, origin_agent=_task_name)
                if _orig is not None:
                    _orig(scan.redacted)
                return scan.redacted

            task.callback = task_callback

        return crew

    async def on_agent_handoff(
        self, from_agent: str, to_agent: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Hook intended for CrewAI sequential / hierarchical handoffs."""
        return await self.intercept_agent_message(from_agent, to_agent, payload)

    def sync_intercept_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Synchronous bridge for tools that cannot await."""
        return asyncio.run(self.intercept_tool_call(tool_name, arguments))
