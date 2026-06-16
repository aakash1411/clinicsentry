"""Google ADK (Agent Development Kit) adapter.

Google ADK exposes ``before_model_callback`` / ``after_model_callback`` on each
:class:`Agent` and tool-execution callbacks via the runner. We attach
interception through these public extension points.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from clinicsentry.adapters.base import GenericAdapter

__all__ = ["GoogleADKAdapter"]


class GoogleADKAdapter(GenericAdapter):
    """Adapter specialization for Google ADK agents."""

    framework_name = "google_adk"

    def wrap(self, agent: Any) -> Any:
        """Attach callbacks to a ``google.adk.Agent`` instance.

        Args:
            agent: an ADK Agent instance (duck-typed).

        Returns:
            The same ``agent`` for fluent chaining.

        Raises:
            ImportError: if google-adk is not installed.
        """
        try:  # pragma: no cover
            import google.adk  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "Google ADK is not installed. `pip install 'clinicsentry[adk]'`."
            ) from exc

        adapter = self
        agent.before_model_callback = self._make_before_model_cb(adapter)
        agent.after_model_callback = self._make_after_model_cb(adapter)
        agent.before_tool_callback = self._make_before_tool_cb(adapter)
        agent.after_tool_callback = self._make_after_tool_cb(adapter)
        return agent

    @staticmethod
    def _make_before_model_cb(adapter: GoogleADKAdapter) -> Callable[..., Any]:
        """Build an ADK before-model callback closing over ``adapter``."""

        def cb(*, callback_context: Any, llm_request: Any) -> None:
            """Scan request contents in place."""
            contents = getattr(llm_request, "contents", None)
            if contents is None:
                return
            scan = adapter.guard.firewall.scan(contents, origin_agent=adapter.framework_name)
            llm_request.contents = scan.redacted

        return cb

    @staticmethod
    def _make_after_model_cb(adapter: GoogleADKAdapter) -> Callable[..., Any]:
        """Build an ADK after-model callback."""

        def cb(*, callback_context: Any, llm_response: Any) -> None:
            """Scan the model response in place."""
            content = getattr(llm_response, "content", None)
            if content is None:
                return
            scan = adapter.guard.firewall.scan(content, origin_agent=adapter.framework_name)
            llm_response.content = scan.redacted

        return cb

    @staticmethod
    def _make_before_tool_cb(adapter: GoogleADKAdapter) -> Callable[..., Any]:
        """Build an ADK before-tool callback."""

        def cb(*, tool: Any, args: dict[str, Any], tool_context: Any) -> dict[str, Any]:
            """Scan tool args; minimum-necessary applies at decoration time."""
            adapter.guard.meddevice.assert_running()
            scan = adapter.guard.firewall.scan(args, origin_agent=getattr(tool, "name", "tool"))
            return scan.redacted  # type: ignore[no-any-return]

        return cb

    @staticmethod
    def _make_after_tool_cb(adapter: GoogleADKAdapter) -> Callable[..., Any]:
        """Build an ADK after-tool callback."""

        def cb(*, tool: Any, args: dict[str, Any], tool_context: Any, tool_response: Any) -> Any:
            """Scan tool result before it re-enters the agent context."""
            scan = adapter.guard.firewall.scan(
                tool_response, origin_agent=getattr(tool, "name", "tool")
            )
            return scan.redacted

        return cb
