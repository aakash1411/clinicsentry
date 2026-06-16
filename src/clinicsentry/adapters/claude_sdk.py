"""Anthropic Claude (Agents) SDK adapter.

The Claude API uses ``tool_use`` / ``tool_result`` content blocks. This adapter
wraps :func:`Anthropic.messages.create` to scan blocks in both directions.
"""

from __future__ import annotations

from typing import Any

from clinicsentry.adapters.base import GenericAdapter

__all__ = ["ClaudeSDKAdapter"]


class ClaudeSDKAdapter(GenericAdapter):
    """Adapter for ``anthropic.Anthropic`` clients."""

    framework_name = "claude_sdk"

    def wrap(self, client: Any) -> Any:
        """Patch the ``messages.create`` method on a Claude client.

        Args:
            client: an ``anthropic.Anthropic`` (or ``AsyncAnthropic``) instance.

        Returns:
            The same client with ``messages.create`` patched.

        Raises:
            ImportError: if the anthropic SDK is missing.
        """
        try:  # pragma: no cover
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "anthropic is not installed. `pip install 'clinicsentry[claude]'`."
            ) from exc

        adapter = self
        messages = client.messages
        original_create = messages.create

        def patched_create(**kwargs: Any) -> Any:
            """Scan input messages / tool blocks; then scan the response."""
            inbound = kwargs.get("messages") or []
            scan_in = adapter.guard.firewall.scan(inbound, origin_agent=adapter.framework_name)
            kwargs["messages"] = scan_in.redacted
            response = original_create(**kwargs)
            content = getattr(response, "content", None)
            if content is not None:
                scan_out = adapter.guard.firewall.scan(content, origin_agent=adapter.framework_name)
                response.content = scan_out.redacted
            return response

        messages.create = patched_create
        return client

    def scan_tool_use(self, block: dict[str, Any]) -> dict[str, Any]:
        """Synchronously scan a Claude ``tool_use`` content block."""
        scan = self.guard.firewall.scan(
            block.get("input", {}), origin_agent=block.get("name", "tool")
        )
        return {**block, "input": scan.redacted}

    def scan_tool_result(self, block: dict[str, Any]) -> dict[str, Any]:
        """Synchronously scan a Claude ``tool_result`` content block."""
        scan = self.guard.firewall.scan(
            block.get("content", ""), origin_agent=block.get("tool_use_id", "tool")
        )
        return {**block, "content": scan.redacted}
