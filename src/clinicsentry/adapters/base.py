"""Adapter ABC + a generic in-process adapter usable for testing.

The README §10 abstract interface is preserved verbatim. The default
``GenericAdapter`` implementation routes all interception points through the
configured :class:`ClinicSentry` instance and is sufficient for
framework-agnostic test coverage.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from clinicsentry.types import AuditEvent, AuditEventType

__all__ = [
    "AgentFrameworkAdapter",
    "GenericAdapter",
]

if TYPE_CHECKING:
    from clinicsentry.guard import ClinicSentry


class AgentFrameworkAdapter(ABC):
    """Adapter contract every framework integration must implement."""

    framework_name: str = "generic"

    def __init__(self, guard: ClinicSentry) -> None:
        self.guard = guard

    @abstractmethod
    async def intercept_before_llm(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sanitize messages before they reach the LLM."""

    @abstractmethod
    async def intercept_after_llm(self, response: dict[str, Any]) -> dict[str, Any]:
        """Sanitize an LLM response before it returns to the agent."""

    @abstractmethod
    async def intercept_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Sanitize tool arguments and apply minimum-necessary."""

    @abstractmethod
    async def intercept_tool_result(self, tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
        """Sanitize tool results before they enter the agent context."""

    @abstractmethod
    async def intercept_agent_message(
        self, from_agent: str, to_agent: str, message: dict[str, Any]
    ) -> dict[str, Any]:
        """Sanitize inter-agent messages."""


def _hash(value: Any) -> str:
    """Stable SHA-256 hash for arbitrary JSON-able value."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class GenericAdapter(AgentFrameworkAdapter):
    """Default adapter wiring all interception points to the firewall + audit."""

    framework_name = "generic"

    async def intercept_before_llm(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Scan and audit each message."""
        scan = self.guard.firewall.scan(messages, origin_agent=self.framework_name)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_CALL,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                input_hash=_hash(messages),
                redacted_input={"messages": scan.redacted},
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]

    async def intercept_after_llm(self, response: dict[str, Any]) -> dict[str, Any]:
        """Scan and audit the LLM response."""
        scan = self.guard.firewall.scan(response, origin_agent=self.framework_name)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.AGENT_LLM_RESPONSE,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                output_hash=_hash(response),
                redacted_output={"response": scan.redacted},
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]

    async def intercept_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Scan tool args; minimum-necessary is applied at decoration time."""
        self.guard.meddevice.assert_running()
        scan = self.guard.firewall.scan(arguments, origin_agent=tool_name)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_CALL,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                agent_id=tool_name,
                input_hash=_hash(arguments),
                redacted_input={"tool_name": tool_name, "arguments": scan.redacted},
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]

    async def intercept_tool_result(self, tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
        """Scan tool result before it re-enters the agent."""
        scan = self.guard.firewall.scan(result, origin_agent=tool_name)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.TOOL_RESULT,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                agent_id=tool_name,
                output_hash=_hash(result),
                redacted_output={"tool_name": tool_name, "result": scan.redacted},
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]

    async def intercept_agent_message(
        self, from_agent: str, to_agent: str, message: dict[str, Any]
    ) -> dict[str, Any]:
        """Scan + propagate PHI tags across an agent-to-agent boundary."""
        scan = self.guard.firewall.scan(message, origin_agent=from_agent)
        for tag in scan.tags:
            self.guard.firewall.propagation.propagate(tag.tag_id, from_agent, to_agent)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.INTER_AGENT_MESSAGE,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                agent_id=from_agent,
                output_hash=_hash(message),
                redacted_output={"to": to_agent, "message": scan.redacted},
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]
