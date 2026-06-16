"""Agent-to-Agent (A2A) interceptor.

A2A is Google's open protocol for inter-agent communication. We intercept
messages crossing an A2A boundary, scan their payloads, and update the
propagation graph so cross-agent PHI flow is traceable in the audit report.
"""

from __future__ import annotations

from typing import Any

from clinicsentry.adapters.base import GenericAdapter
from clinicsentry.types import AuditEvent, AuditEventType

__all__ = ["A2AInterceptor"]


class A2AInterceptor(GenericAdapter):
    """Session-tagging layer for A2A protocol messages."""

    framework_name = "a2a"

    async def on_message(
        self,
        *,
        from_agent: str,
        to_agent: str,
        message: dict[str, Any],
        session_correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Scan an A2A message, propagate PHI tags, audit, and return the redacted payload.

        Args:
            from_agent: agent id of the sender.
            to_agent: agent id of the receiver.
            message: the A2A message payload.
            session_correlation_id: optional cross-session correlation token.

        Returns:
            The redacted message ready to forward.
        """
        scan = self.guard.firewall.scan(message, origin_agent=from_agent)
        for tag in scan.tags:
            self.guard.firewall.propagation.propagate(tag.tag_id, from_agent, to_agent)
        self.guard.emit_event(
            AuditEvent(
                event_type=AuditEventType.A2A_MESSAGE,
                session_id=self.guard.session_id,
                sequence_number=0,
                agent_framework=self.framework_name,
                agent_id=from_agent,
                redacted_output={
                    "to": to_agent,
                    "message": scan.redacted,
                    "correlation_id": session_correlation_id,
                },
                phi_tags_detected=[t.tag_id for t in scan.tags],
            )
        )
        return scan.redacted  # type: ignore[no-any-return]
