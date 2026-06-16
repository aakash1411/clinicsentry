"""Model Context Protocol (MCP) proxy adapter.

The MCP proxy sits between an MCP client (Claude Desktop, IDE, agent) and a
tool server. Every ``tools/call`` request is scanned for PHI in both directions
and audited. Supports stdio and SSE transports.

The proxy is intentionally minimal and framework-agnostic: it expects JSON-RPC
2.0 messages and re-serializes them after scanning.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from clinicsentry.adapters.base import GenericAdapter
from clinicsentry.types import AuditEvent, AuditEventType

__all__ = ["MCPProxyAdapter"]


class MCPProxyAdapter(GenericAdapter):
    """JSON-RPC proxy that scans ``tools/call`` payloads."""

    framework_name = "mcp_proxy"

    async def handle_request(
        self,
        request_text: str,
        upstream: Callable[[str], Awaitable[str]],
    ) -> str:
        """Scan an MCP JSON-RPC request, forward upstream, scan the response.

        Args:
            request_text: raw JSON-RPC 2.0 request from the client.
            upstream: async callable that forwards to the MCP server and
                returns the response text.

        Returns:
            The (possibly redacted) JSON-RPC response string.
        """
        try:
            request = json.loads(request_text)
        except json.JSONDecodeError:
            # Forward malformed requests unchanged; let the server return JSON-RPC error.
            return await upstream(request_text)

        method = request.get("method", "")
        if method == "tools/call":
            params = request.get("params") or {}
            tool_name = params.get("name", "tool")
            arguments = params.get("arguments") or {}
            scan_in = self.guard.firewall.scan(arguments, origin_agent=tool_name)
            params["arguments"] = scan_in.redacted
            request["params"] = params
            self.guard.emit_event(
                AuditEvent(
                    event_type=AuditEventType.MCP_TOOL_CALL,
                    session_id=self.guard.session_id,
                    sequence_number=0,
                    agent_framework=self.framework_name,
                    agent_id=tool_name,
                    redacted_input={"arguments": scan_in.redacted},
                    phi_tags_detected=[t.tag_id for t in scan_in.tags],
                )
            )

        response_text = await upstream(json.dumps(request))

        if method == "tools/call":
            try:
                response = json.loads(response_text)
            except json.JSONDecodeError:
                return response_text
            result = response.get("result") or {}
            scan_out = self.guard.firewall.scan(
                result, origin_agent=request.get("params", {}).get("name", "tool")
            )
            response["result"] = scan_out.redacted
            self.guard.emit_event(
                AuditEvent(
                    event_type=AuditEventType.MCP_TOOL_CALL,
                    session_id=self.guard.session_id,
                    sequence_number=0,
                    agent_framework=self.framework_name,
                    agent_id=request.get("params", {}).get("name", "tool"),
                    redacted_output={"result": scan_out.redacted},
                    phi_tags_detected=[t.tag_id for t in scan_out.tags],
                )
            )
            return json.dumps(response)
        return response_text
