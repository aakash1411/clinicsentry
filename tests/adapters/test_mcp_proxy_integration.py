"""Real-SDK compatibility check for :class:`MCPProxyAdapter`."""

from __future__ import annotations

import pytest

try:
    import mcp  # noqa: F401

    HAS_MCP = True
except ImportError:
    HAS_MCP = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_MCP, reason="mcp not installed"),
]


def test_mcp_proxy_adapter_imports_and_constructs() -> None:
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.mcp_proxy import MCPProxyAdapter

    guard = ClinicSentry(framework="test")
    adapter = MCPProxyAdapter(guard)
    assert adapter.framework_name == "mcp_proxy"
