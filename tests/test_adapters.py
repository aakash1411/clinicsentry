"""Unit tests for the framework adapter ecosystem.

Each adapter is exercised against a mock framework harness so the test suite
runs without the heavy upstream SDKs installed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from clinicsentry import ClinicSentry
from clinicsentry.adapters import (
    A2AInterceptor,
    ClaudeSDKAdapter,
    CrewAIAdapter,
    GenericAdapter,
    GoogleADKAdapter,
    MCPProxyAdapter,
    OpenAIAgentsAdapter,
)


@pytest.fixture
def guard() -> ClinicSentry:
    return ClinicSentry(framework="test")


# --- Generic adapter sanity check ----------------------------------------


def test_generic_adapter_intercepts_before_llm_redacts_ssn(guard: ClinicSentry) -> None:
    adapter = GenericAdapter(guard)
    msgs = [{"role": "user", "content": "Patient SSN 123-45-6789 requested refill."}]
    out = asyncio.run(adapter.intercept_before_llm(msgs))
    assert "[REDACTED:SSN]" in json.dumps(out)


def test_generic_adapter_propagation_records_edge(guard: ClinicSentry) -> None:
    adapter = GenericAdapter(guard)
    msg = {"summary": "patient email j@example.com"}
    asyncio.run(adapter.intercept_agent_message("agent_a", "agent_b", msg))
    # Propagation graph should now contain at least one edge originating in agent_a.
    edges = guard.propagation.edges
    assert any(("agent_a", "agent_b") in edge_list for edge_list in edges.values())


# --- CrewAI ---------------------------------------------------------------


class _FakeTask:
    def __init__(self, description: str) -> None:
        self.description = description
        self.callback: Any = None


class _FakeCrew:
    def __init__(self) -> None:
        self.tasks = [_FakeTask("triage")]
        self.kicked_off_with: dict[str, Any] | None = None

    def kickoff(self, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
        self.kicked_off_with = inputs
        return {"answer": "patient email j@example.com"}


def test_crewai_adapter_wraps_kickoff_and_scans_io(
    guard: ClinicSentry, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pretend CrewAI is installed.
    import sys
    import types

    fake = types.ModuleType("crewai")
    monkeypatch.setitem(sys.modules, "crewai", fake)

    adapter = CrewAIAdapter(guard)
    crew = adapter.wrap(_FakeCrew())
    result = crew.kickoff(inputs={"note": "SSN 123-45-6789"})
    assert "[REDACTED:SSN]" in json.dumps(crew.kicked_off_with)
    assert "[REDACTED:EMAIL]" in json.dumps(result)


# --- Google ADK -----------------------------------------------------------


class _FakeADKAgent:
    before_model_callback: Any = None
    after_model_callback: Any = None
    before_tool_callback: Any = None
    after_tool_callback: Any = None


def test_google_adk_adapter_attaches_callbacks(
    guard: ClinicSentry, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    pkg = types.ModuleType("google")
    adk = types.ModuleType("google.adk")
    pkg.adk = adk  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", pkg)
    monkeypatch.setitem(sys.modules, "google.adk", adk)

    adapter = GoogleADKAdapter(guard)
    agent = adapter.wrap(_FakeADKAgent())
    assert callable(agent.before_model_callback)
    assert callable(agent.after_tool_callback)

    # Exercise the before-tool callback with PHI.
    class _Tool:
        name = "lookup"

    redacted = agent.before_tool_callback(
        tool=_Tool(), args={"q": "SSN 111-22-3333"}, tool_context=None
    )
    assert "[REDACTED:SSN]" in json.dumps(redacted)


# --- OpenAI Agents --------------------------------------------------------


def test_openai_agents_build_run_hooks_returns_hooks_object(guard: ClinicSentry) -> None:
    adapter = OpenAIAgentsAdapter(guard)
    hooks = __import__(
        "clinicsentry.adapters.openai_agents", fromlist=["build_run_hooks"]
    ).build_run_hooks(adapter)
    assert hasattr(hooks, "on_tool_start")
    assert hasattr(hooks, "on_tool_end")
    assert hasattr(hooks, "on_agent_handoff")


# --- Claude SDK -----------------------------------------------------------


class _FakeClaudeResponse:
    def __init__(self, content: list[dict[str, Any]]) -> None:
        self.content = content


class _FakeClaudeMessages:
    def __init__(self) -> None:
        self.last_kwargs: dict[str, Any] | None = None

    def create(self, **kwargs: Any) -> _FakeClaudeResponse:
        self.last_kwargs = kwargs
        return _FakeClaudeResponse(
            content=[{"type": "text", "text": "Contact patient at j@example.com"}]
        )


class _FakeClaudeClient:
    def __init__(self) -> None:
        self.messages = _FakeClaudeMessages()


def test_claude_sdk_adapter_scans_messages_create(
    guard: ClinicSentry, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    monkeypatch.setitem(sys.modules, "anthropic", types.ModuleType("anthropic"))

    adapter = ClaudeSDKAdapter(guard)
    client = adapter.wrap(_FakeClaudeClient())
    response = client.messages.create(messages=[{"role": "user", "content": "SSN 123-45-6789"}])
    assert "[REDACTED:SSN]" in json.dumps(client.messages.last_kwargs)
    assert "[REDACTED:EMAIL]" in json.dumps(response.content)


# --- MCP Proxy ------------------------------------------------------------


def test_mcp_proxy_scans_tools_call(guard: ClinicSentry) -> None:
    adapter = MCPProxyAdapter(guard)

    forwarded: dict[str, str] = {}

    async def upstream(req: str) -> str:
        forwarded["req"] = req
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"text": "Contact j@example.com"},
            }
        )

    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"q": "SSN 123-45-6789"}},
        }
    )
    response_text = asyncio.run(adapter.handle_request(req, upstream))
    assert "[REDACTED:SSN]" in forwarded["req"]
    assert "[REDACTED:EMAIL]" in response_text


def test_mcp_proxy_forwards_unknown_methods_unchanged(guard: ClinicSentry) -> None:
    adapter = MCPProxyAdapter(guard)

    async def upstream(req: str) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    response = asyncio.run(adapter.handle_request(req, upstream))
    assert json.loads(response)["result"]["ok"] is True


# --- A2A interceptor ------------------------------------------------------


def test_a2a_interceptor_records_propagation_and_audit(guard: ClinicSentry) -> None:
    interceptor = A2AInterceptor(guard)
    redacted = asyncio.run(
        interceptor.on_message(
            from_agent="triage",
            to_agent="dosing",
            message={"summary": "SSN 123-45-6789 needs basal review"},
            session_correlation_id="corr-123",
        )
    )
    assert "[REDACTED:SSN]" in json.dumps(redacted)
    # Verify an a2a_message audit event was recorded.
    events = list(guard.audit_backend.read_session(guard.session_id))
    assert any(e.event_type.value == "a2a_message" for e in events)
