# Adapters

ClinicSentry ships with adapters for the major agent frameworks. All conform to the [`AgentFrameworkAdapter`](api.md#clinicsentry.adapters.base.AgentFrameworkAdapter) ABC (ADR-0002).

| Framework | Class | Extras | Install |
|-----------|-------|--------|---------|
| Generic | `GenericAdapter` | — | builtin |
| LangGraph | `LangGraphAdapter` | `langgraph` | `pip install 'clinicsentry[langgraph]'` |
| CrewAI | `CrewAIAdapter` | `crewai` | `pip install 'clinicsentry[crewai]'` |
| Google ADK | `GoogleADKAdapter` | `adk` | `pip install 'clinicsentry[adk]'` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `openai-agents` | `pip install 'clinicsentry[openai-agents]'` |
| Anthropic Claude SDK | `ClaudeSDKAdapter` | `claude` | `pip install 'clinicsentry[claude]'` |
| MCP Proxy | `MCPProxyAdapter` | `mcp` | `pip install 'clinicsentry[mcp]'` |
| A2A | `A2AInterceptor` | — | builtin |

## Stability contract

The ABC is a v1 contract: additive only within 1.x. New interception methods may be added with default no-op implementations; existing methods are never removed or re-signatured. See ADR-0002.

## Adapter authoring

A new adapter is approximately 80 lines:

1. Subclass `GenericAdapter`.
2. Set `framework_name`.
3. Implement `wrap(framework_object)` to install hooks via the framework's callback/extension API.

See [`LangGraphAdapter`](https://github.com/aakash1411/clinicsentry/blob/main/src/clinicsentry/adapters/langgraph.py) or [`GoogleADKAdapter`](https://github.com/aakash1411/clinicsentry/blob/main/src/clinicsentry/adapters/google_adk.py) for reference.
