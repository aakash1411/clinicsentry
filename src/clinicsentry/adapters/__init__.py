"""Framework adapters.

All adapters subclass :class:`AgentFrameworkAdapter` and are functional even if
the corresponding upstream SDK is not installed — only the ``wrap`` /
``install`` methods raise :class:`ImportError` in that case.
"""

from clinicsentry.adapters.a2a import A2AInterceptor
from clinicsentry.adapters.base import AgentFrameworkAdapter, GenericAdapter
from clinicsentry.adapters.claude_sdk import ClaudeSDKAdapter
from clinicsentry.adapters.crewai import CrewAIAdapter
from clinicsentry.adapters.google_adk import GoogleADKAdapter
from clinicsentry.adapters.langgraph import LangGraphAdapter
from clinicsentry.adapters.mcp_proxy import MCPProxyAdapter
from clinicsentry.adapters.openai_agents import OpenAIAgentsAdapter

__all__ = [
    "AgentFrameworkAdapter",
    "GenericAdapter",
    "A2AInterceptor",
    "ClaudeSDKAdapter",
    "CrewAIAdapter",
    "GoogleADKAdapter",
    "LangGraphAdapter",
    "MCPProxyAdapter",
    "OpenAIAgentsAdapter",
]
