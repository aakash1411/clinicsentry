"""Real-SDK compatibility check for :class:`OpenAIAgentsAdapter`."""

from __future__ import annotations

import pytest

try:
    import agents  # noqa: F401  # the openai-agents SDK module name

    HAS_OPENAI_AGENTS = True
except ImportError:
    HAS_OPENAI_AGENTS = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_OPENAI_AGENTS, reason="openai-agents not installed"),
]


def test_openai_agents_adapter_imports_and_constructs() -> None:
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.openai_agents import OpenAIAgentsAdapter

    guard = ClinicSentry(framework="test")
    adapter = OpenAIAgentsAdapter(guard)
    assert adapter.framework_name == "openai_agents"
