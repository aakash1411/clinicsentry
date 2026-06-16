"""Real-SDK compatibility check for :class:`ClaudeSDKAdapter`."""

from __future__ import annotations

import pytest

try:
    import anthropic  # noqa: F401

    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_ANTHROPIC, reason="anthropic not installed"),
]


def test_claude_adapter_imports_and_constructs() -> None:
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.claude_sdk import ClaudeSDKAdapter

    guard = ClinicSentry(framework="test")
    adapter = ClaudeSDKAdapter(guard)
    assert adapter.framework_name == "claude_sdk"
