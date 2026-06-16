"""Real-SDK compatibility check for :class:`CrewAIAdapter`."""

from __future__ import annotations

import pytest

try:
    import crewai  # noqa: F401

    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_CREWAI, reason="crewai not installed"),
]


def test_crewai_adapter_imports_and_constructs() -> None:
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.crewai import CrewAIAdapter

    guard = ClinicSentry(framework="test")
    adapter = CrewAIAdapter(guard)
    assert adapter.framework_name == "crewai"
