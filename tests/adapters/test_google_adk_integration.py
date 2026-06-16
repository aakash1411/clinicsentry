"""Real-SDK compatibility check for :class:`GoogleADKAdapter`."""

from __future__ import annotations

import pytest

try:
    import google.adk  # noqa: F401

    HAS_ADK = True
except ImportError:
    HAS_ADK = False

pytestmark = [
    pytest.mark.adapter,
    pytest.mark.skipif(not HAS_ADK, reason="google-adk not installed"),
]


def test_adk_adapter_imports_and_constructs() -> None:
    from clinicsentry import ClinicSentry
    from clinicsentry.adapters.google_adk import GoogleADKAdapter

    guard = ClinicSentry(framework="test")
    adapter = GoogleADKAdapter(guard)
    assert adapter.framework_name == "google_adk"
