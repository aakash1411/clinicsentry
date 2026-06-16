"""IEC 62304 Edition 2 rigor-level mapping.

Edition 2 introduces "rigor levels" that refine the Edition 1 A/B/C
classification with additional documentation and process requirements. This
module provides a translation layer so existing :class:`SoftwareSafetyClass`
declarations can be reported in either edition without re-tagging actions.
"""

from __future__ import annotations

from dataclasses import dataclass

from clinicsentry.meddevice.mode import SoftwareSafetyClass

__all__ = ["RigorLevel", "EDITION2_MAPPING", "translate_to_edition2"]


@dataclass(frozen=True)
class RigorLevel:
    """Edition 2 rigor level descriptor."""

    code: str
    description: str
    required_documents: tuple[str, ...]


# IMDRF SaMD risk categorization, Edition 2 draft (informative).
EDITION2_MAPPING: dict[SoftwareSafetyClass, RigorLevel] = {
    SoftwareSafetyClass.A: RigorLevel(
        code="I",
        description="No injury possible — basic software lifecycle.",
        required_documents=("Software Plan", "Verification Plan"),
    ),
    SoftwareSafetyClass.B: RigorLevel(
        code="II",
        description="Non-serious injury possible — enhanced verification.",
        required_documents=(
            "Software Plan",
            "Verification Plan",
            "Architecture Document",
            "Unit + Integration Test Report",
            "Risk Management File",
        ),
    ),
    SoftwareSafetyClass.C: RigorLevel(
        code="III",
        description="Serious injury or death possible — full lifecycle.",
        required_documents=(
            "Software Plan",
            "Verification Plan",
            "Architecture Document",
            "Detailed Design",
            "Unit + Integration + System Test Reports",
            "Risk Management File",
            "Anomaly Resolution Procedure",
            "Configuration Management Plan",
        ),
    ),
}


def translate_to_edition2(cls: SoftwareSafetyClass) -> RigorLevel:
    """Return the Edition 2 :class:`RigorLevel` equivalent of ``cls``."""
    return EDITION2_MAPPING[cls]
