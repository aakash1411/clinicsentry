"""Change Impact Assessment (CIA) generator.

Given two deployment snapshots, produce a structured CIA report that maps each
delta to the IEC 62304 software safety class and identifies regulator-flagging
changes (model version, configuration risk, dose range expansion, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from clinicsentry.meddevice.mode import SoftwareSafetyClass

__all__ = ["DeploymentSnapshot", "ChangeImpactAssessment", "build_cia"]


@dataclass
class DeploymentSnapshot:
    """A point-in-time deployment configuration.

    Snapshots are version-controlled artifacts (JSON) so a CIA report can be
    regenerated from any two historical points.
    """

    version: str
    model_versions: dict[str, str] = field(default_factory=dict)
    safety_class: SoftwareSafetyClass = SoftwareSafetyClass.A
    dose_ranges: dict[str, tuple[float, float]] = field(default_factory=dict)
    rate_limit_per_hour: int | None = None
    enabled_actions: list[str] = field(default_factory=list)
    policy_version: str = ""
    intended_use: str = ""

    def diff_keys(self, other: DeploymentSnapshot) -> dict[str, tuple[Any, Any]]:
        """Return per-attribute diffs from ``other`` to ``self``."""
        diffs: dict[str, tuple[Any, Any]] = {}
        for attr in (
            "version",
            "safety_class",
            "rate_limit_per_hour",
            "policy_version",
            "intended_use",
            "enabled_actions",
            "model_versions",
            "dose_ranges",
        ):
            old = getattr(other, attr)
            new = getattr(self, attr)
            if old != new:
                diffs[attr] = (old, new)
        return diffs


@dataclass
class ChangeImpactAssessment:
    """Structured CIA result; serializable into the regulatory report."""

    base_version: str
    target_version: str
    diffs: dict[str, tuple[Any, Any]]
    regulator_flags: list[str]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "base_version": self.base_version,
            "target_version": self.target_version,
            "diffs": {k: list(v) for k, v in self.diffs.items()},
            "regulator_flags": list(self.regulator_flags),
            "summary": self.summary,
        }


def build_cia(
    base: DeploymentSnapshot,
    target: DeploymentSnapshot,
) -> ChangeImpactAssessment:
    """Produce a CIA report for the transition ``base -> target``.

    Regulator flags are raised for:
    - safety class upgrade (e.g. A → B),
    - new model versions on any role,
    - any dose-range expansion (max increased),
    - rate-limit relaxation (limit raised or removed).
    """
    diffs = target.diff_keys(base)
    flags: list[str] = []

    if "safety_class" in diffs:
        old, new = diffs["safety_class"]
        if _class_rank(new) > _class_rank(old):
            flags.append("safety_class_upgrade")

    if "model_versions" in diffs:
        flags.append("model_version_change")

    if "dose_ranges" in diffs:
        for role, new_range in target.dose_ranges.items():
            old_range = base.dose_ranges.get(role)
            if old_range is None or new_range[1] > old_range[1]:
                flags.append(f"dose_range_expansion:{role}")

    if "rate_limit_per_hour" in diffs:
        old, new = diffs["rate_limit_per_hour"]
        if old is not None and (new is None or new > old):
            flags.append("rate_limit_relaxation")

    summary = (
        f"{len(diffs)} attribute(s) changed between {base.version} and "
        f"{target.version}; {len(flags)} regulator flag(s) raised."
    )
    return ChangeImpactAssessment(
        base_version=base.version,
        target_version=target.version,
        diffs=diffs,
        regulator_flags=flags,
        summary=summary,
    )


def _class_rank(cls: SoftwareSafetyClass) -> int:
    """Order A < B < C."""
    return {SoftwareSafetyClass.A: 0, SoftwareSafetyClass.B: 1, SoftwareSafetyClass.C: 2}[cls]
