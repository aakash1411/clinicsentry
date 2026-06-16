"""Composable detection pipeline (ADR-0007's "composition operator").

A :class:`DetectorPipeline` chains multiple :class:`Detector` stages and
resolves conflicts using a configurable strategy. Each detector returns a list
of :class:`Hit`; the pipeline merges them with confidence-max conflict
resolution by default.

Formal semantics:

- Let ``D1, D2, ..., Dn`` be detector stages.
- Each ``Di(text) -> set[Hit]``.
- The pipeline computes ``H = union(D1(t), ..., Dn(t))``.
- For overlapping hits ``a, b`` (same span), keep the higher-confidence hit
  (tie → first detector wins).
- For nested hits, keep the longest span.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from clinicsentry.phi.detectors import Hit, _dedupe_overlaps

__all__ = ["Detector", "DetectorPipeline", "ContextFilter"]


class Detector(Protocol):
    """Structural type for any detector stage."""

    def detect(self, text: str) -> list[Hit]:  # pragma: no cover - protocol
        """Return hits found in ``text``."""
        ...


@dataclass
class ContextFilter:
    """False-positive filter that drops hits whose context disqualifies them.

    A hit is kept iff ``predicate(text, hit) == True``. Use this to encode
    domain-specific rules — e.g., "the digits look like an SSN but the
    immediately preceding word is 'pulse oximetry'".
    """

    predicate: Callable[[str, Hit], bool]

    def apply(self, text: str, hits: Sequence[Hit]) -> list[Hit]:
        """Return only the hits the predicate keeps."""
        return [h for h in hits if self.predicate(text, h)]


@dataclass
class DetectorPipeline:
    """Ordered collection of detectors plus optional context filter.

    The pipeline runs every detector, unions their hits, dedupes overlaps
    (keeping the highest-confidence longest span), and finally applies the
    context filter (if present).
    """

    detectors: Sequence[Detector]
    context_filter: ContextFilter | None = None

    def detect(self, text: str) -> list[Hit]:
        """Run the pipeline on ``text``."""
        aggregated: list[Hit] = []
        for d in self.detectors:
            aggregated.extend(d.detect(text))
        merged = _dedupe_overlaps(aggregated)
        if self.context_filter is not None:
            return self.context_filter.apply(text, merged)
        return merged


# --- Common context predicates -------------------------------------------


def clinical_false_positive_predicate(text: str, hit: Hit) -> bool:
    """Reject hits with surrounding tokens that strongly indicate non-PHI.

    Drops:

    - SSN-shaped digits preceded by "pulse" / "BP" / "rate" (vital signs).
    - Date-shaped tokens preceded by "year" (relative ages, not DOBs).
    """
    window = text[max(0, hit.start - 24) : hit.start].lower()
    if hit.phi_type in {"SSN"} and any(k in window for k in (" pulse", " bp", " rate ")):
        return False
    return not (hit.phi_type in {"DATE", "DOB"} and " year " in window)


__all__ += ["clinical_false_positive_predicate"]
