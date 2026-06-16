"""Composite confidence scoring (README §7).

Implements the four signal sources defined by the spec:
1. LLM self-reported uncertainty extracted from reasoning text.
2. Factual grounding via clinical vocabulary cross-reference.
3. Hallucination risk (drug-name MISMATCH check, [R10]).
4. Input completeness against registered required fields.

Vocabularies are pluggable via the `ClinicalVocabulary` interface so users may
swap in RxNorm / ICD-10 / SNOMED-CT loaders without touching scoring logic.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

__all__ = [
    "ClinicalVocabulary",
    "InMemoryVocabulary",
    "ConfidenceInputs",
    "ConfidenceResult",
    "ConfidenceScorer",
]


class ClinicalVocabulary(Protocol):
    """Abstract clinical vocabulary lookup."""

    def contains(self, term: str) -> bool:  # pragma: no cover - protocol
        """Return True if ``term`` is recognized as a clinical-vocabulary entry."""
        ...


@dataclass
class InMemoryVocabulary:
    """Simple set-backed vocabulary suitable for tests / small policies."""

    terms: set[str] = field(default_factory=set)

    def contains(self, term: str) -> bool:
        """Case-insensitive membership test."""
        return term.lower() in self.terms

    @classmethod
    def from_iterable(cls, items: Iterable[str]) -> InMemoryVocabulary:
        """Build from any iterable of strings."""
        return cls(terms={t.lower() for t in items})


_CONFIDENCE_PATTERNS = [
    re.compile(r"confidence[:\s]+(\d{1,3})\s*%", re.IGNORECASE),
    re.compile(r"(\d{1,3})\s*%\s*confiden", re.IGNORECASE),
]
# Drug-shaped tokens: capitalized words ending in common pharma suffixes, or all-caps INNs.
_DRUG_TOKEN = re.compile(
    r"\b([A-Z][a-z]+(?:cillin|mycin|olol|pril|sartan|statin|azole|prazole|formin)|"
    r"[A-Z]{4,})\b"
)
# Casual ICD-10 token shape (e.g., E11.9, I10).
_ICD10_TOKEN = re.compile(r"\b([A-TV-Z][0-9][0-9AB](?:\.[0-9A-Z]{1,4})?)\b")


@dataclass
class ConfidenceInputs:
    """Inputs collected at agent decision time for confidence scoring."""

    output_text: str = ""
    reasoning_text: str = ""
    provided_fields: set[str] = field(default_factory=set)
    required_fields: set[str] = field(default_factory=set)
    drug_vocab: ClinicalVocabulary | None = None
    icd_vocab: ClinicalVocabulary | None = None


@dataclass
class ConfidenceResult:
    """Aggregate confidence + per-signal breakdown."""

    score: float
    breakdown: dict[str, float]


class ConfidenceScorer:
    """Aggregate the four signal scores into a composite confidence value."""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        default_when_unscored: float = 0.7,
    ) -> None:
        """Configure signal weights (must be non-negative, will be normalized)."""
        self.weights = weights or {
            "self_reported": 0.25,
            "grounding": 0.30,
            "hallucination": 0.30,
            "completeness": 0.15,
        }
        negative = {k: v for k, v in self.weights.items() if v < 0}
        if negative:
            raise ValueError(f"confidence weights must be non-negative, got {negative}")
        if sum(self.weights.values()) <= 0:
            raise ValueError("confidence weights must not all be zero")
        if not 0.0 <= default_when_unscored <= 1.0:
            raise ValueError(
                f"default_when_unscored must be in [0, 1], got {default_when_unscored}"
            )
        self.default_when_unscored = default_when_unscored

    def score(self, inputs: ConfidenceInputs) -> ConfidenceResult:
        """Compute composite confidence.

        Missing signals (returned as -1 by the helpers) are excluded from the
        weighted average. If every signal is missing, fall back to the
        configured ``default_when_unscored`` value.
        """
        breakdown = {
            "self_reported": _self_reported(inputs.reasoning_text),
            "grounding": _grounding(inputs.output_text, inputs.icd_vocab),
            "hallucination": _hallucination(inputs.output_text, inputs.drug_vocab),
            "completeness": _completeness(inputs.provided_fields, inputs.required_fields),
        }
        present = {k: v for k, v in breakdown.items() if v >= 0}
        if not present:
            return ConfidenceResult(score=self.default_when_unscored, breakdown=breakdown)
        weighted_sum = sum(v * self.weights.get(k, 0) for k, v in present.items())
        total_weight = sum(self.weights.get(k, 0) for k in present) or 1.0
        score = weighted_sum / total_weight
        return ConfidenceResult(score=max(0.0, min(1.0, score)), breakdown=breakdown)


def _self_reported(text: str) -> float:
    """Signal 1: parse explicit confidence percentages from reasoning."""
    if not text:
        return -1.0
    matches: list[float] = []
    for pat in _CONFIDENCE_PATTERNS:
        for m in pat.finditer(text):
            try:
                pct = float(m.group(1))
            except ValueError:
                continue
            if 0 <= pct <= 100:
                matches.append(pct / 100.0)
    if not matches:
        return -1.0
    return sum(matches) / len(matches)


def _grounding(text: str, icd_vocab: ClinicalVocabulary | None) -> float:
    """Signal 2: fraction of ICD-10-shaped tokens that exist in the vocab."""
    if not text or icd_vocab is None:
        return -1.0
    tokens = _ICD10_TOKEN.findall(text)
    if not tokens:
        return -1.0
    valid = sum(1 for t in tokens if icd_vocab.contains(t))
    return valid / len(tokens)


def _hallucination(text: str, drug_vocab: ClinicalVocabulary | None) -> float:
    """Signal 3: MISMATCH-style drug-name verification (1.0 = none hallucinated)."""
    if not text or drug_vocab is None:
        return -1.0
    tokens = _DRUG_TOKEN.findall(text)
    if not tokens:
        return -1.0
    valid = sum(1 for t in tokens if drug_vocab.contains(t))
    return valid / len(tokens)


def _completeness(provided: set[str], required: set[str]) -> float:
    """Signal 4: fraction of required input fields that were provided."""
    if not required:
        return -1.0
    return len(provided & required) / len(required)
