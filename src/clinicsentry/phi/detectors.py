"""PHI detection layers.

Pass 1: regex / structured detectors covering all 18 HIPAA Safe Harbor identifiers
where deterministic patterns suffice.
Pass 2 (optional): Microsoft Presidio analyzer if installed.

Detection returns a list of `Hit` records that the firewall combines with
structured-data parser hits (FHIR/HL7/DICOM) before redaction.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

__all__ = [
    "Hit",
    "RegexDetector",
    "PresidioDetector",
    "merge_hits",
]


@dataclass
class Hit:
    """A single PHI detection within a string."""

    phi_type: str
    start: int
    end: int
    value: str
    confidence: float
    source: str = "regex"


# ---------------------------------------------------------------------------
# Regex patterns — keep deliberately conservative to limit false positives.
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Separator may be a hyphen or a single space ("123 45 6789" evades
    # hyphen-only patterns); mixed separators are accepted as fail-safe.
    ("SSN", re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"), 0.99),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.99,
    ),
    (
        "PHONE",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.95,
    ),
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
        0.97,
    ),
    (
        "URL",
        re.compile(r"https?://[^\s<>\"']+"),
        0.95,
    ),
    (
        "DATE",
        re.compile(
            r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|"
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b"
        ),
        0.85,
    ),
    (
        "MRN",
        # Heuristic: explicit "MRN" / "Medical Record" prefix followed by an id.
        re.compile(
            r"\b(?:MRN|Medical\s*Record(?:\s*Number)?)[:#\s]*([A-Z0-9-]{4,20})\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    (
        "NPI",
        re.compile(r"\bNPI[:#\s]*(\d{10})\b", re.IGNORECASE),
        0.95,
    ),
    (
        "DEA",
        re.compile(r"\bDEA[:#\s]*([A-Z]{2}\d{7})\b", re.IGNORECASE),
        0.95,
    ),
    (
        "ZIP",
        # Only redact 5+4 (precise locator) — first 3 digits of plain ZIP are
        # safe-harbor compliant per 45 CFR § 164.514(b)(2)(i)(B).
        re.compile(r"\b\d{5}-\d{4}\b"),
        0.85,
    ),
]


class RegexDetector:
    """Deterministic PHI detector based on compiled regex patterns."""

    def detect(self, text: str) -> list[Hit]:
        """Return all non-overlapping high-confidence hits in `text`."""
        if not text:
            return []
        hits: list[Hit] = []
        for phi_type, pattern, conf in _PATTERNS:
            for m in pattern.finditer(text):
                hits.append(
                    Hit(
                        phi_type=phi_type,
                        start=m.start(),
                        end=m.end(),
                        value=m.group(0),
                        confidence=conf,
                        source="regex",
                    )
                )
        return _dedupe_overlaps(hits)


class PresidioDetector:
    """Optional Presidio-backed detector. No-op if presidio is not installed."""

    def __init__(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine

            self._engine: object | None = AnalyzerEngine()
        except Exception:
            self._engine = None

    @property
    def available(self) -> bool:
        """True if presidio is installed and initialized."""
        return self._engine is not None

    def detect(self, text: str, language: str = "en") -> list[Hit]:
        """Return hits from Presidio, or [] if unavailable."""
        if not self._engine or not text:
            return []
        try:
            results = self._engine.analyze(text=text, language=language)  # type: ignore[attr-defined]
        except Exception:
            return []
        out: list[Hit] = []
        for r in results:
            out.append(
                Hit(
                    phi_type=str(getattr(r, "entity_type", "UNKNOWN")),
                    start=int(getattr(r, "start", 0)),
                    end=int(getattr(r, "end", 0)),
                    value=text[int(getattr(r, "start", 0)) : int(getattr(r, "end", 0))],
                    confidence=float(getattr(r, "score", 0.5)),
                    source="presidio",
                )
            )
        return out


def _dedupe_overlaps(hits: Iterable[Hit]) -> list[Hit]:
    """Merge overlapping hits into their span union, keeping the winner's metadata.

    The winner of an overlap is the higher-confidence (then longer) hit, but
    the merged span always covers *both* hits — discarding the loser's span
    could leave a fragment of detected PHI unredacted.
    """
    ordered = sorted(hits, key=lambda h: (h.start, -(h.end - h.start), -h.confidence))
    out: list[Hit] = []
    for h in ordered:
        if out and h.start < out[-1].end:
            prev = out[-1]
            winner = (
                h
                if (h.confidence, h.end - h.start) > (prev.confidence, prev.end - prev.start)
                else prev
            )
            out[-1] = Hit(
                phi_type=winner.phi_type,
                start=min(prev.start, h.start),
                end=max(prev.end, h.end),
                value=winner.value,
                confidence=winner.confidence,
                source=winner.source,
            )
            continue
        out.append(h)
    return out


def merge_hits(*sources: Iterable[Hit]) -> list[Hit]:
    """Combine hits from multiple detectors, deduping overlaps."""
    combined: list[Hit] = []
    for src in sources:
        combined.extend(src)
    return _dedupe_overlaps(combined)
