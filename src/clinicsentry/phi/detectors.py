"""PHI detection layers.

Pass 1: regex / structured detectors covering the HIPAA Safe Harbor identifiers
where deterministic patterns suffice (see docs/phi-coverage.md for the matrix).
Pass 2 (optional): Microsoft Presidio analyzer if installed.

Detection returns a list of `Hit` records that the firewall combines with
structured-data parser hits (FHIR/HL7/DICOM) before redaction.

Detectors are described by :class:`PatternSpec` entries. ``group`` selects the
regex group whose span is redacted — label-anchored detectors (``DEVICE_ID``,
``FAX``, …) redact only the identifier and keep the anchor readable. An
optional ``validator`` runs a checksum over the matched value (NHS mod-11,
IBAN mod-97, Luhn) so high-collision numeric formats stay precise.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

__all__ = [
    "Hit",
    "PatternSpec",
    "RegexDetector",
    "PresidioDetector",
    "merge_hits",
    "core_specs",
    "extra_specs",
    "known_labels",
    "resolve_specs",
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


@dataclass(frozen=True)
class PatternSpec:
    """One deterministic detector: label, pattern, and match semantics."""

    label: str
    pattern: re.Pattern[str]
    confidence: float
    group: int = 0
    validator: Callable[[str], bool] | None = None


# ---------------------------------------------------------------------------
# Core patterns (enabled by default) — deliberately conservative on false
# positives; identifier-bearing formats without a reliable shape are anchored
# on an explicit label token.
# ---------------------------------------------------------------------------

_CORE_SPECS: list[PatternSpec] = [
    # Separator may be a hyphen or a single space ("123 45 6789" evades
    # hyphen-only patterns); mixed separators are accepted as fail-safe.
    PatternSpec(
        "SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        0.99,
    ),
    PatternSpec(
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.99,
    ),
    PatternSpec(
        "PHONE",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.95,
    ),
    PatternSpec(
        "FAX",
        re.compile(
            r"\bfax(?:\s*(?:no\.?|number|#))?\b[\s:#.-]*"
            r"((?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b",
            re.IGNORECASE,
        ),
        0.96,
        group=1,
    ),
    PatternSpec(
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
        0.97,
    ),
    PatternSpec(
        "URL",
        re.compile(r"https?://[^\s<>\"']+"),
        0.95,
    ),
    PatternSpec(
        "DATE",
        re.compile(
            r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|"
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b"
        ),
        0.85,
    ),
    PatternSpec(
        "MRN",
        # Heuristic: explicit "MRN" / "Medical Record" prefix followed by an id.
        re.compile(
            r"\b(?:MRN|Medical\s*Record(?:\s*Number)?)[:#\s]*([A-Z0-9-]{4,20})\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    PatternSpec(
        "NPI",
        re.compile(r"\bNPI[:#\s]*(\d{10})\b", re.IGNORECASE),
        0.95,
    ),
    PatternSpec(
        "DEA",
        re.compile(r"\bDEA[:#\s]*([A-Z]{2}\d{7})\b", re.IGNORECASE),
        0.95,
    ),
    PatternSpec(
        "ZIP",
        # Only redact 5+4 (precise locator) — first 3 digits of plain ZIP are
        # safe-harbor compliant per 45 CFR § 164.514(b)(2)(i)(B).
        re.compile(r"\b\d{5}-\d{4}\b"),
        0.85,
    ),
    # HIPAA §164.514(b)(2)(i)(N): device identifiers and serial numbers.
    # Anchored so document ids / catalog refs ("manual US-DBA-2500685") pass.
    PatternSpec(
        "DEVICE_ID",
        re.compile(
            r"\b(?:serial(?:\s*(?:no\.?|number|#))?|s/n|sn|device\s*id"
            r"|lot(?:\s*(?:no\.?|number|#))?)\b"
            r"[\s:#.-]*([A-Za-z0-9][A-Za-z0-9-]{4,19})\b",
            re.IGNORECASE,
        ),
        0.92,
        group=1,
    ),
    PatternSpec(
        "UDI",
        re.compile(
            r"\bUDI\b[\s:#.-]*((?:\([0-9]{2}\)[A-Za-z0-9]+)+|[A-Za-z0-9-]{10,})",
            re.IGNORECASE,
        ),
        0.95,
        group=1,
    ),
    # HIPAA (9): account numbers.
    PatternSpec(
        "ACCOUNT",
        re.compile(
            r"\b(?:account|acct)\s*(?:no\.?|number|#|id)?\b[\s:#.-]*([0-9][0-9-]{5,19})\b",
            re.IGNORECASE,
        ),
        0.90,
        group=1,
    ),
    # HIPAA (8): health plan beneficiary numbers. The id/no/number token is
    # required so prose like "privacy policy 2024" is not matched.
    PatternSpec(
        "MEMBER_ID",
        re.compile(
            r"\b(?:member|subscriber|beneficiary|policy|health\s*plan)\s*"
            r"(?:id|no\.?|number|#)\b[\s:#.-]*([A-Za-z0-9][A-Za-z0-9-]{5,19})\b",
            re.IGNORECASE,
        ),
        0.90,
        group=1,
    ),
]

# ---------------------------------------------------------------------------
# Opt-in extras (unanchored formats with residual false-positive risk).
# Enable via policy `phi_firewall.detectors: [..., "VIN"]`.
# ---------------------------------------------------------------------------

_EXTRA_SPECS: list[PatternSpec] = [
    # HIPAA (11): vehicle identifiers. 17 chars, no I/O/Q, must mix letters
    # and digits so pure numeric ids don't match.
    PatternSpec(
        "VIN",
        re.compile(
            r"\b(?=[A-HJ-NPR-Z0-9]{17}\b)(?=[A-HJ-NPR-Z0-9]*\d)"
            r"(?=[A-HJ-NPR-Z0-9]*[A-HJ-NPR-Z])[A-HJ-NPR-Z0-9]{17}\b"
        ),
        0.85,
    ),
]


def core_specs() -> list[PatternSpec]:
    """Return the default-enabled detector specs."""
    return list(_CORE_SPECS)


def extra_specs() -> list[PatternSpec]:
    """Return the opt-in detector specs (enable via ``detectors`` config)."""
    return list(_EXTRA_SPECS)


def known_labels() -> set[str]:
    """Return every built-in detector label, including locale packs."""
    from clinicsentry.phi.locales import locale_specs, supported_locales

    labels = {s.label for s in _CORE_SPECS} | {s.label for s in _EXTRA_SPECS}
    for locale in supported_locales():
        labels |= {s.label for s in locale_specs(locale)}
    return labels


def resolve_specs(
    detectors: Sequence[str] | None = None,
    locales: Sequence[str] = (),
) -> list[PatternSpec]:
    """Resolve the active spec list from config.

    ``locales`` adds each locale pack to the default set. ``detectors``, when
    given, is authoritative: exactly those labels are enabled (drawn from core,
    extras, and any locale pack).
    """
    from clinicsentry.phi.locales import locale_specs

    pool: dict[str, PatternSpec] = {s.label: s for s in _CORE_SPECS}
    for s in _EXTRA_SPECS:
        pool.setdefault(s.label, s)
    active = [s.label for s in _CORE_SPECS]
    for locale in locales:
        for s in locale_specs(locale):
            pool.setdefault(s.label, s)
            active.append(s.label)
    if detectors is not None:
        unknown = [d for d in detectors if d not in pool]
        if unknown:
            raise ValueError(f"unknown detector label(s): {unknown}; known: {sorted(pool)}")
        active = list(detectors)
    seen: set[str] = set()
    out: list[PatternSpec] = []
    for label in active:
        if label not in seen:
            seen.add(label)
            out.append(pool[label])
    return out


class RegexDetector:
    """Deterministic PHI detector driven by a list of :class:`PatternSpec`."""

    def __init__(self, specs: Sequence[PatternSpec] | None = None) -> None:
        self.specs = list(specs) if specs is not None else core_specs()

    def detect(self, text: str) -> list[Hit]:
        """Return all non-overlapping high-confidence hits in `text`."""
        if not text:
            return []
        hits: list[Hit] = []
        for spec in self.specs:
            for m in spec.pattern.finditer(text):
                value = m.group(spec.group)
                if value is None:
                    continue
                if spec.validator is not None and not spec.validator(value):
                    continue
                hits.append(
                    Hit(
                        phi_type=spec.label,
                        start=m.start(spec.group),
                        end=m.end(spec.group),
                        value=value,
                        confidence=spec.confidence,
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
