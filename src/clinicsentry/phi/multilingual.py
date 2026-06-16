"""Multilingual detection scaffolding.

Provides per-language detector wiring. The built-in regex detector is already
language-agnostic for SSN/EMAIL/PHONE-shaped patterns. This module adds
per-language *context* rules that improve precision in non-English text.

When Presidio is installed, the analyzer is configured with the requested
language (Presidio supports en/es/fr/de/it via NLP backends).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from clinicsentry.phi.detectors import Hit
from clinicsentry.phi.pipeline import ContextFilter

__all__ = ["MultilingualDetector", "build_context_filter"]


# Per-language tokens that strongly indicate PHI in surrounding context.
_LANGUAGE_RULES: dict[str, dict[str, list[str]]] = {
    "es": {
        "NAME": ["paciente", "señor", "señora", "doctor"],
        "DATE": ["fecha de nacimiento", "nacimiento"],
        "ID": ["dni", "nss"],
    },
    "fr": {
        "NAME": ["patient", "monsieur", "madame", "docteur"],
        "DATE": ["date de naissance"],
        "ID": ["numéro de sécurité sociale"],
    },
    "zh": {
        "NAME": ["患者", "病人"],
        "DATE": ["出生日期"],
        "ID": ["身份证"],
    },
}


@dataclass
class MultilingualDetector:
    """Routes to a language-specific Presidio analyzer when available."""

    language: str = "en"
    _engine: Any | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize the Presidio analyzer for ``self.language``."""
        try:  # pragma: no cover - optional dep
            from presidio_analyzer import AnalyzerEngine

            self._engine = AnalyzerEngine(supported_languages=[self.language])
        except Exception:
            self._engine = None

    @property
    def available(self) -> bool:
        """True if Presidio loaded for the requested language."""
        return self._engine is not None

    def detect(self, text: str) -> list[Hit]:
        """Return analyzer hits in the configured language."""
        if self._engine is None:  # pragma: no cover
            return []
        results = self._engine.analyze(text=text, language=self.language)
        hits: list[Hit] = []
        for r in results:
            hits.append(
                Hit(
                    phi_type=r.entity_type,
                    start=int(r.start),
                    end=int(r.end),
                    value=text[r.start : r.end],
                    source=f"presidio:{self.language}",
                    confidence=float(r.score),
                )
            )
        return hits


def build_context_filter(language: str) -> ContextFilter:
    """Return a :class:`ContextFilter` that boosts hits with language cues.

    The filter keeps every hit but downweights candidates whose surrounding
    24-char window contains zero language-specific PHI cues (currently
    implemented as binary keep/discard at confidence < 0.5).
    """
    rules = _LANGUAGE_RULES.get(language, {})

    def predicate(text: str, hit: Hit) -> bool:
        """Keep the hit unless it's low-confidence with no contextual cue."""
        if hit.confidence >= 0.5:
            return True
        window = text[max(0, hit.start - 32) : hit.end + 32].lower()
        cues = rules.get(hit.phi_type, [])
        return any(c in window for c in cues)

    return ContextFilter(predicate=predicate)
