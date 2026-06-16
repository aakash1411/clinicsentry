"""Clinical NER detectors (scispaCy + Med7).

Both detectors are optional: they require ``clinicsentry[nlp-medical]``. If
the dependency is missing, the detector reports itself as unavailable and
:meth:`detect` returns an empty list — never raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from clinicsentry.phi.detectors import Hit

__all__ = ["ScispacyDetector", "Med7Detector"]


@dataclass
class ScispacyDetector:
    """scispaCy NER for clinical entities (DISEASE, PERSON, ORG)."""

    model_name: str = "en_core_sci_sm"
    _nlp: Any | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Lazily load the spaCy model; tolerate absent dependency."""
        try:  # pragma: no cover - heavy optional dep
            import spacy

            self._nlp = spacy.load(self.model_name)
        except Exception:
            self._nlp = None

    @property
    def available(self) -> bool:
        """True if the model loaded successfully."""
        return self._nlp is not None

    def detect(self, text: str) -> list[Hit]:
        """Return PERSON-like hits the model identifies."""
        if self._nlp is None:  # pragma: no cover - depends on optional install
            return []
        doc = self._nlp(text)
        out: list[Hit] = []
        for ent in doc.ents:
            if ent.label_ not in {"PERSON", "GPE", "ORG"}:
                continue
            out.append(
                Hit(
                    phi_type="NAME" if ent.label_ == "PERSON" else "LOCATION",
                    start=ent.start_char,
                    end=ent.end_char,
                    value=ent.text,
                    source="scispacy",
                    confidence=0.85,
                )
            )
        return out


@dataclass
class Med7Detector:
    """Med7 NER for medication entities (DRUG, DOSAGE, STRENGTH).

    Used by the hallucination signal to verify that the LLM's drug names
    appear in a clinical vocabulary.
    """

    model_name: str = "en_core_med7_lg"
    _nlp: Any | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Lazily load the model."""
        try:  # pragma: no cover - heavy optional dep
            import spacy

            self._nlp = spacy.load(self.model_name)
        except Exception:
            self._nlp = None

    @property
    def available(self) -> bool:
        """True if the model loaded successfully."""
        return self._nlp is not None

    def detect_drugs(self, text: str) -> list[str]:
        """Return the unique drug surface forms in ``text``."""
        if self._nlp is None:  # pragma: no cover
            return []
        doc = self._nlp(text)
        return list({ent.text.lower() for ent in doc.ents if ent.label_ == "DRUG"})

    def detect(self, text: str) -> list[Hit]:
        """Return medication entities as :class:`Hit` records (low PHI relevance)."""
        if self._nlp is None:  # pragma: no cover
            return []
        doc = self._nlp(text)
        out: list[Hit] = []
        for ent in doc.ents:
            out.append(
                Hit(
                    phi_type="MEDICATION",
                    start=ent.start_char,
                    end=ent.end_char,
                    value=ent.text,
                    source="med7",
                    confidence=0.75,
                )
            )
        return out
