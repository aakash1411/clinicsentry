"""Happy-path coverage for PHI detectors that depend on heavy optional libs.

Each section is gated on a fresh import probe so the module can be loaded
without any of the optional NLP / OCR dependencies installed. In CI, a
dedicated matrix job installs ``clinicsentry[nlp-medical,ocr,phi]`` plus the
spaCy / Med7 model wheels and runs this file with ``--no-cov`` so the heavy
import time doesn't pollute the inner-loop coverage gate.
"""

from __future__ import annotations

import importlib.util
from typing import Any

import pytest


def _have(*module_names: str) -> bool:
    """True iff every named module is importable in the current interpreter."""
    return all(importlib.util.find_spec(m) is not None for m in module_names)


# ---------------------------------------------------------------------------
# scispaCy / Med7
# ---------------------------------------------------------------------------

_HAS_SPACY = _have("spacy")


@pytest.mark.slow
@pytest.mark.skipif(not _HAS_SPACY, reason="spacy not installed")
class TestScispacyDetector:
    """Happy path for :class:`ScispacyDetector` (requires ``en_core_sci_sm``)."""

    def _make(self) -> Any:
        from clinicsentry.phi.medical_ner import ScispacyDetector

        return ScispacyDetector(model_name="en_core_sci_sm")

    def test_detector_available_when_model_installed(self) -> None:
        det = self._make()
        if not det.available:
            pytest.skip("en_core_sci_sm model not downloaded")
        assert det.available

    def test_detects_person_in_clinical_text(self) -> None:
        det = self._make()
        if not det.available:
            pytest.skip("en_core_sci_sm model not downloaded")
        hits = det.detect("Patient Jane Doe presented with chest pain.")
        assert any(h.phi_type == "NAME" for h in hits)


@pytest.mark.slow
@pytest.mark.skipif(not _HAS_SPACY, reason="spacy not installed")
class TestMed7Detector:
    """Happy path for :class:`Med7Detector` (requires ``en_core_med7_lg``)."""

    def _make(self) -> Any:
        from clinicsentry.phi.medical_ner import Med7Detector

        return Med7Detector(model_name="en_core_med7_lg")

    def test_detector_available_when_model_installed(self) -> None:
        det = self._make()
        if not det.available:
            pytest.skip("en_core_med7_lg model not downloaded")
        assert det.available

    def test_detects_drugs(self) -> None:
        det = self._make()
        if not det.available:
            pytest.skip("en_core_med7_lg model not downloaded")
        drugs = det.detect_drugs("Patient takes metformin 500mg twice daily.")
        assert any("metformin" in d.lower() for d in drugs)


# ---------------------------------------------------------------------------
# Presidio multilingual
# ---------------------------------------------------------------------------

_HAS_PRESIDIO = _have("presidio_analyzer")


@pytest.mark.slow
@pytest.mark.skipif(not _HAS_PRESIDIO, reason="presidio-analyzer not installed")
class TestMultilingualDetector:
    """Happy path for :class:`MultilingualDetector`."""

    def test_en_detector_available(self) -> None:
        from clinicsentry.phi.multilingual import MultilingualDetector

        det = MultilingualDetector(language="en")
        if not det.available:
            pytest.skip("presidio engine failed to construct")
        assert det.available

    def test_en_detector_finds_email(self) -> None:
        from clinicsentry.phi.multilingual import MultilingualDetector

        det = MultilingualDetector(language="en")
        if not det.available:
            pytest.skip("presidio engine failed to construct")
        hits = det.detect("Contact patient at jane@example.com")
        assert any(h.phi_type in {"EMAIL_ADDRESS", "EMAIL"} for h in hits)


def test_multilingual_context_filter_drops_low_confidence_without_cue() -> None:
    """Pure-Python context filter — no Presidio needed."""
    from clinicsentry.phi.detectors import Hit
    from clinicsentry.phi.multilingual import build_context_filter

    cf = build_context_filter("es")
    low_no_cue = Hit(phi_type="NAME", start=0, end=4, value="Juan", confidence=0.3)
    assert cf.apply("Juan went home", [low_no_cue]) == []
    low_with_cue = Hit(phi_type="NAME", start=9, end=13, value="Juan", confidence=0.3)
    kept = cf.apply("paciente Juan acudio", [low_with_cue])
    assert kept == [low_with_cue]


def test_multilingual_context_filter_keeps_high_confidence() -> None:
    """High-confidence hits skip the cue check."""
    from clinicsentry.phi.detectors import Hit
    from clinicsentry.phi.multilingual import build_context_filter

    cf = build_context_filter("es")
    high = Hit(phi_type="NAME", start=0, end=4, value="Juan", confidence=0.9)
    assert cf.apply("Juan went home", [high]) == [high]


# ---------------------------------------------------------------------------
# DICOM pixel OCR
# ---------------------------------------------------------------------------

_HAS_TESSERACT = _have("pytesseract", "PIL")


@pytest.mark.slow
@pytest.mark.skipif(not _HAS_TESSERACT, reason="pytesseract / PIL not installed")
def test_ocr_detector_returns_empty_on_no_pixel_array() -> None:
    """Edge case the detector must handle: dataset without pixel_array."""
    from clinicsentry.phi.ocr import DICOMPixelOCRDetector

    class _Dataset:
        pixel_array = None

    det = DICOMPixelOCRDetector()
    assert det.detect(_Dataset()) == []


@pytest.mark.slow
@pytest.mark.skipif(not _HAS_TESSERACT, reason="pytesseract / PIL not installed")
def test_ocr_detector_handles_invalid_array_gracefully() -> None:
    """An object whose pixel_array conversion throws must not crash."""
    from clinicsentry.phi.ocr import DICOMPixelOCRDetector

    class _Broken:
        @property
        def pixel_array(self) -> Any:
            raise RuntimeError("synthetic failure")

    det = DICOMPixelOCRDetector()
    # The implementation catches Exception and returns [].
    assert det.detect(_Broken()) == []
