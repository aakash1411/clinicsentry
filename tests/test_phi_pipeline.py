"""Tests for the detection pipeline, adversarial normalization, multilingual."""

from __future__ import annotations

from clinicsentry.phi.adversarial import AdversarialDetector, AdversarialNormalizer
from clinicsentry.phi.detectors import RegexDetector
from clinicsentry.phi.pipeline import (
    ContextFilter,
    DetectorPipeline,
    clinical_false_positive_predicate,
)


def test_pipeline_unions_hits_across_detectors() -> None:
    pipeline = DetectorPipeline(detectors=[RegexDetector(), RegexDetector()])
    hits = pipeline.detect("SSN 123-45-6789")
    # Despite two detectors emitting the same hit, dedup leaves one.
    assert len(hits) == 1
    assert hits[0].phi_type == "SSN"


def test_pipeline_applies_context_filter_to_drop_false_positives() -> None:
    pipeline = DetectorPipeline(
        detectors=[RegexDetector()],
        context_filter=ContextFilter(predicate=clinical_false_positive_predicate),
    )
    # "pulse 120-80-7777" doesn't match SSN (regex rejects 7777 sub-blocks?
    # use a real SSN preceded by "BP" context).
    hits = pipeline.detect("Resting BP 123-45-6789 reading")
    # Context predicate drops the hit because "BP" precedes the SSN-shape.
    assert hits == []


def test_pipeline_keeps_hit_when_no_disqualifying_context() -> None:
    pipeline = DetectorPipeline(
        detectors=[RegexDetector()],
        context_filter=ContextFilter(predicate=clinical_false_positive_predicate),
    )
    hits = pipeline.detect("Patient SSN 123-45-6789 needs renewal")
    assert len(hits) == 1


def test_adversarial_normalizer_strips_invisibles_and_homoglyphs() -> None:
    norm = AdversarialNormalizer()
    # 'е' is Cyrillic, zero-width space inserted between digits.
    raw = "S\u200bSN: 1\u200b23-45-6789 contact j@еxample.com"
    cleaned = norm.normalize(raw)
    assert "\u200b" not in cleaned
    assert "е" not in cleaned  # Cyrillic gone
    assert "example.com" in cleaned


def test_adversarial_detector_unmasks_homoglyph_phi() -> None:
    detector = AdversarialDetector(inner=RegexDetector())
    raw = "Patient e-mail: j@еxample.com"  # Cyrillic 'е'
    hits = detector.detect(raw)
    assert any(h.phi_type == "EMAIL" for h in hits)


def test_pipeline_with_adversarial_detector_in_chain() -> None:
    pipeline = DetectorPipeline(detectors=[AdversarialDetector(inner=RegexDetector())])
    hits = pipeline.detect("Email: j@еxample.com")
    assert len(hits) >= 1
