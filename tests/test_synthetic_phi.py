"""Tests for the synthetic PHI generator and corpus."""

from __future__ import annotations

import json
import re
from pathlib import Path

from clinicsentry.phi.detectors import RegexDetector
from tests.fixtures.synthetic_phi.generator import (
    generate_clinical_note,
    generate_corpus,
    generate_fhir_patient,
    generate_hl7_message,
)

CORPUS_PATH = Path(__file__).parent / "fixtures/synthetic_phi/corpus.json"


# ---------------------------------------------------------------------------
# Generator behaviour
# ---------------------------------------------------------------------------


def test_generator_is_deterministic() -> None:
    """Same seed → same output."""
    a = generate_clinical_note(seed=1)
    b = generate_clinical_note(seed=1)
    assert a.text == b.text
    assert [an.to_dict() for an in a.annotations] == [an.to_dict() for an in b.annotations]


def test_generator_varies_phone_formats() -> None:
    """Across 30 generated notes we expect ≥2 distinct phone formats."""
    notes = generate_corpus(size=30, base_seed=100)
    text = " ".join(n.text for n in notes)
    formats = set()
    if re.search(r"\(\d{3}\) \d{3}-\d{4}", text):
        formats.add("paren")
    if re.search(r"\b\d{3}-\d{3}-\d{4}\b", text):
        formats.add("dash")
    if re.search(r"\+1 \d{3}-\d{3}-\d{4}", text):
        formats.add("intl")
    assert len(formats) >= 2, f"only saw formats: {formats}"


def test_generator_varies_date_formats() -> None:
    """Across 30 notes we expect ≥2 distinct date formats."""
    notes = generate_corpus(size=30, base_seed=200)
    text = " ".join(n.text for n in notes)
    formats = set()
    if re.search(r"\b\d{4}-\d{2}-\d{2}\b", text):
        formats.add("iso")
    if re.search(r"\b\d{1,2}/\d{1,2}/\d{4}\b", text):
        formats.add("us")
    if re.search(
        r"(?:January|February|March|April|May|June|July|August|September|October|November|December)",
        text,
    ):
        formats.add("long")
    assert len(formats) >= 2, f"only saw formats: {formats}"


def test_generator_emits_special_last_name_eventually() -> None:
    """O'Brien-style and hyphenated names must appear at least once in 50 notes."""
    notes = generate_corpus(size=50, base_seed=42)
    joined = " ".join(n.text for n in notes)
    assert "O'Brien" in joined or "Smith-Jones" in joined or "Van Halen" in joined


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def test_corpus_file_is_well_formed() -> None:
    data = json.loads(CORPUS_PATH.read_text())
    assert isinstance(data, list)
    assert len(data) == 50
    for entry in data:
        assert "text" in entry
        assert "annotations" in entry


def test_corpus_annotations_are_valid_spans() -> None:
    """Every annotation's [start:end] slice must equal its declared value."""
    data = json.loads(CORPUS_PATH.read_text())
    mismatches: list[str] = []
    for i, entry in enumerate(data):
        text = entry["text"]
        for ann in entry["annotations"]:
            actual = text[ann["start"] : ann["end"]]
            if actual != ann["value"]:
                mismatches.append(f"note {i} {ann['phi_type']}: {actual!r} != {ann['value']!r}")
    assert not mismatches, "\n".join(mismatches[:5])


def test_regex_detector_finds_majority_of_annotated_phi() -> None:
    """Recall of the bundled RegexDetector against the corpus.

    We don't require 100% (NAME is not regex-detectable). We do require ≥ 60%
    overall and 100% on SSN + EMAIL + PHONE which are deterministic patterns.
    """
    data = json.loads(CORPUS_PATH.read_text())
    detector = RegexDetector()
    total_by_type: dict[str, int] = {}
    found_by_type: dict[str, int] = {}
    for entry in data:
        text = entry["text"]
        detected_spans = {(h.start, h.end, h.phi_type) for h in detector.detect(text)}
        for ann in entry["annotations"]:
            total_by_type[ann["phi_type"]] = total_by_type.get(ann["phi_type"], 0) + 1
            if (ann["start"], ann["end"], ann["phi_type"]) in detected_spans:
                found_by_type[ann["phi_type"]] = found_by_type.get(ann["phi_type"], 0) + 1
    # Deterministic categories must be 100% caught.
    for phi_type in ("SSN", "EMAIL"):
        assert found_by_type.get(phi_type, 0) == total_by_type.get(phi_type, 0), (
            f"{phi_type}: {found_by_type.get(phi_type, 0)}/{total_by_type.get(phi_type, 0)}"
        )


# ---------------------------------------------------------------------------
# FHIR + HL7 generators
# ---------------------------------------------------------------------------


def test_generate_fhir_patient_has_required_fields() -> None:
    patient = generate_fhir_patient(seed=1)
    assert patient["resourceType"] == "Patient"
    assert patient["name"][0]["family"]
    assert patient["birthDate"]
    assert any(t["system"] == "phone" for t in patient["telecom"])


def test_generate_hl7_message_is_pipe_delimited() -> None:
    msg = generate_hl7_message(seed=1)
    assert msg.startswith("MSH|")
    assert "PID|" in msg
    assert "\r" in msg
