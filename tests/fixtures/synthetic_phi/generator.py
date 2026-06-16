"""Deterministic synthetic clinical-data generator.

Uses :mod:`random` with explicit seeds so the same input seed always yields
the same output. Produces realistic-but-fake clinical notes that vary across:

- Phone formats: ``(555) 123-4567``, ``555-123-4567``, ``+1 555-123-4567``
- Name structures: first-last, last-first, hyphenated, apostrophe (O'Brien)
- Date formats: ISO ``2024-01-15``, US ``01/15/2024``, long ``January 15, 2024``

All identifiers are computer-generated. No real patient data is reproduced.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

__all__ = [
    "Annotation",
    "GeneratedNote",
    "generate_clinical_note",
    "generate_fhir_patient",
    "generate_hl7_message",
    "generate_corpus",
]


@dataclass
class Annotation:
    """Ground-truth PHI span inside a generated note."""

    phi_type: str
    start: int
    end: int
    value: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "phi_type": self.phi_type,
            "start": self.start,
            "end": self.end,
            "value": self.value,
        }


@dataclass
class GeneratedNote:
    """A synthetic clinical note plus annotations of its embedded PHI."""

    text: str
    annotations: list[Annotation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for corpus dumps."""
        return {
            "text": self.text,
            "annotations": [a.to_dict() for a in self.annotations],
        }


# ---------------------------------------------------------------------------
# Vocabulary (intentionally small + obviously fake)
# ---------------------------------------------------------------------------

_FIRST_NAMES = [
    "Avery",
    "Briar",
    "Casey",
    "Devon",
    "Ellis",
    "Finley",
    "Gale",
    "Harper",
    "Iris",
    "Jordan",
]
_LAST_NAMES = [
    "Adler",
    "Blake",
    "Carter",
    "Dunn",
    "Ellis",
    "Frost",
    "Greene",
    "Holt",
    "Ives",
    "Jordan",
]
# Hyphenated and apostrophe edge cases.
_LAST_NAMES_SPECIAL = ["O'Brien", "Smith-Jones", "Van Halen", "Mc'Cartney"]
_DIAGNOSES = [
    "type 2 diabetes mellitus",
    "essential hypertension",
    "asthma",
    "chronic kidney disease, stage 3",
    "atrial fibrillation",
]


def _format_phone(rng: random.Random) -> str:
    """Return a phone number in one of three formats."""
    area = rng.randint(200, 999)
    pre = rng.randint(200, 999)
    line = rng.randint(0, 9999)
    style = rng.choice(["dash", "paren", "intl"])
    if style == "dash":
        return f"{area}-{pre:03d}-{line:04d}"
    if style == "paren":
        return f"({area}) {pre:03d}-{line:04d}"
    return f"+1 {area}-{pre:03d}-{line:04d}"


def _format_date(rng: random.Random, base: date) -> str:
    """Return a date in one of three formats."""
    style = rng.choice(["iso", "us", "long"])
    if style == "iso":
        return base.isoformat()
    if style == "us":
        return base.strftime("%m/%d/%Y")
    return base.strftime("%B %-d, %Y") if hasattr(base, "strftime") else base.isoformat()


def _pick_name(rng: random.Random) -> str:
    """Return a person name, occasionally using a special-case last name."""
    first = rng.choice(_FIRST_NAMES)
    if rng.random() < 0.3:
        return f"{first} {rng.choice(_LAST_NAMES_SPECIAL)}"
    return f"{first} {rng.choice(_LAST_NAMES)}"


def _format_ssn(rng: random.Random) -> str:
    """SSN in canonical 3-2-4 dash format (regex-friendly)."""
    a = rng.randint(100, 665)
    b = rng.randint(10, 99)
    c = rng.randint(1000, 9999)
    return f"{a}-{b}-{c}"


def _format_email(rng: random.Random, name: str) -> str:
    """Email derived from name; lowercase, ascii-only."""
    handle = "".join(ch for ch in name.lower() if ch.isalnum() or ch == ".")
    domain = rng.choice(["example.com", "synthetic.test", "demo.org"])
    return f"{handle}@{domain}"


def _annotate(text: str, phi_type: str, value: str) -> Annotation | None:
    """Return an :class:`Annotation` for the first occurrence of ``value`` in ``text``."""
    start = text.find(value)
    if start < 0:
        return None
    return Annotation(phi_type=phi_type, start=start, end=start + len(value), value=value)


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------


def generate_clinical_note(seed: int) -> GeneratedNote:
    """Generate one synthetic clinical note with embedded PHI annotations."""
    rng = random.Random(seed)
    name = _pick_name(rng)
    dob = date(2000, 1, 1) + timedelta(days=rng.randint(-15000, 8000))
    dob_str = _format_date(rng, dob)
    visit = date(2024, 1, 1) + timedelta(days=rng.randint(0, 365))
    visit_str = _format_date(rng, visit)
    phone = _format_phone(rng)
    ssn = _format_ssn(rng)
    email = _format_email(rng, name)
    mrn = f"{rng.randint(10_000_000, 99_999_999)}"
    diagnosis = rng.choice(_DIAGNOSES)

    text = (
        f"Patient {name} (DOB: {dob_str}) presented on {visit_str} for follow-up "
        f"of {diagnosis}. MRN: {mrn}. Contact: {phone}, {email}. "
        f"SSN on file: {ssn}. Plan reviewed; no acute distress."
    )

    annotations: list[Annotation] = []
    for phi_type, value in [
        ("NAME", name),
        ("DATE", dob_str),
        ("DATE", visit_str),
        ("MRN", mrn),
        ("PHONE", phone),
        ("EMAIL", email),
        ("SSN", ssn),
    ]:
        ann = _annotate(text, phi_type, value)
        if ann is not None:
            annotations.append(ann)
    return GeneratedNote(text=text, annotations=annotations)


def generate_fhir_patient(seed: int) -> dict[str, Any]:
    """Generate a minimal FHIR R4 Patient resource (synthetic)."""
    rng = random.Random(seed)
    name = _pick_name(rng)
    first, _, last = name.partition(" ")
    dob = date(2000, 1, 1) + timedelta(days=rng.randint(-15000, 8000))
    return {
        "resourceType": "Patient",
        "id": f"synthetic-{seed}",
        "name": [{"family": last, "given": [first]}],
        "birthDate": dob.isoformat(),
        "telecom": [
            {"system": "phone", "value": _format_phone(rng)},
            {"system": "email", "value": _format_email(rng, name)},
        ],
        "identifier": [
            {"system": "urn:oid:2.16.840.1.113883.4.1", "value": _format_ssn(rng)},
        ],
    }


def generate_hl7_message(seed: int) -> str:
    """Generate a minimal HL7 v2 ADT^A01 message (synthetic, pipe-delimited)."""
    rng = random.Random(seed)
    name = _pick_name(rng)
    first, _, last = name.partition(" ")
    dob = date(2000, 1, 1) + timedelta(days=rng.randint(-15000, 8000))
    return (
        f"MSH|^~\\&|EHR|HOSP|RCV|FAC|20240101120000||ADT^A01|MSG{seed}|P|2.5\r"
        f"PID|1||{rng.randint(10_000_000, 99_999_999)}||{last}^{first}||"
        f"{dob.strftime('%Y%m%d')}|M|||123 Main St^^Springfield^IL^62701||"
        f"{_format_phone(rng)}|||||||{_format_ssn(rng)}\r"
    )


def generate_corpus(size: int = 50, base_seed: int = 42) -> list[GeneratedNote]:
    """Generate a deterministic corpus of ``size`` clinical notes."""
    return [generate_clinical_note(base_seed + i) for i in range(size)]
