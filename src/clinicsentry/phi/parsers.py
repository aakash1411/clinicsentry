"""Structured clinical data parsers (Pass 1 of the PHI detection pipeline).

The README §6 Pass 1 calls for FHIR, HL7 v2, and DICOM parsers. We implement
schema-position based PHI detection. We do not require the heavy `fhir.resources`
dependency at runtime: detection is driven by a static field-path registry so
that arbitrary JSON payloads claiming to be FHIR are still scanned.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

__all__ = [
    "fhir_phi_paths",
    "hl7_phi_segments",
    "dicom_phi_pairs",
]

# FHIR resource_type -> list of dotted PHI field paths. Lists in paths are denoted
# by ``[*]`` and traversed across all elements.
FHIR_PHI_REGISTRY: dict[str, list[str]] = {
    "Patient": [
        "name",
        "telecom",
        "address",
        "birthDate",
        "deceasedDateTime",
        "identifier",
        "photo",
        "contact",
    ],
    "Practitioner": ["name", "telecom", "address", "identifier", "photo"],
    "Organization": ["name", "telecom", "address", "identifier"],
    "Observation": ["subject", "performer", "effectiveDateTime", "issued"],
    "Condition": ["subject", "asserter", "recordedDate", "onsetDateTime"],
    "MedicationRequest": [
        "subject",
        "requester",
        "authoredOn",
        "recorder",
    ],
    "DiagnosticReport": ["subject", "performer", "effectiveDateTime", "issued"],
    "Encounter": ["subject", "participant", "period"],
    "AllergyIntolerance": ["patient", "recorder", "asserter", "recordedDate"],
    "Procedure": ["subject", "performer", "performedDateTime"],
    "ImagingStudy": ["subject", "started", "referrer"],
    "DocumentReference": ["subject", "author", "date"],
    "Device": ["patient", "serialNumber", "udiCarrier", "owner"],
}

# HL7 v2 segment -> field index list (1-based, per HL7 convention).
HL7_PHI_REGISTRY: dict[str, list[int]] = {
    "PID": [3, 5, 6, 7, 8, 9, 11, 13, 14, 19, 20],  # IDs, names, DOB, address, phone, SSN
    "PV1": [7, 8, 9, 17, 44, 45],  # attending/referring/consulting, admit/discharge
    "IN1": [3, 4, 5, 16, 19, 36, 49],
    "NK1": [2, 4, 5, 6],
    "GT1": [3, 4, 5, 6, 7, 11, 12, 19],
    "AL1": [],  # allergens themselves are not PHI; subject linkage matters via PID
    "OBX": [],  # context dependent, leave to NLP layer
}

# DICOM tags treated as PHI per DICOM PS3.15 confidentiality profile.
DICOM_PHI_TAGS: set[tuple[int, int]] = {
    (0x0010, 0x0010),  # PatientName
    (0x0010, 0x0020),  # PatientID
    (0x0010, 0x0030),  # PatientBirthDate
    (0x0010, 0x0040),  # PatientSex
    (0x0010, 0x1000),  # OtherPatientIDs
    (0x0010, 0x1010),  # PatientAge
    (0x0008, 0x0090),  # ReferringPhysicianName
    (0x0008, 0x1050),  # PerformingPhysicianName
    (0x0008, 0x1070),  # OperatorsName
    (0x0008, 0x0080),  # InstitutionName
    (0x0008, 0x0081),  # InstitutionAddress
}


def _walk(obj: Any, path: str) -> Iterable[tuple[str, Any]]:
    """Yield ``(json_pointer, value)`` for the dotted path within ``obj``.

    Supports plain field names; lists are traversed implicitly.
    """
    parts = path.split(".") if path else []
    stack: list[tuple[str, Any, list[str]]] = [("", obj, parts)]
    while stack:
        cur_path, cur, remaining = stack.pop()
        if not remaining:
            if cur is not None:
                yield cur_path or path, cur
            continue
        head, *tail = remaining
        if isinstance(cur, list):
            for i, item in enumerate(cur):
                stack.append((f"{cur_path}[{i}]", item, [head, *tail]))
        elif isinstance(cur, dict) and head in cur:
            stack.append((f"{cur_path}.{head}" if cur_path else head, cur[head], tail))


def fhir_phi_paths(resource: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return ``(field_path, value)`` PHI hits in a FHIR resource dict."""
    rtype = resource.get("resourceType")
    if not rtype or rtype not in FHIR_PHI_REGISTRY:
        return []
    out: list[tuple[str, Any]] = []
    for path in FHIR_PHI_REGISTRY[rtype]:
        for found_path, value in _walk(resource, path):
            out.append((f"{rtype}.{found_path}", value))
    return out


def hl7_phi_segments(message: str) -> list[tuple[str, str]]:
    """Return ``(segment_field_ref, value)`` PHI hits in an HL7 v2 message."""
    out: list[tuple[str, str]] = []
    for line in message.replace("\r", "\n").splitlines():
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        seg = parts[0].strip().upper()
        indices = HL7_PHI_REGISTRY.get(seg)
        if not indices:
            continue
        for idx in indices:
            # HL7 fields are 1-indexed; for MSH the separator counts as field 1,
            # but we don't claim PHI on MSH so this offset isn't a concern here.
            if idx < len(parts):
                value = parts[idx].strip()
                if value:
                    out.append((f"{seg}-{idx}", value))
    return out


def dicom_phi_pairs(dataset: Any) -> list[tuple[str, Any]]:
    """Return ``(tag_name, value)`` PHI hits from a pydicom Dataset.

    Falls back to a no-op if pydicom is not available or input is not a Dataset.
    """
    try:
        from pydicom.dataset import Dataset
    except Exception:
        return []
    if not isinstance(dataset, Dataset):
        return []
    out: list[tuple[str, Any]] = []
    for group, element in DICOM_PHI_TAGS:
        if (group, element) in dataset:
            data_elem = dataset[(group, element)]
            out.append((str(data_elem.keyword or f"({group:04X},{element:04X})"), data_elem.value))
    return out
