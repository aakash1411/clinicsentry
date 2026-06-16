# PHI Firewall

The PHI Firewall is Module 1. It scans every dict, list, or string that crosses an adapter boundary, detects PHI, and replaces matches with one of four redaction modes (`REDACT`, `PSEUDONYMIZE`, `GENERALIZE`, `SUPPRESS`).

## Detection layers

- **Regex** — SSN, EMAIL, PHONE, MRN, DOB. Conservative patterns.
- **Presidio** (optional) — analyzer-engine, language-aware.
- **FHIR / HL7 / DICOM parsers** — schema-aware: a value at a known PHI path is tagged even if it doesn't match a regex.
- **Detector pipeline** (`DetectorPipeline`) — composable union with context-filter false-positive suppression.
- **Adversarial normalizer** — strips zero-width characters and remaps homoglyphs before further detection.
- **Multilingual** — per-language Presidio plus contextual cues (es/fr/zh).
- **Clinical NER** — scispaCy for names/locations, Med7 for medications.
- **DICOM OCR** — Tesseract over pixel arrays for burned-in PHI.

## Redaction modes (ADR-0015)

| Mode | Behavior | Use case |
|------|----------|----------|
| `REDACT` | `[REDACTED:CATEGORY]` placeholder | default; safest for LLM prompts |
| `PSEUDONYMIZE` | stable per-session token | join records across an agent run |
| `GENERALIZE` | broaden to age band, ZIP3 | analytics, public APIs |
| `SUPPRESS` | drop the field entirely | strict minimum-disclosure |

## Propagation graph

The firewall is paired with `PropagationGraph` — every PHI tag carries metadata identifying which agents have seen it. Cross-agent leakage is auditable from the regulatory report (see [Audit Trail](audit-trail.md)).

## API

See the [API reference](../api.md#phi) for `PHIFirewall`, `apply_redaction`,
and the full PHI surface.
