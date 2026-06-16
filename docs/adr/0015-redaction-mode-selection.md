# ADR-0015: Redaction Mode Selection and Per-Field Overrides

- **Status:** accepted
- **Date:** 2025-01-15

## Context

PHI can be redacted in four ways: `REDACT` (replace with a placeholder), `PSEUDONYMIZE` (stable per-session pseudonym), `GENERALIZE` (broaden the value — e.g., DOB → age band), and `SUPPRESS` (drop the field entirely). Different downstream agents need different modes: a triage agent may need pseudonymous identifiers to join records; a summarization agent may need generalized demographics; a public-facing API may need full suppression.

## Decision

- **Global default mode** is set in `PolicyConfig.phi_mode`.
- **Per-category overrides** (in `PolicyConfig.phi_overrides`) replace the default for specific PHI categories (e.g., `dob: GENERALIZE`).
- **Per-action overrides** are set on the `@register_action` decorator (`redaction_overrides={"address": "SUPPRESS"}`). Per-action wins over per-category, which wins over global default.
- **Pseudonyms are stable within a session, never across sessions** — derived from `sha256(value || session_salt)` where `session_salt = session_id`.
- **`GENERALIZE` strategies** are registered per category in `phi/generalize.py`. Unknown categories fall back to `REDACT` rather than failing — fail-safe default.
- **`SUPPRESS` always wins** if combined with another mode in the same path (defense in depth).

## Consequences

- **Positive:** operators can tune disclosure per downstream tool without code changes.
- **Negative:** three-level precedence requires clear documentation. Mitigated by `clinicsentry policy-validate` showing the resolved effective mode per category.
- **Neutral:** introducing a fifth mode (e.g., `ENCRYPT`) is a non-breaking addition.

## References

- ADR-0004, ADR-0012.
- HIPAA §164.514(b) Safe Harbor and Expert Determination methods.
