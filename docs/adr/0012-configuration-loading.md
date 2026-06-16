# ADR-0012: Configuration Loading Rules

- **Status:** accepted
- **Date:** 2025-01-15

## Context

Operators need three configuration modes: a YAML file (production), environment overrides (containers), and programmatic construction (tests, embedded use). These must compose predictably without surprising precedence rules.

## Decision

- **Precedence (lowest → highest):** built-in defaults → YAML file → environment variables (prefixed `CLINICSENTRY_`) → programmatic constructor kwargs.
- **Schema:** `PolicyConfig` is a Pydantic model. Unknown keys are rejected (Pydantic `extra="forbid"`); typos fail at load time.
- **Env var format:** `CLINICSENTRY_<SECTION>_<KEY>`, e.g., `CLINICSENTRY_AUDIT_BACKEND=postgres`. Nested keys use double underscore.
- **Secrets:** never read from YAML. Secrets (HMAC keys, DB passwords, HSM PINs) MUST come from env vars or a `KeyProvider`.
- **Validation timing:** all validation happens at `load_policy`; runtime never has to defensively re-check.
- **Reload:** policy is immutable per `ClinicSentry` instance. Hot reload is a non-goal (operators restart the process).

## Consequences

- **Positive:** unambiguous precedence; secrets are out of source control by construction; bad config fails fast.
- **Negative:** no live reload — operators accept the restart model.
- **Neutral:** the schema serves as documentation; `clinicsentry policy-validate` runs the same validator.

## References

- ADR-0011, ADR-0014.
