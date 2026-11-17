# Public API and Deprecation Policy

## What is public

Everything importable from the top-level package is the supported surface:

```python
from clinicsentry import (
    ClinicSentry,
    PolicyConfig,
    load_policy,
    policy_schema,
    PHIFirewall,
    PHIScanResult,
    PHIFinding,
    TokenizeResult,
    StreamRedactor,
    RedactionMode,
    register_detector,
    ClinicSentryError,
    PolicyError,
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
    EscalationDecision,
    PHITag,
    RegulatoryReport,
    minimum_necessary,
)
```

Also public, at their documented import paths:

- `clinicsentry.testing` — test fixtures and assertions (whole module)
- `clinicsentry.phi` re-exports (`DetectorPipeline`, `ContextFilter`,
  `AdversarialDetector`, `supported_locales`, …)
- the policy YAML schema (`clinicsentry policy-schema`) and the
  `CLINICSENTRY_*` environment override format
- the CLI commands and their exit codes
- audit event serialization (`AuditEvent.to_dict`) and the report schema
  (`clinicsentry.audit.report.report_schema`)

Everything else — any name starting with `_`, and modules not re-exported
above (`clinicsentry.phi.parsers`, `clinicsentry.audit.backend` internals,
adapter internals) — is implementation detail and may change in any release.

## Stability rules (pre-1.0)

- Public API changes only in **minor** releases (0.x → 0.x+1), never in
  patches.
- A removed or renamed public symbol keeps a working shim emitting
  `DeprecationWarning` for **one full minor release** before deletion, with a
  migration note in the CHANGELOG.
- Behavioral hardening that makes the library *stricter* (fail-closed
  defaults) may land in a minor release; the CHANGELOG flags each with its
  opt-out.
- From 1.0, standard SemVer applies.

## Serialization stability

Audit events, findings, and reports are written to long-retention stores, so
their serialized forms only gain fields — existing fields are never renamed or
retyped within a major version. Hash-chain canonicalization (ADR-0003) is
frozen; a change there would be a new chain version, not a mutation.
