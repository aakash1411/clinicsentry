# ADR-0008: Error and Exception Taxonomy

- **Status:** accepted
- **Date:** 2025-01-15

## Context

Exceptions thrown by middleware must be (a) catchable by host frameworks so they can degrade gracefully, (b) distinguishable from host framework errors so observability stacks can route them correctly, and (c) safe — they must never leak PHI into messages or tracebacks.

## Decision

All ClinicSentry exceptions derive from `ClinicSentryError`. The taxonomy:

```
ClinicSentryError
├── PolicyError                 # malformed policy YAML / config
├── PHIError
│   ├── PHIDetectionError       # detector internal failure
│   └── RedactionError          # redaction strategy failure
├── EscalationError
│   ├── EscalationRaised        # signals "do not proceed"; carries decision
│   └── ConfidenceComputeError  # signal computation failed
├── AuditError
│   ├── ChainIntegrityError     # hash/HMAC mismatch on verify
│   └── BackendError            # storage backend I/O failure
├── MedDeviceError
│   ├── SafetyClassViolation
│   ├── DoseOutOfRange
│   ├── AuthorizationRequired
│   └── EmergencyStopActive
└── AdapterError                # framework adapter wiring failure
```

Rules:
1. Every error message is **PHI-free** by construction: messages reference `tag_id`s and field names, never values.
2. Every error carries a `code` attribute (e.g., `"CG-PHI-001"`) for stable matching in tests and dashboards.
3. `EscalationRaised` is a **control-flow exception**, not an error — host frameworks should catch and route, not log as a failure.
4. Tracebacks across the adapter boundary are scrubbed via `__suppress_context__` to avoid leaking captured local PHI.

## Consequences

- **Positive:** uniform error handling; easy to alert on; safe by default.
- **Negative:** developers must use the typed exceptions rather than `ValueError`. We enforce via lint.
- **Neutral:** PHI scrubbing of tracebacks is a small runtime cost on the exception path only.

## References

- ADR-0002, ADR-0014.
