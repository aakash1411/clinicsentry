# ADR-0001: Module Boundaries and Dependency Direction

- **Status:** accepted
- **Date:** 2025-01-15
- **Authors:** ClinicSentry Contributors

## Context

ClinicSentry implements four orthogonal compliance concerns: PHI containment, escalation routing, audit trail integrity, and IEC 62304 device-class enforcement. These concerns must compose without coupling, because (a) regulators and customers will audit each one independently and (b) different deployments enable different subsets. Cycles between modules would make formal review intractable.

## Decision

We will enforce a strict acyclic dependency direction:

```
adapters/  ─►  guard.py  ─►  { phi/, escalation/, audit/, meddevice/ }  ─►  types.py
                                                          │
                                                          └─►  policy.py
```

- `types.py` and `policy.py` are the only modules that anything else may import without restriction.
- The four feature modules (`phi/`, `escalation/`, `audit/`, `meddevice/`) MUST NOT import from each other.
- Cross-module wiring happens exclusively in `guard.py` (the facade).
- Adapters import only `guard.py` and `types.py`; never reach into a feature module directly.
- A CI lint (`ruff` import-graph rule + a custom `tests/test_layering.py`) enforces the rule.

## Consequences

- **Positive:** each module is independently testable, replaceable, and reviewable. The facade is the only place that knows about the system as a whole.
- **Negative:** cross-cutting concerns (e.g., emitting an `AuditEvent` from inside `phi/`) must be exposed via callbacks or returned data, not direct calls. This adds a small amount of plumbing.
- **Neutral:** the facade grows in proportion to module count. We accept this in exchange for clarity at the edges.

## Alternatives Considered

- **Mediator inside `audit/`:** rejected — would make `audit/` a god-module and obscure the propagation chain.
- **Event bus:** rejected for v1 — too much indirection for four modules; revisit if module count exceeds eight.

## References

- ADR-0002 (adapter contract), ADR-0011 (DI patterns).
- Parnas, "On the Criteria To Be Used in Decomposing Systems into Modules" (1972).
