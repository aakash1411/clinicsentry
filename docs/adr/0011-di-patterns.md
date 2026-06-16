# ADR-0011: Dependency Injection Patterns

- **Status:** accepted
- **Date:** 2025-01-15

## Context

ClinicSentry composes ~10 collaborating objects (firewall, scorer, router, chain, backend, propagation, meddevice, adapter, key provider, attestation engine). Constructor-only DI keeps wiring explicit but bloats `ClinicSentry.__init__`. A container framework would obscure the wiring. We need a middle ground.

## Decision

- **Constructor injection** is the default. Every collaborator is a `__init__` parameter with a sensible default.
- **Defaults are constructed lazily** in private factory functions (`_default_firewall`, `_default_scorer`, etc.) in `guard.py`, so users can override one collaborator without re-specifying the rest.
- **No service-locator pattern:** there is no `ClinicSentry.get_service()`; everything is wired in `__init__`.
- **Policy is the single source of configuration:** runtime parameters are read from `PolicyConfig`; constructor parameters are object-level overrides for testing.
- **Adapters receive their `ClinicSentry` instance via constructor**, never via a module global.

This matches the "humble object" pattern: `ClinicSentry` is the only place wiring happens; all real logic is in the collaborators.

## Consequences

- **Positive:** unit tests inject mocks easily; the wiring is greppable.
- **Negative:** `ClinicSentry.__init__` is the file most likely to grow over time. Mitigated by extracting factories.
- **Neutral:** no container framework dependency.

## References

- ADR-0001.
- Fowler, "Inversion of Control Containers and the Dependency Injection pattern" (2004).
