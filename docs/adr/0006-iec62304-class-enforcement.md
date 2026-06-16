# ADR-0006: IEC 62304 Class Enforcement Formal Model

- **Status:** accepted
- **Date:** 2025-01-15

## Context

IEC 62304 classifies medical-device software into Class A (no injury possible), Class B (non-serious injury possible), and Class C (serious injury or death possible). Each class entails progressively more rigorous lifecycle controls. ClinicSentry must (a) refuse to register actions inconsistent with the declared device class and (b) generate evidence that the right controls were applied.

## Decision

We model the class as a runtime invariant rather than a documentation artifact:

- The device class is declared in policy (`meddevice.safety_class`).
- Every registered action declares a `ClinicalRiskTier` (`ADVISORY`, `DECISION_SUPPORT`, `AUTONOMOUS`).
- `MedDeviceMode.validate_registration(action)` rejects registrations whose tier exceeds the class ceiling:

  | safety_class | max tier permitted        |
  |--------------|---------------------------|
  | A            | ADVISORY                  |
  | B            | DECISION_SUPPORT          |
  | C            | AUTONOMOUS                |

- Class C registrations additionally require `iec62304_requirement` (a traceability id linking to a documented requirement).
- Class B and C `AUTONOMOUS` actions require a clinician authorization signature at runtime (`MedDeviceMode.require_authorization`).

The `RegulatoryReport` includes an IEC 62304 section listing every registered action, its tier, requirement id, and authorization evidence.

## Consequences

- **Positive:** the device class is enforced, not aspirational. Misuse fails fast at registration time.
- **Negative:** users must declare a class before registering any action — minor onboarding friction.
- **Neutral:** Edition 2 of IEC 62304 (when adopted) adds rigor levels; we add a translation table in ADR-0014 rather than restructure.

## Alternatives Considered

- **Documentation-only class declaration:** rejected — undermines the entire point of the module.
- **Per-action override of class:** rejected — defeats the ceiling guarantee.

## References

- IEC 62304:2006 + Amd 1:2015, §4.3, §5.
- ADR-0011 (DI), ADR-0013 (observability).
