# MedDevice Mode

Module 4. Enforces IEC 62304 software safety class ceilings on registration, dose-range and rate-limit checks at runtime, and an emergency-stop kill-switch.

## Classes (ADR-0006)

| `safety_class` | Permitted action tiers |
|----------------|-------------------------|
| **A** | `INFORMATIONAL` only |
| **B** | up to `ADVISORY` |
| **C** | `INTERVENTIONAL` permitted (requires clinician auth + IEC requirement id) |

## Dynamic dose ranges

`DoseRange(parameter, min_value, max_value)` is checked on every clinical action that records a dose. Out-of-range values raise `DoseOutOfRange`.

## Emergency stop

`mode.emergency_stop()` sets a process-wide flag. `assert_running()` raises `EmergencyStopActive` until `mode.reset()` is called.

## Clinician authorization

Class B/C `INTERVENTIONAL` actions require a signed `AuthorizationToken` validated by `ClinicianAuthValidator`. The token includes a per-session nonce to prevent replay.

## Change Impact Assessment

`build_cia(base, target)` diffs two `DeploymentSnapshot` records and flags regulator-relevant changes (class upgrade, model version change, dose-range expansion, rate-limit relaxation).

## Edition 2 mapping

`translate_to_edition2(SoftwareSafetyClass)` returns the IEC 62304 Edition 2 rigor level (I/II/III) and required documentation list.
