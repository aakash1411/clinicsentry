# MedDevice Mode

Module 4. Enforces IEC 62304 software safety class ceilings on registration, dose-range and rate-limit checks at runtime, and an emergency-stop kill-switch.

## Classes (ADR-0006)

| `safety_class` | Permitted action tiers |
|----------------|-------------------------|
| **A** | `INFORMATIONAL` only |
| **B** | up to `ADVISORY` |
| **C** | `INTERVENTIONAL` permitted (requires clinician auth + IEC requirement id) |

## Dynamic dose ranges

When MedDevice mode is enabled, `guard.check_tool_call()` (run by every adapter before a tool executes) validates top-level tool arguments named after a declared `DoseRange`. Out-of-range or non-numeric values raise `DoseOutOfRange` and emit a `POLICY_VIOLATION` event. With `strict_dose_ranges` (default), an `INTERVENTIONAL` tool receiving a numeric argument with no declared range is also rejected. `rate_limit_per_hour` caps approved interventional calls.

## Emergency stop

`mode.emergency_stop()` sets a process-wide flag. `assert_running()` raises `EmergencyStop` (a subclass of `EmergencyStopActive`) until `mode.reset()` is called.

## Clinician authorization

A registered `INTERVENTIONAL` tool call is always escalated and blocked (`EscalationRaised`) unless a verified clinician approval is pending. Approvals are single-use and bound to the session, action, a fresh `issued_at` and a nonce; pass `arguments=` to also bind them to the exact call arguments.

```python
from clinicsentry.meddevice import sign_interventional_authorization, arguments_hash

# clinician side
sig = sign_interventional_authorization(
    key,
    action_name="adjust_insulin",
    clinician_id="dr",
    session_id=guard.session_id,
    nonce=nonce,
    issued_at=now,
    args_hash=arguments_hash(args),
)
# server side
guard.approve_interventional(
    "adjust_insulin",
    clinician_id="dr",
    signature=sig,
    nonce=nonce,
    issued_at=now,
    arguments=args,
)
```

Ed25519 tokens use `guard.approve_interventional_token(blob, sig, ClinicianAuthValidator(...))`. Nonces are tracked in a process-local `InMemoryNonceStore`; multi-replica deployments should supply a shared `NonceStore`.

## Change Impact Assessment

`build_cia(base, target)` diffs two `DeploymentSnapshot` records and flags regulator-relevant changes (class upgrade, model version change, dose-range expansion, rate-limit relaxation).

## Edition 2 mapping

`translate_to_edition2(SoftwareSafetyClass)` returns the IEC 62304 Edition 2 rigor level (I/II/III) and required documentation list.
