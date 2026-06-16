# ADR-0014: Security Boundaries and Threat Model Scope

- **Status:** accepted
- **Date:** 2025-01-15

## Context

ClinicSentry is middleware. It cannot defend against a hostile process running as the same Unix user (which can read its memory) nor against a malicious operator who replaces the binary. We must state explicitly what is in and out of scope so we don't oversell the security posture.

## Decision

### In Scope

1. **PHI containment within a single process boundary:** detectors prevent PHI from being shipped to upstream LLMs or downstream tools through the adapter interception points.
2. **Audit chain integrity against an honest operator:** tamper attempts on the audit log are detected by `verify()`.
3. **Compromised LLM output:** hallucination, prompt-injection-induced PHI exposure, and confidence-signal manipulation are mitigated by the escalation router.
4. **Compromised tool input:** minimum-necessary enforcement and propagation tracking limit blast radius.
5. **Class-violation by buggy host code:** registration-time validation refuses to enable an action exceeding the device class.

### Out of Scope

1. **Hostile co-tenant on the same host:** assume the OS isolates the process; use container hardening (ADR-0014 references `THREAT_MODEL.md` for details).
2. **Malicious operator with root:** an operator who can replace the package or read process memory wins. Use code signing, supply-chain attestation, and HSM-held keys (ADR-0005) to raise the bar.
3. **LLM provider exfiltration:** if the upstream LLM provider is malicious, we can only reduce the data we send, not prevent misuse of what they receive.
4. **Side-channel timing attacks** on the HMAC verification: we use `hmac.compare_digest`; mitigations beyond that are out of scope.
5. **Denial of service:** rate limiting belongs at the host framework / ingress.

## Decision

A full STRIDE analysis lives in `THREAT_MODEL.md` (Phase 3C). This ADR is the canonical statement of scope; the threat model is the enumeration of threats within that scope.

## Consequences

- **Positive:** honest marketing; auditors see clear boundaries.
- **Negative:** we cannot claim "secure against malicious operators" — by design.
- **Neutral:** future ADRs may expand scope (e.g., adding confidential computing support).

## References

- ADR-0003, ADR-0005, ADR-0008.
- NIST SP 800-154 (Guide to Data-Centric System Threat Modeling).
