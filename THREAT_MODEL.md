# ClinicSentry Threat Model (STRIDE)

This document enumerates threats *within the scope defined by ADR-0014*. Threats out of scope (hostile root, malicious operator, side channels) are listed for completeness with their mitigations.

| ID | Asset | Threat | STRIDE | Mitigation | Residual Risk |
|----|-------|--------|--------|------------|---------------|
| T-01 | PHI in transit to LLM | Adversarial prompt extracts PHI from earlier turns | Information Disclosure | PHI firewall scrubs every message at the adapter boundary; propagation graph caps cross-agent leak | Low — depends on detector recall on PHI variants |
| T-02 | Audit chain on disk | Operator modifies a past event to rewrite history | Tampering | Hash-linked HMAC chain (ADR-0003); `verify()` detects any change | Low for software keys; very low for HSM-held keys (ADR-0005) |
| T-03 | Audit chain | Truncate-and-replay (delete tail events) | Tampering, Repudiation | Sequence numbers gapless within a session; report flags missing tail | Medium — operator with DB write can drop rows; offset by S3 object-lock |
| T-04 | Audit chain | Re-order rows in storage backend | Tampering | `prev_event_hash` verifies link order independent of storage order | Low |
| T-05 | Confidence signals | LLM gaming self-reported confidence string | Spoofing | Self-reported is one of 4–8 signals, weighted; alone never decisive | Medium — research opportunity |
| T-06 | Drug-name vocabulary | Stale vocabulary makes hallucination signal underdetect | Spoofing | Vocabulary is a pluggable `KeyProvider`-style protocol; can be refreshed | Medium |
| T-07 | Tool args | Prompt injection drives a tool with unsafe args | Elevation of Privilege | `@minimum_necessary` strips disallowed fields; meddevice dose-range check | Low |
| T-08 | Class B/C autonomous action | Replay clinician auth token across sessions | Spoofing, Repudiation | Token includes session id + nonce; validator rejects replay | Very Low |
| T-09 | Class B/C autonomous action | Steal clinician signing key | Elevation of Privilege | Recommend HSM-held keys; `RESPONSIBLE_USE.md` warns on software keys | Out of scope without HSM |
| T-10 | PHI in error / log lines | Stack trace leaks PHI captured locally | Information Disclosure | ADR-0008: exceptions are PHI-free by construction; CI lints message templates | Low |
| T-11 | Detector pipeline | Adversarial unicode (homoglyph) bypass | Information Disclosure | `AdversarialNormalizer` precedes regex; multilingual detector covers es/fr/zh | Medium |
| T-12 | Policy YAML | Operator weakens redaction modes silently | Tampering | Policy is in source control; CIA generator flags `safety_class_upgrade`, dose-range expansion | Low |
| T-13 | Web dashboard | XSS via PHI tag display | Information Disclosure | Dashboard renders only `tag_id` / categories; never PHI values | Very Low |
| T-14 | OTEL exporter | Span attributes leak PHI to upstream tracing backend | Information Disclosure | Span attributes restricted to ids and counts; never values (ADR-0013) | Low |
| T-15 | Supply chain | Compromised PyPI dependency injects PHI exfiltration | Tampering | Pinned versions; pip-audit + bandit + semgrep in CI; cosign-signed images | Medium — industry-wide problem |
| T-16 | Process memory | Coredump or memory-snapshot reveals PHI | Information Disclosure | Containers run with `ReadonlyRootFilesystem` + `RUN_AS_NONROOT`; coredump disabled | Out of scope per ADR-0014 |
| T-17 | DoS | Adversarial input exhausts firewall regex matching | Denial of Service | Detectors use anchored, bounded patterns; rate-limiting belongs at ingress | Medium |

## STRIDE Coverage

- **S**poofing — T-05, T-06, T-08, T-09
- **T**ampering — T-02, T-03, T-04, T-12, T-15
- **R**epudiation — T-03, T-08
- **I**nformation Disclosure — T-01, T-10, T-11, T-13, T-14, T-16
- **D**enial of Service — T-17
- **E**levation of Privilege — T-07, T-09

## Review Cadence

- Per release: re-score residual risk; update mitigations.
- Per ADR: cross-reference impacted threats and revise.

## References

- ADR-0014 (security scope), ADR-0003 (chain), ADR-0005 (keys), ADR-0008 (errors), ADR-0013 (observability).
- NIST SP 800-154 — Data-Centric System Threat Modeling.
- OWASP ASVS v4.0.3.
