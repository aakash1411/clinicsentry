# Regulatory Mapping

How ClinicSentry maps to the major regulatory frameworks. This is **alignment**, not certification — see [Responsible Use](responsible-use.md).

## HIPAA Security Rule (45 CFR §164.308–§164.312)

| Citation | Requirement | ClinicSentry control |
|----------|-------------|------------------------|
| §164.312(a)(1) | Unique user identification | `AuditEvent.agent_id` populated for every event |
| §164.312(b) | Audit controls | `AuditChain` + linear hash-chain backend |
| §164.312(c)(1) | Integrity | HMAC signing; `verify()` reports tampering |
| §164.312(e)(1) | Transmission security | Adapter scans every cross-boundary message |
| §164.502(b) | Minimum necessary | `@minimum_necessary` decorator; `PHI_DETECTED` / `PHI_REDACTED` audit evidence |
| §164.514(b) | De-identification methods | Four redaction modes per ADR-0015 |

## FDA AI-enabled device software functions (TPLC)

Mapped to the themes of FDA's draft guidance *Artificial Intelligence-Enabled
Device Software Functions: Lifecycle Management and Marketing Submission
Recommendations* (January 2025, draft — non-binding) and the final PCCP
guidance (December 2024). Bundled rule IDs (`FDA-TPLC-III-B-*`) are retained
for compatibility and do not cite guidance section numbers.

| Theme | ClinicSentry control |
|-------|------------------------|
| Device description / intended use | `MedDeviceConfig.intended_use` + report metadata |
| Risk management | IEC 62304 class enforcement; runtime dose-range, rate-limit and interventional gates |
| Performance monitoring | OTEL spans + Prometheus metrics; per-session audit chain |
| Change control (PCCP) | `ChangeImpactAssessment` generator |
| Real-world performance evidence | `RegulatoryReport.session_summary` |

## IEC 62304:2006 +A1:2015

| Clause | Requirement | ClinicSentry control |
|--------|-------------|------------------------|
| §4.3 | Software safety classification | `SoftwareSafetyClass`, registration-time check (ADR-0006) |
| §5.1 | Software development planning | `CHANGELOG.md`, ADRs |
| §5.5 | Software unit verification | ≥ 75% test coverage (CI gate) |
| §5.7 | Software system testing | Integration + adapter test suites |
| §7.1 | Risk management process | Threat model + risk register |

## IEC 62304 Edition 2 (draft)

`translate_to_edition2(safety_class)` returns the Rigor Level (I/II/III) and required documents per Edition 2's risk-based scaling.

## IMDRF Good Machine Learning Practice (2021)

| Principle | ClinicSentry control |
|-----------|------------------------|
| 1. Multi-disciplinary expertise | Adapter pattern; clinicians via `ClinicianAuthValidator` |
| 5. Training data independent from test | Out of scope: ClinicSentry is middleware, not a model |
| 8. Continuous performance monitoring | OTEL + Prometheus + audit chain |
| 9. Cybersecurity | ADR-0014 threat model, signed releases |
| 10. Periodic monitoring | `RegulatoryReport.compliance_attestation` |
