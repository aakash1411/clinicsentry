# Regulatory Mapping

How ClinicSentry maps to the major regulatory frameworks. This is **alignment**, not certification — see [Responsible Use](responsible-use.md).

## HIPAA Security Rule (45 CFR §164.308–§164.312)

| Citation | Requirement | ClinicSentry control |
|----------|-------------|------------------------|
| §164.312(a)(1) | Unique user identification | `AuditEvent.agent_id` populated for every event |
| §164.312(b) | Audit controls | `AuditChain` + linear hash-chain backend |
| §164.312(c)(1) | Integrity | HMAC signing; `verify()` reports tampering |
| §164.312(e)(1) | Transmission security | Adapter scans every cross-boundary message |
| §164.502(b) | Minimum necessary | `@minimum_necessary` decorator |
| §164.514(b) | De-identification methods | Four redaction modes per ADR-0015 |

## FDA TPLC (2025 draft guidance)

| Section | Requirement | ClinicSentry control |
|---------|-------------|------------------------|
| II.A | Intended use documentation | `MedDeviceConfig.intended_use` + report metadata |
| II.B | Risk management | IEC 62304 class enforcement + dose ranges |
| II.C | Monitoring | OTEL spans + Prometheus metrics |
| II.D | Change control | `ChangeImpactAssessment` generator |
| III.B | Real-world performance | `RegulatoryReport.session_summary` |

## IEC 62304:2006 +A1:2015

| Clause | Requirement | ClinicSentry control |
|--------|-------------|------------------------|
| §4.3 | Software safety classification | `SoftwareSafetyClass`, registration-time check (ADR-0006) |
| §5.1 | Software development planning | `CHANGELOG.md`, ADRs |
| §5.5 | Software unit verification | ≥ 85% test coverage (CI gate) |
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
