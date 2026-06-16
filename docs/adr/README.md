# Architecture Decision Records

This directory contains the architectural decisions for ClinicSentry, recorded as ADRs in the [Michael Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).

## Index

| #    | Title                                                  | Status   |
|------|--------------------------------------------------------|----------|
| 0000 | Template                                               | template |
| 0001 | Module Boundaries and Dependency Direction             | accepted |
| 0002 | Adapter ABC Interface Stability Contract               | accepted |
| 0003 | Audit Chain Semantics — Linear Hash Chain              | accepted |
| 0004 | Propagation Graph Schema and Serialization             | accepted |
| 0005 | Key Management Protocol                                | accepted |
| 0006 | IEC 62304 Class Enforcement Formal Model               | accepted |
| 0007 | Compliance Attestation Rule Language                   | accepted |
| 0008 | Error and Exception Taxonomy                           | accepted |
| 0009 | Async / Sync Boundary Conventions                      | accepted |
| 0010 | Test Naming and Tagging Conventions                    | accepted |
| 0011 | Dependency Injection Patterns                          | accepted |
| 0012 | Configuration Loading Rules                            | accepted |
| 0013 | Observability Hooks                                    | accepted |
| 0014 | Security Boundaries and Threat Model Scope             | accepted |
| 0015 | Redaction Mode Selection and Per-Field Overrides       | accepted |
| 0016 | Adversarial Normalization in the Production Scan Path  | accepted |

## Process

1. Copy `0000-template.md` to `NNNN-short-title.md`.
2. Open a PR. Status starts as `proposed`.
3. On merge, status moves to `accepted`. Existing ADRs are amended via a new ADR that supersedes them (status changes to `superseded by ADR-NNNN`); ADRs are never deleted.
