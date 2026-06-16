# ADR-0007: Compliance Attestation Rule Language

- **Status:** accepted
- **Date:** 2025-01-15

## Context

The `RegulatoryReport` produced at `end_session` must be checkable mechanically: regulators and auditors want to see "all 12 attestations passed" rather than a 400-line narrative. We need a tiny rule language so attestations are declarative, reviewable, and version-controlled.

## Decision

We will ship attestation rules as YAML in `src/clinicsentry/compliance/rules/`. Each rule has the schema:

```yaml
id: HIPAA-164.312-a-1
title: Access control - unique user identification
predicate: every_event.has(agent_id)
severity: blocker  # blocker | warning | info
references:
  - 45 CFR §164.312(a)(1)
```

`predicate` is a restricted expression language (parsed via `ast.parse` with a whitelist of names and operators) operating over the report fields. Implemented operators: `every_event`, `no_event`, `count_of`, `any_event`, `tag_category_in`, `tier_atleast`. No arbitrary Python evaluation.

Rules ship as a curated set covering HIPAA §164.308–§164.312 and FDA TPLC 2025 §III.B. New rules require a PR with one passing and one failing test fixture.

## Consequences

- **Positive:** attestation logic is declarative, diff-reviewable, and shippable as a regulatory artifact.
- **Negative:** the DSL is a small custom thing we have to maintain. Acceptable because the alternative is auditor-unreadable Python.
- **Neutral:** Phase 4 may swap the DSL for OPA/Rego; the rule schema is forward-compatible.

## Alternatives Considered

- **Free Python callables:** rejected — un-auditable.
- **OPA/Rego:** parked — too heavy for v1; we revisit if rule count exceeds 50.

## References

- ADR-0006, ADR-0014.
