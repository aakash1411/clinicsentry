# Clinical Escalation Router

Module 2. Each registered action declares a `ClinicalRiskTier`:

- `INFORMATIONAL` — agent may proceed if confidence ≥ tier threshold.
- `ADVISORY` — proceed only with annotation; otherwise escalate.
- `INTERVENTIONAL` — always block; require explicit human authorization.

## Composite confidence

The router consumes a composite confidence score blending four (up to eight) signals:

1. Self-reported confidence (parsed from reasoning).
2. Grounding (ICD-10 vocab cross-reference).
3. Hallucination check (drug-name vocabulary).
4. Input completeness (against `required_fields`).
5. Historical consistency (cosine similarity vs. session embeddings).
6. Uncertainty quantification (temperature-scaled top-1 logprob).
7. Clinical guideline adherence (rule engine).
8. Clinician-override probability inverse (logistic regression).

Missing signals are excluded from the weighted mean.

## Channels

Escalations are routed to one of:

- `InMemoryReviewQueue` (tests).
- `SQLiteReviewQueue` (SLA-tracking, persistent).
- `WebhookChannel` (HTTP POST with exponential backoff).

## API

See the [API reference](../api.md#escalation) for `EscalationRouter`,
`ConfidenceScorer`, and the full escalation surface.
