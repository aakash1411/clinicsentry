# ADR-0013: Observability Hooks

- **Status:** accepted
- **Date:** 2025-01-15

## Context

Production deployers need to know (a) is the chain intact, (b) what is the PHI detection rate, (c) where in the request flow does latency live, and (d) which escalations fire how often. We must not invent a custom observability stack but we also can't hard-depend on one.

## Decision

- **OpenTelemetry as the lingua franca.** Every public method on the four modules emits an OTEL span with attributes prefixed `clinicsentry.*`. Span names follow `clinicsentry.<module>.<operation>`.
- **OTEL is optional.** Import is wrapped in try/except; if absent, span context managers become no-ops (`contextlib.nullcontext`).
- **Structured logging** uses `structlog` if present, else stdlib `logging` with `JSONFormatter` shipped in `clinicsentry.observability.logging`. Correlation id is the audit `session_id`.
- **Prometheus metrics** (optional `clinicsentry[metrics]` extra) exposed at the dashboard service, not the library. Library code emits via a thin `Metrics` protocol with a no-op default.
- **No log lines contain PHI** — same rule as ADR-0008. Logs reference `tag_id` and field paths.
- **Health endpoint** (`/healthz/chain`) verifies the latest N events of the active chain. Lives in the dashboard / sidecar, not the library.

## Consequences

- **Positive:** integrates with any modern observability stack; no library lock-in.
- **Negative:** users who want metrics must run the dashboard or wire their own Prometheus collector. Acceptable.
- **Neutral:** the OTEL attribute schema is itself a v1 contract; changes follow ADR-0002's stability rule.

## References

- ADR-0008.
- OpenTelemetry Semantic Conventions v1.27.
