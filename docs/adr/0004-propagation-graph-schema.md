# ADR-0004: Propagation Graph Schema and Serialization

- **Status:** accepted
- **Date:** 2025-01-15

## Context

HIPAA §164.502(b) (minimum necessary) and §164.514 (de-identification) require us to demonstrate that PHI did not leak across boundaries it shouldn't have. To prove this, ClinicSentry tracks every PHI tag as a node and every cross-agent / cross-tool transfer as a directed edge. The graph must be serializable into the regulatory report and queryable at runtime for escalation decisions.

## Decision

We will represent the propagation graph as:

- **Nodes:** `PHITag` records (`tag_id`, `category`, `value_hash`, `first_seen_at`, `redaction_mode`).
- **Edges:** directed `(from_agent, to_agent, tag_id, timestamp)` tuples.
- **Storage:** in-memory `dict[tag_id -> PHITag]` plus `list[Edge]`, snapshotted into the `RegulatoryReport` at `end_session`.
- **Serialization:** JSON, with `tag_id`s referenced by id (not by inlined value) so PHI never appears in the report.
- **Identifiers:** `tag_id` is `sha256(value || session_salt)[:16]` to be stable within a session but unlinkable across sessions.

## Consequences

- **Positive:** report is auditable without exposing raw PHI; cross-agent flow is explicit.
- **Negative:** in-memory graph is bounded by session size — acceptable for v1 (single-session footprint < 100k tags).
- **Neutral:** moving to a graph DB (Neo4j, NetworkX-on-disk) is a future option once cross-session analysis is required.

## Alternatives Considered

- **Edges only, no node table:** rejected — would lose PHI category metadata needed for report sections.
- **Networkx as core dependency:** rejected — overkill for v1; reintroduce if graph algorithms (e.g., shortest-path leakage) become a feature.

## References

- ADR-0001, ADR-0015 (redaction modes).
