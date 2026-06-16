# ADR-0003: Audit Chain Semantics — Linear Hash Chain, Not Merkle Tree

- **Status:** accepted
- **Date:** 2025-01-15

## Context

FDA TPLC and IEC 62304 require tamper-evident audit logs. The two dominant designs are (a) a linear hash chain where each event embeds the previous event's hash, and (b) a Merkle tree (or hash chain plus periodic Merkle anchoring). Merkle trees enable efficient proofs over event subsets but require either anchoring to an external timestamping authority or significant in-process state.

## Decision

We will use a **linear hash chain with HMAC signing** for v1:

- Each `AuditEvent` carries `previous_hash` (SHA-256 of the prior canonical event encoding) and `signature` (HMAC-SHA256 over the event's canonical form using a per-deployment secret key).
- Sequence numbers are assigned by `AuditChain` at write time (monotonic, gapless within a session).
- Verification walks the chain in O(n) and re-derives the HMAC; any divergence is reported with the index of the first mismatch.
- The chain is **per-session**. Cross-session linkage is the responsibility of the storage backend (PostgreSQL FK to session row, S3 object naming).

## Consequences

- **Positive:** simple, fast, no external dependencies, trivial to verify on commodity hardware. Matches regulator mental model (a write-only journal).
- **Negative:** cannot generate compact proofs of "event X was in the log" without revealing the whole prefix. Acceptable because regulator review is full-log anyway.
- **Neutral:** the format is forward-compatible with a Merkle overlay (a future ADR may add periodic Merkle roots without breaking existing chains).

## Alternatives Considered

- **Merkle tree:** rejected for v1 — added complexity not justified by current threat model.
- **External timestamping (RFC 3161):** parked for Phase 4+ when production deployments require non-repudiation against the deployer.

## References

- ADR-0005 (key management), ADR-0014 (threat model scope).
- NIST SP 800-92 (Guide to Computer Security Log Management).
