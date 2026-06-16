# Regulatory Audit Trail

Module 3. Every event is appended to a linear hash chain with HMAC signatures (ADR-0003).

## Event schema

`AuditEventType` enumerates ~15 event categories: `session_start`, `agent_llm_call`, `agent_llm_response`, `tool_call`, `tool_result`, `inter_agent_message`, `mcp_tool_call`, `a2a_message`, `phi_detected`, `escalation_triggered`, `human_review_response`, `module_error`, `session_end`, and more.

Each event carries:

- monotonic per-session `sequence_number`,
- SHA-256 `prev_event_hash` linking to its predecessor,
- HMAC-SHA256 `signature` over the canonical encoding,
- `redacted_input` / `redacted_output` — never raw PHI,
- `phi_tags_detected` — tag ids only.

## Backends

| Backend | Use case |
|---------|----------|
| `InMemoryAuditBackend` | tests, ephemeral |
| `FileAuditBackend` | JSONL append-only with fsync |
| `SqliteAuditBackend` | WAL-mode SQLite for single-node prod |
| `PostgresAuditBackend` | RLS + append-only triggers |
| `S3AuditBackend` | write-once with Object Lock |
| `OTELAuditBackend` | wrapper emitting OTLP spans per event |
| `ChainedAuditBackend` | hot + cold fan-out |

## Verification

```python
ok, errors = guard.verify_audit_chain()
```

Walks the chain in O(n), re-deriving each HMAC and `prev_event_hash`. Reports the index of the first mismatch.

## Regulatory report

`guard.end_session()` produces a `RegulatoryReport` covering FDA TPLC § II.D plus IEC 62304 traceability. Render to PDF via `clinicsentry.audit.pdf_report.render_report_pdf`.
