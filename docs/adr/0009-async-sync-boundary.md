# ADR-0009: Async / Sync Boundary Conventions

- **Status:** accepted
- **Date:** 2025-01-15

## Context

Modern agent frameworks (LangGraph, ADK, OpenAI Agents SDK) are async-first. Some hosts (CLI tools, batch pipelines) are sync. Mixing creates either deadlocks (sync inside async event loop) or thread-pool churn (async called from sync). We need a clear rule.

## Decision

- **Adapters and interception points are async.** The five `intercept_*` methods on `AgentFrameworkAdapter` are `async def`.
- **Module internals are sync** unless they perform I/O.  PHI detection, confidence scoring, hash computation, and policy loading are pure-compute and stay sync.
- **Storage backends are dual:** `AuditBackend.append` is sync (called from the hot path) with an optional `aappend` async method. Background flush / archival is async.
- **No mixing inside a module:** if a module needs both, it splits files (`*_sync.py` and `*_async.py`).
- **`asyncio.run` is forbidden inside the package** except in the CLI entry point.

This keeps the call graph predictable: async at the edges, sync in the middle.

## Consequences

- **Positive:** zero deadlock risk in framework integrations; tests stay simple (sync `pytest` for internals, `pytest-asyncio` only for adapters).
- **Negative:** if a future feature requires async deep in the core (e.g., async detector calling an external API), we add an explicit boundary rather than retrofitting.
- **Neutral:** sync code can still be called from async via `await asyncio.to_thread(...)`; we document this pattern in `CONTRIBUTING.md`.

## References

- ADR-0002.
- "Sans-I/O" pattern (Brett Cannon).
