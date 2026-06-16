# ADR-0002: Adapter ABC Interface Stability Contract

- **Status:** accepted
- **Date:** 2025-01-15

## Context

Adapters are the primary extension point. Every framework integration (LangGraph, CrewAI, ADK, OpenAI Agents, Claude SDK, MCP, A2A) must conform to the same interception surface so that downstream guarantees (audit chain integrity, PHI containment, escalation correctness) hold regardless of host framework. Breaking the adapter contract would force every integrator to re-implement.

## Decision

We will treat `AgentFrameworkAdapter` (in `src/clinicsentry/adapters/base.py`) as a stable v1 contract with these properties:

1. **Five interception points, async-only:** `intercept_before_llm`, `intercept_after_llm`, `intercept_tool_call`, `intercept_tool_result`, `intercept_agent_message`. New points may be added (additive) but never removed in a 1.x release.
2. **Return type is the (possibly redacted) input:** adapters must never silently drop messages. Suppression is signaled by raising `EscalationRaised` (defined in `escalation/exceptions.py`).
3. **Side effects are confined to `self.guard`:** adapters MUST NOT mutate framework state directly.
4. **Adapters are stateless across calls:** any state lives on `self.guard` (specifically `propagation` and `chain`).
5. **Each adapter ships with a mock framework harness** so adapter tests can run without the heavy SDK installed.

Breaking changes require a new major version and a deprecation window of one full minor release.

## Consequences

- **Positive:** integrators get a small, stable surface; we get freedom to evolve internals.
- **Negative:** any new interception need (e.g., a "before-handoff" hook for A2A) must be coordinated across all adapters or stubbed with a default no-op on the ABC.
- **Neutral:** `GenericAdapter` becomes the canonical reference implementation and the test double for non-framework-bound code.

## Alternatives Considered

- **Callback registry instead of ABC:** rejected — loses static typing and discoverability.
- **Sync interception with async optional:** rejected — async-first lets sync hosts call `asyncio.run` once, but async hosts (most agent frameworks) cannot wrap a sync interceptor without thread pools.

## References

- ADR-0001, ADR-0008 (exception taxonomy), ADR-0009 (async/sync boundary).
