# ClinicSentry

Framework-agnostic **compliance middleware** for clinical AI agents. ClinicSentry implements four orthogonal controls aligned with HIPAA, FDA TPLC, and IEC 62304:

1. **PHI Firewall** — detect, redact, and track PHI flowing through your agents.
2. **Clinical Escalation Router** — risk-tier each action and route uncertain decisions to humans.
3. **Regulatory Audit Trail** — tamper-evident hash-chain of every event in the session.
4. **MedDevice Mode** — IEC 62304 Class A/B/C registration-time enforcement, dose-range checks, emergency stop, clinician authorization.

ClinicSentry sits *between* your agent framework (LangGraph, CrewAI, Google ADK, OpenAI Agents, Claude SDK, MCP, A2A) and the LLM / tool surface. No framework lock-in.

## Status

Pre-1.0 research software. See [Responsible Use](responsible-use.md) before any deployment that touches real PHI.

## Quick links

- [Quickstart](quickstart.md) — install and run the worked example in < 5 minutes.
- [Concepts](concepts/phi-firewall.md) — one page per module.
- [Adapters](adapters.md) — supported frameworks.
- [Regulatory mapping](regulatory-mapping.md) — which controls satisfy which clauses.
- [Threat model](threat-model.md) — STRIDE analysis (ADR-0014).
- [ADRs](adr/README.md) — every architectural decision documented.
