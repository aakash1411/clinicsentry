# Project Status

**Current version:** 0.3.0 (pre-1.0; API may change between minor versions)

| Area | Status |
|------|--------|
| PHI Firewall (regex + adversarial normalization + encoded-token scan) | stable, benchmarked |
| Escalation Router + confidence scoring | stable |
| Audit chain (HMAC, thread-safe, truncation detection) | stable |
| MedDevice mode (IEC 62304 class enforcement, dose ranges, rate limits) | stable |
| Adapters (LangGraph, CrewAI, ADK, OpenAI Agents, Claude SDK, MCP, A2A) | beta — SDK API churn risk |
| Presidio / NER name detection | optional extra; recall not characterized on real clinical text |
| Postgres / S3 audit backends | beta — integration-tested via testcontainers |
| Dashboard | experimental |

See `RESPONSIBLE_USE.md` before any deployment touching real PHI.
