# ClinicSentry

> **Framework-agnostic compliance middleware for clinical AI agents**

ClinicSentry is an open-source Python library that wraps any AI agent
framework (LangGraph, CrewAI, Google ADK, OpenAI Agents SDK, Claude SDK, MCP,
A2A) and enforces clinical-domain guardrails — without requiring changes to
your existing agent code.

> **⚠️ Important disclaimers**
>
> - ClinicSentry is **not a medical device** and is not FDA-cleared or
>   CE-marked. Its controls *align with* HIPAA, FDA TPLC draft guidance, and
>   IEC 62304 — alignment is not certification, and using this library does
>   not make your system compliant by itself.
> - The default detectors catch **structured identifiers** (SSN, MRN, phone,
>   email, dates, …) deterministically. **Person-name detection requires the
>   optional NER extras** (`pip install 'clinicsentry[phi]'`); its recall on
>   real clinical text is not yet characterized on a public benchmark.
> - Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) before any deployment that
>   touches real PHI or influences patient care.

## Four Orthogonal Controls

| Module | What it does | Regulatory alignment |
|--------|-------------|---------------------|
| **PHI Firewall** | Detect, redact, and track PHI across agents | HIPAA §164.502(b), §164.312 |
| **Clinical Escalation Router** | Risk-tier actions; route uncertain decisions to humans | IEC 62304 §9, FDA TPLC §III.B |
| **Regulatory Audit Trail** | Tamper-evident HMAC-signed hash chain of every event | 21 CFR Part 11, HIPAA §164.312(b) |
| **MedDevice Mode** | IEC 62304 Class A/B/C enforcement, dose-range checks, emergency stop | IEC 62304 §5.1/§8, EU AI Act |

## Install

```bash
pip install clinicsentry            # core
pip install 'clinicsentry[all]'     # everything (Presidio, FHIR, OTEL, cloud KMS, …)
```

**Extras:** `[postgres]`, `[cloud-kms]`, `[otel]`, `[dashboard]`, `[all]`

## Quick Example

```python
from clinicsentry import ClinicSentry, ClinicalRiskTier

guard = ClinicSentry(framework="my-agent")

# 1. Scan input for PHI
scan = guard.firewall.scan(
    {"note": "Patient Jane Doe (MRN 12345678), SSN 123-45-6789"},
    origin_agent="intake",
)
print(scan.redacted)  # PHI replaced with [REDACTED:MRN], [REDACTED:SSN]

# 2. Register actions with risk tiers
@guard.register_action(
    tier=ClinicalRiskTier.ADVISORY,
    description="Summarize a clinical note",
    required_fields={"note"},
)
def summarize(payload: dict) -> str:
    return f"Summary ({len(payload['note'])} chars)"

# 3. Evaluate — router decides: proceed / escalate / block
decision = guard.evaluate_action(
    "summarize",
    output_text="Summary of visit note",
    reasoning_text="High confidence, structured input",
    provided_fields={"note"},
)
print(decision.action, decision.confidence)

# 4. End session → regulatory compliance report
report = guard.end_session(intended_use="clinical summarization")
print(report.compliance_attestation)
```

Or let the context manager guarantee the session boundary — `SESSION_END` is
audited even if your pipeline raises:

```python
with ClinicSentry(framework="my-agent") as guard:
    ...  # scans, evaluations, tool calls
# report available as guard.last_report
```

## Risk Tiers

| Tier | Behavior | Example |
|------|----------|---------|
| `INFORMATIONAL` | Auto-proceed; audit logged | "How do I use my device?" |
| `ADVISORY` | Proceed with annotation; confidence score visible | Triage patients by glucose trends |
| `INTERVENTIONAL` | **Auto-blocked**; routed to human reviewer | Adjust insulin dosing parameters |

Unregistered actions **escalate by default** (fail closed) — see
`escalation.on_unregistered_action` in the [policy reference](docs/policy.md).

## Fail-Safe by Default

- **Adversarial PHI detection** on the production scan path: homoglyphs,
  zero-width characters, full-width forms, percent-encoding, and
  base64-encoded payloads are normalized with exact offset mapping, then
  redacted in the original text (ADR-0016). Plain-ASCII inputs take a
  no-overhead fast path (~0.7 ms p95 on 3 KB notes, pure Python, no extra
  LLM calls).
- **Whole-payload coverage**: strings, dicts (keys included), lists, tuples,
  sets, UTF-8 bytes, FHIR/HL7/DICOM; nesting deeper than
  `phi_firewall.max_depth` is redacted wholesale rather than erroring.
- **Tamper-evident auditing** under concurrency: thread-safe gapless
  sequencing, plus tail-truncation detection on `verify()`.
- **Strict policy loading**: typo'd keys and out-of-range values raise
  `PolicyError` at startup instead of silently disabling enforcement;
  `CLINICSENTRY_*` env overrides for containerized deployments.
- **MedDevice guardrails**: undeclared dose parameters and non-finite values
  fail validation; rate limits use a true rolling 1-hour window.

## CLI

```bash
clinicsentry demo                                    # seeded demo session
clinicsentry scan "Patient SSN 123-45-6789"          # one-shot PHI scan
clinicsentry verify ./audit.sqlite --secret <hex>    # verify audit chain
clinicsentry report ./audit.sqlite --session <id>    # compliance report
clinicsentry policy-validate examples/policy.yaml    # validate policy file
```

## Bundled Compliance Frameworks

| Framework | Key rules |
|-----------|-----------|
| **HIPAA** | PHI redacted, audit signed, chain integrity, minimum necessary |
| **FDA TPLC** | Session boundaries, no sequence gaps, postmarket data capture |
| **IEC 62304** | Agent traceability, chain integrity, interventional escalation |
| **EU AI Act** | Transparency, human oversight |

All four are checked automatically by `clinicsentry report`.

## Production Stack

```bash
# Postgres audit + S3 + OTEL + Grafana dashboard
docker compose -f deploy/compose/docker-compose.yml up
```

Open <http://localhost:3000> (Grafana) or <http://localhost:9001> (MinIO).

## Documentation

- [Quickstart](docs/quickstart.md) — install and run in < 5 minutes
- [Adapters](docs/adapters.md) — supported agent frameworks
- [Regulatory Mapping](docs/regulatory-mapping.md) — controls → regulation clauses
- [Threat Model](THREAT_MODEL.md) — STRIDE analysis
- [API Reference](docs/api.md)

## Status, Versioning, and Support

**v0.3.0** — pre-1.0 software ([per-module status](STATUS.md)). SemVer: breaking
changes only in minor releases until 1.0, always flagged in the
[CHANGELOG](CHANGELOG.md) with migration notes. Only the latest minor release
receives security fixes ([security policy](SECURITY.md) — PHI-detection
bypasses are treated as vulnerabilities, reported privately).

- Bugs and feature requests: GitHub issues (templates provided).
- Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) and [CONVENTIONS.md](CONVENTIONS.md).

## How It Compares

| | ClinicSentry | NeMo Guardrails / Guardrails AI | Presidio |
|---|---|---|---|
| Clinical regulatory mapping (HIPAA / FDA TPLC / IEC 62304) | built-in, rule DSL | generic rails | none |
| Tamper-evident audit chain | HMAC hash chain | logging only | none |
| Risk-tiered human escalation | built-in | build your own | none |
| Extra LLM calls on hot path | **zero** | often 1+ per check | zero |
| PHI detection | regex + adversarial normalization (+ optional Presidio/NER) | delegate | NER engine |

Presidio is a complementary *detector* (we wrap it via `[phi]`); rails
frameworks are complementary *conversation shapers*. ClinicSentry is the
compliance enforcement and evidence layer between your agent and the world.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Apache-2.0 permits
commercial use, modification, and redistribution — including inside
proprietary products.
