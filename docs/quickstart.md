# Quickstart

## Install

```bash
pip install clinicsentry            # core
pip install 'clinicsentry[all]'     # everything (Presidio, FHIR/HL7/DICOM, OTEL, …)
```

## Five-minute example

```python
from clinicsentry import ClinicSentry, ClinicalRiskTier, minimum_necessary

guard = ClinicSentry(policy="examples/policy.yaml", framework="generic")


@guard.register_action(
    tier=ClinicalRiskTier.ADVISORY,
    description="Suggest basal-rate adjustment.",
    required_fields={"cgm_trend", "current_rate"},
)
@minimum_necessary(["cgm_trend", "current_rate"], purpose="dose_advice")
def recommend_basal(payload: dict) -> dict:
    return {"new_rate": payload["current_rate"] * 1.05}


decision = guard.evaluate_action(
    "recommend_basal",
    output_text="confidence: 85%",
    provided_fields={"cgm_trend", "current_rate"},
)
print(decision.action, decision.confidence)

report = guard.end_session(intended_use="basal-rate advisory")
print(report.compliance_attestation)
```

## CLI

```bash
clinicsentry demo
clinicsentry scan "Patient SSN 123-45-6789 needs refill"
clinicsentry verify ./audit.sqlite
clinicsentry report ./audit.jsonl --session <id>
clinicsentry policy-validate examples/policy.yaml
```

## Local stack (Postgres + S3 + OTEL + Grafana)

```bash
docker compose -f deploy/compose/docker-compose.yml up
```

Then open <http://localhost:3000> (Grafana, `admin`/`admin`) or
<http://localhost:9001> (MinIO console).

## Next

- [PHI Firewall concept](concepts/phi-firewall.md)
- [Production tutorial](tutorials/production.md)
- [Regulatory mapping](regulatory-mapping.md)
