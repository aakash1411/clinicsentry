# Policy YAML Reference

A ClinicSentry policy is a single YAML file. Precedence (lowest → highest): built-in defaults → YAML → environment variables (`CLINICSENTRY_*`) → constructor kwargs (ADR-0012).

```yaml
version: "0.1.0"

phi_firewall:
  mode: REDACT                    # REDACT | PSEUDONYMIZE | GENERALIZE | SUPPRESS
  use_presidio: false
  decode_encoded: true            # scan base64-decodable tokens for embedded PHI
  max_depth: 64                   # deeper nesting is redacted wholesale (fail closed)
  overrides:
    DATE: GENERALIZE
    ZIP: GENERALIZE

escalation:
  thresholds:
    informational: 0.6
    advisory: 0.8                 # values in [0, 1.01]; 1.01 = always escalate
  on_unregistered_action: escalate  # escalate (fail closed) | tier_default

audit:
  backend: sqlite                 # memory | file | sqlite | postgres | s3
  path: ./audit.sqlite
  retention_years: 7

meddevice_mode:
  enabled: true
  software_safety_class: B
  device_type: closed_loop_drug_delivery
  intended_use: dosage advisory
  manufacturer: Acme
  strict_dose_ranges: true        # undeclared parameters fail validation
  dose_ranges:
    - parameter: basal_rate_u_per_hr
      min: 0.0
      max: 5.0
      unit: U/hr
  rate_limit_per_hour: 6          # rolling 1-hour window
```

## Environment Overrides

`CLINICSENTRY_<SECTION>_<KEY>` overrides any policy field; nested keys use a
double underscore. Values are parsed as YAML scalars.

```bash
export CLINICSENTRY_AUDIT_BACKEND=postgres
export CLINICSENTRY_PHI_FIREWALL_MODE=PSEUDONYMIZE
export CLINICSENTRY_ESCALATION_THRESHOLDS__ADVISORY=0.9
```

Secrets (HMAC keys, DSNs) are **not** policy fields and are read separately
(`CLINICSENTRY_HMAC_KEY`, `CLINICSENTRY_DSN`). Pass
`load_policy(..., apply_env=False)` to skip the environment layer.

## Validation

```bash
clinicsentry policy-validate policy.yaml
```

Prints the resolved `PolicyConfig` as JSON, or a clear error if any field is malformed. `extra="forbid"` semantics: unknown keys are rejected (ADR-0012).
