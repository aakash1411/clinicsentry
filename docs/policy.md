# Policy YAML Reference

A ClinicSentry policy is a single YAML file. Precedence (lowest → highest): built-in defaults → YAML → environment variables (`CLINICSENTRY_*`) → constructor kwargs (ADR-0012).

```yaml
version: "0.1.0"

phi_firewall:
  mode: REDACT                    # REDACT | PSEUDONYMIZE | GENERALIZE | SUPPRESS | AUDIT_ONLY
  use_presidio: false
  decode_encoded: true            # scan base64-decodable tokens for embedded PHI
  max_depth: 64                   # deeper nesting is redacted wholesale (fail closed)
  overrides:
    DATE: GENERALIZE
    ZIP: GENERALIZE
  allowlist:                      # public, non-PHI literals kept readable;
    PHONE:                        # matching ignores case and separators
      - "1-800-646-4633"
    URL:
      - "https://www.medtronicdiabetes.com/support"
  # detectors: [EMAIL, PHONE, SSN, DEVICE_ID]   # exact set; default = core set
  locales: [en_US]                # + en_GB (NHS/NINO/IBAN), de_DE, en_CA
  custom_detectors:               # domain-specific formats (see docs/api.md
    - label: PUMP_SERIAL          # for the @register_detector code API)
      pattern: '\b(?:SN|serial)[\s:#-]*[A-Z0-9]{6,}\b'
      flags: [IGNORECASE]
      confidence: 0.99
      mode: REDACT
  skip_fields: ["public_kb_snippet", "citation.*"]   # dotted-path globs
  always_redact_fields: ["raw_user_transcript"]
  # detector_backend: aws_comprehend_medical    # cloud NER layer (needs boto3)

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
clinicsentry policy-validate policy.yaml   # load + print the resolved config
clinicsentry policy-schema                 # print the authoritative JSON Schema
```

Prints the resolved `PolicyConfig` as JSON, or a clear error if any field is malformed. `extra="forbid"` semantics: unknown keys are rejected (ADR-0012). The YAML examples in this file are loaded through `load_policy` in CI, so this reference cannot drift from the schema.

Detector coverage per HIPAA identifier: see [phi-coverage.md](phi-coverage.md).
