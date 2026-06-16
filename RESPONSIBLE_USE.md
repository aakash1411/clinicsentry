# Responsible Use of ClinicSentry

## Not a Medical Device

ClinicSentry is **research-grade middleware**. It is **not** FDA-cleared, CE-marked, or otherwise authorized as a medical device. The library implements controls aligned with HIPAA, FDA TPLC draft guidance, and IEC 62304; alignment is not certification.

Do not deploy ClinicSentry in a setting where its failure could cause patient harm without (a) your own regulatory submission, (b) clinical validation, and (c) a quality management system covering the full SaMD lifecycle.

## Intended Use

- A reference implementation of compliance controls for clinical AI agents.
- A research substrate for studying PHI containment, escalation policies, and audit-chain integrity.
- A teaching artifact for healthcare-AI compliance engineering.

## Out-of-Scope Uses

- Direct integration with patient-facing decision-support without clinical and regulatory review.
- Reliance on the default software key provider in production. Use HSM-backed keys (see ADR-0005).
- Use of synthetic-PHI-only evaluation as evidence of production performance — real-world distributional shift is significant.

## Honest Disclosures

- The default detectors are **rule-based + Presidio**. False-positive and false-negative rates on real clinical text are not yet characterized on a public benchmark. Phase 4 of the roadmap addresses this.
- The audit chain protects against **honest-operator** integrity violations (see ADR-0014). A malicious root user can compromise any in-process state.
- The IEC 62304 class enforcement is a **runtime check**. It does not constitute a quality management system, design history file, or risk management file.

## Required for Deployment in Clinical Settings

If you choose to deploy in any setting that touches real PHI or influences patient care:

1. **Operator must hold a HIPAA Business Associate Agreement** with each downstream provider that receives data.
2. **Use HSM-backed keys** for the audit chain (see `KeyProvider` implementations).
3. **Configure a Postgres + S3 audit backend** with append-only constraints (RLS, Object Lock).
4. **Run the threat model review** (`THREAT_MODEL.md`) against your specific deployment.
5. **Document intended use** in your QMS; ClinicSentry cannot do this for you.
6. **Establish a clinical safety case** independent of the ClinicSentry configuration.

## Disclaimer

ClinicSentry is provided "as is", without warranty of any kind, express or implied (Apache-2.0 §7–§8). The authors and contributors are not liable for any direct, indirect, incidental, or consequential damages arising from the use of this software.
