"""Worked example: a tiny clinical summarization agent wrapped by ClinicSentry."""

from __future__ import annotations

from pathlib import Path

from clinicsentry import ClinicalRiskTier, ClinicSentry, minimum_necessary
from clinicsentry.policy import load_policy

POLICY_PATH = Path(__file__).parent / "policy.yaml"


def main() -> None:
    """Run a synthetic two-step summarization with full guard wiring."""
    guard = ClinicSentry(policy=load_policy(POLICY_PATH), framework="example")

    @guard.register_action(
        tier=ClinicalRiskTier.INFORMATIONAL,
        description="Summarize a visit note",
        iec62304_requirement="SR-001",
        required_fields={"note"},
    )
    @minimum_necessary(["note"], purpose="summarization")
    def summarize(payload: dict) -> str:
        # In a real agent, this is where the LLM call would happen.
        return f"Summary of note ({len(payload.get('note', ''))} chars)."

    raw_input = {
        "note": (
            "Patient John Doe (MRN: 12345678) seen on 2025-04-12. "
            "Contact: john.doe@example.com, 415-555-1212. Diagnosis: E11.9."
        ),
        "ssn": "123-45-6789",
        "irrelevant_field": "should be stripped by minimum_necessary",
    }

    scan = guard.firewall.scan(raw_input, origin_agent="example_agent")
    print("Redacted input:", scan.redacted)
    print("PHI tags:", [t.phi_type for t in scan.tags])

    output = summarize(raw_input)

    decision = guard.evaluate_action(
        "summarize",
        output_text=output,
        reasoning_text="Confidence: 90% — note is well-structured.",
        provided_fields={"note"},
    )
    print("Escalation decision:", decision.to_dict())

    report = guard.end_session(intended_use="Demo summarization agent")
    ok, errors = guard.verify_audit_chain()
    print("Audit chain ok:", ok, "errors:", errors)
    print("Compliance attestation:", report.compliance_attestation)


if __name__ == "__main__":  # pragma: no cover
    main()
