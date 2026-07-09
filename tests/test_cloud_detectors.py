"""B5: cloud PHI-service detector adapters (fake client, no network)."""

from __future__ import annotations

import pytest

from clinicsentry.errors import PolicyError
from clinicsentry.phi.cloud import AWSComprehendMedicalDetector, build_cloud_detector
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.policy import load_policy


class FakeComprehendClient:
    def __init__(self, entities=None, error: Exception | None = None):
        self._entities = entities or []
        self._error = error
        self.calls: list[str] = []

    def detect_phi(self, Text: str):  # noqa: N803 - AWS API casing
        self.calls.append(Text)
        if self._error:
            raise self._error
        return {"Entities": self._entities}


def test_comprehend_entities_become_hits() -> None:
    client = FakeComprehendClient(
        entities=[{"Type": "NAME", "BeginOffset": 8, "EndOffset": 16, "Score": 0.98}]
    )
    det = AWSComprehendMedicalDetector(client=client)
    hits = det.detect("Patient Jane Doe seen today")
    assert hits[0].phi_type == "NAME"
    assert hits[0].value == "Jane Doe"
    assert hits[0].source == "aws_comprehend_medical"


def test_comprehend_wired_into_firewall_redaction() -> None:
    client = FakeComprehendClient(
        entities=[{"Type": "NAME", "BeginOffset": 8, "EndOffset": 16, "Score": 0.98}]
    )
    fw = PHIFirewall()
    fw._cloud = AWSComprehendMedicalDetector(client=client)
    out = fw.scan("Patient Jane Doe seen today")
    assert "Jane Doe" not in str(out.redacted)
    assert "[REDACTED:NAME]" in str(out.redacted)


def test_backend_failure_falls_back_to_regex_layer() -> None:
    errors: list[Exception] = []
    client = FakeComprehendClient(error=ConnectionError("network down"))
    fw = PHIFirewall()
    fw._cloud = AWSComprehendMedicalDetector(client=client, on_error=errors.append)
    out = fw.scan("SSN 123-45-6789 for Jane Doe")
    assert "[REDACTED:SSN]" in str(out.redacted)  # regex layer still active
    assert errors
    assert isinstance(errors[0], ConnectionError)


def test_long_text_is_chunked() -> None:
    client = FakeComprehendClient()
    det = AWSComprehendMedicalDetector(client=client)
    det.detect("x" * 45_000)
    assert len(client.calls) == 3


def test_unknown_backend_rejected() -> None:
    with pytest.raises(ValueError, match="detector_backend"):
        build_cloud_detector("gcp_dlp")


def test_unknown_backend_rejected_at_policy_load() -> None:
    with pytest.raises(PolicyError, match="detector_backend"):
        load_policy({"phi_firewall": {"detector_backend": "azure_health"}})


def test_valid_backend_accepted_at_policy_load() -> None:
    cfg = load_policy({"phi_firewall": {"detector_backend": "aws_comprehend_medical"}})
    assert cfg.phi_detector_backend == "aws_comprehend_medical"
