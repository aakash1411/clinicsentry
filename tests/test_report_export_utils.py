"""B10 + B13 + CLI extras: report export, testing utilities, bench/schema commands."""

from __future__ import annotations

import json
import os

import pytest

from clinicsentry.audit.report import report_schema, verify_signed_report
from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.testing import (
    assert_not_redacted,
    assert_redacted,
    synthetic_note,
    synthetic_phi,
)


def _sample_report():
    guard = ClinicSentry(framework="test")
    guard.firewall.scan("SSN 123-45-6789", origin_agent="t")
    return guard.end_session(intended_use="export test"), guard.secret_key


# --- B10: report export -----------------------------------------------------------


def test_report_to_html(tmp_path) -> None:
    report, _ = _sample_report()
    out = tmp_path / "report.html"
    html = report.to_html(out)
    assert out.exists()
    assert "<html" in html.lower()
    assert "compliance" in html.lower()


def test_report_signed_export_roundtrip(tmp_path) -> None:
    report, key = _sample_report()
    path = tmp_path / "report.json"
    written, sig = report.export_signed(path, key)
    assert written.exists()
    assert sig.exists()
    assert verify_signed_report(path, key)
    # any byte change must invalidate the signature
    path.write_bytes(path.read_bytes().replace(b"export test", b"tampered!!!"))
    assert not verify_signed_report(path, key)


def test_signed_export_wrong_key_fails(tmp_path) -> None:
    report, key = _sample_report()
    path = tmp_path / "r.json"
    report.export_signed(path, key)
    assert not verify_signed_report(path, os.urandom(32))


def test_report_schema_accepts_real_report() -> None:
    schema = report_schema()
    report, _ = _sample_report()
    payload = json.loads(json.dumps(report.to_dict(), default=str))
    try:
        import jsonschema
    except ImportError:
        assert set(schema["required"]) <= set(payload)
        return
    jsonschema.validate(payload, schema)


def test_report_to_pdf_requires_weasyprint(tmp_path) -> None:
    report, _ = _sample_report()
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        with pytest.raises(Exception, match="weasyprint|pdf"):
            report.to_pdf(tmp_path / "r.pdf")
    else:
        assert report.to_pdf(tmp_path / "r.pdf").exists()


# --- B13: testing utilities ---------------------------------------------------------


def test_synthetic_phi_and_assert_redacted() -> None:
    guard = ClinicSentry(framework="test")
    assert_redacted(guard, synthetic_phi("ssn"), expect="SSN")
    assert_redacted(guard.firewall, synthetic_phi("device_id"), expect="DEVICE_ID")


def test_assert_redacted_failure_message() -> None:
    guard = ClinicSentry(framework="test")
    with pytest.raises(AssertionError, match="found none"):
        assert_redacted(guard, "nothing sensitive here")


def test_assert_not_redacted() -> None:
    assert_not_redacted(PHIFirewall(), "see manual US-DBA-2500685 page 42")
    with pytest.raises(AssertionError, match="unchanged"):
        assert_not_redacted(PHIFirewall(), "SSN 123-45-6789")


def test_every_us_sample_is_detected_by_matching_type() -> None:
    fw = PHIFirewall(detectors=None)
    opted = PHIFirewall(
        detectors=[
            *(
                s.label
                for s in __import__("clinicsentry.phi.detectors", fromlist=["x"]).core_specs()
            ),
            "VIN",
        ]
    )
    for kind in (
        "ssn",
        "email",
        "phone",
        "fax",
        "mrn",
        "npi",
        "dea",
        "device_id",
        "udi",
        "account",
        "member_id",
    ):
        assert_redacted(fw, synthetic_phi(kind), expect=kind.upper())
    assert_redacted(opted, synthetic_phi("vin"), expect="VIN")


def test_locale_samples_detected() -> None:
    gb = PHIFirewall(locales=["en_GB"])
    assert_redacted(gb, synthetic_phi("nhs_number", locale="en_GB"), expect="NHS_NUMBER")
    ca = PHIFirewall(locales=["en_CA"])
    assert_redacted(ca, synthetic_phi("ca_sin", locale="en_CA"), expect="CA_SIN")


def test_synthetic_note_contains_many_types() -> None:
    fw = PHIFirewall()
    result = fw.scan(synthetic_note())
    assert len(result.by_type) >= 8


def test_unknown_kind_and_locale_raise() -> None:
    with pytest.raises(ValueError, match="kind"):
        synthetic_phi("dna")
    with pytest.raises(ValueError, match="locale"):
        synthetic_phi("ssn", locale="xx_XX")


# --- CLI extras ------------------------------------------------------------------


def test_bench_cli_smoke(capsys) -> None:
    from clinicsentry.cli import main as cli_main

    rc = cli_main(["bench", "--n", "3"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ascii_3kb" in out
    assert "p95_ms" in out
