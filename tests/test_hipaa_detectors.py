"""A2 + A3: device/UDI detectors and expanded HIPAA-18 coverage."""

from __future__ import annotations

import pytest

from clinicsentry.phi.detectors import RegexDetector, known_labels, resolve_specs
from clinicsentry.phi.firewall import PHIFirewall


@pytest.fixture
def fw() -> PHIFirewall:
    return PHIFirewall()


# --- A2: device serials / UDI ------------------------------------------------


def test_pump_serial_redacted_anchor_preserved(fw: PHIFirewall) -> None:
    out = fw.scan({"note": "My pump serial is SN NG1234567A"})
    assert out.redacted["note"] == "My pump serial is SN [REDACTED:DEVICE_ID]"


def test_serial_number_label_variant(fw: PHIFirewall) -> None:
    out = fw.scan("serial number: 123456-AB")
    assert out.redacted == "serial number: [REDACTED:DEVICE_ID]"


def test_lot_and_device_id_variants(fw: PHIFirewall) -> None:
    assert "[REDACTED:DEVICE_ID]" in str(fw.scan("lot no. ABC12345").redacted)
    assert "[REDACTED:DEVICE_ID]" in str(fw.scan("device id: XK-99201-B").redacted)


def test_udi_gs1_redacted(fw: PHIFirewall) -> None:
    out = fw.scan("UDI (01)00844588003288(21)XYZ98765")
    assert out.redacted == "UDI [REDACTED:UDI]"


def test_document_ids_not_redacted(fw: PHIFirewall) -> None:
    """Unanchored alphanumerics (manual refs, page refs) must pass through."""
    text = "see manual US-DBA-2500685 page 42"
    assert fw.scan(text).redacted == text


def test_serialized_prose_not_redacted(fw: PHIFirewall) -> None:
    text = "the serialized payload has 123456 rows"
    assert fw.scan(text).redacted == text


# --- A3: fax / account / member id / VIN --------------------------------------


def test_fax_detected_as_fax_not_phone(fw: PHIFirewall) -> None:
    out = fw.scan("fax: 555-123-9876")
    assert out.redacted == "fax: [REDACTED:FAX]"


def test_account_number(fw: PHIFirewall) -> None:
    out = fw.scan("account number: 12345678")
    assert out.redacted == "account number: [REDACTED:ACCOUNT]"


def test_member_id_variants(fw: PHIFirewall) -> None:
    assert "[REDACTED:MEMBER_ID]" in str(fw.scan("member id: XYZ1234567").redacted)
    assert "[REDACTED:MEMBER_ID]" in str(fw.scan("policy number: P-12345678").redacted)
    assert "[REDACTED:MEMBER_ID]" in str(fw.scan("subscriber id ABC998877").redacted)


def test_privacy_policy_prose_not_redacted(fw: PHIFirewall) -> None:
    text = "please read our privacy policy 2024 update"
    assert fw.scan(text).redacted == text


def test_vin_is_opt_in() -> None:
    vin = "vehicle 1HGCM82633A004352"
    default = PHIFirewall()
    assert default.scan(vin).redacted == vin
    opted = PHIFirewall(detectors=[*[s.label for s in resolve_specs()], "VIN"])
    assert "[REDACTED:VIN]" in str(opted.scan(vin).redacted)


def test_vin_requires_letters_and_digits() -> None:
    opted = PHIFirewall(detectors=["VIN"])
    all_digits = "12345678901234567"
    assert opted.scan(all_digits).redacted == all_digits


# --- detectors config: explicit selection --------------------------------------


def test_detectors_list_is_authoritative() -> None:
    fw = PHIFirewall(detectors=["EMAIL"])
    out = fw.scan("jane@example.com SSN 123-45-6789")
    assert "[REDACTED:EMAIL]" in str(out.redacted)
    assert "123-45-6789" in str(out.redacted)  # SSN detector disabled


def test_unknown_detector_label_rejected() -> None:
    with pytest.raises(ValueError, match="unknown detector"):
        PHIFirewall(detectors=["NOT_A_DETECTOR"])


def test_known_labels_cover_wishlist_set() -> None:
    labels = known_labels()
    for required in ("DEVICE_ID", "UDI", "FAX", "ACCOUNT", "MEMBER_ID", "VIN", "NHS_NUMBER"):
        assert required in labels


def test_regex_detector_default_specs_unchanged_for_core_types() -> None:
    det = RegexDetector()
    hits = det.detect("SSN 123-45-6789 email jane@example.com")
    assert {h.phi_type for h in hits} == {"SSN", "EMAIL"}
