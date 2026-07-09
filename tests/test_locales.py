"""B3: locale detector packs with checksum validation."""

from __future__ import annotations

import pytest

from clinicsentry.errors import PolicyError
from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.phi.locales import supported_locales
from clinicsentry.policy import load_policy


def test_nhs_number_valid_checksum_redacted() -> None:
    fw = PHIFirewall(locales=["en_GB"])
    out = fw.scan("NHS number 943 476 5919")
    assert "943 476 5919" not in str(out.redacted)
    assert any(f.phi_type == "NHS_NUMBER" for f in out.findings)


def test_nhs_number_bad_checksum_not_typed_as_nhs() -> None:
    """A mod-11 failure must not produce an NHS_NUMBER finding (the digit run
    may still legitimately match other detectors such as PHONE)."""
    fw = PHIFirewall(locales=["en_GB"])
    out = fw.scan("ref 943 476 5918")  # fails mod-11
    assert not any(f.phi_type == "NHS_NUMBER" for f in out.findings)


def test_uk_nino_redacted() -> None:
    fw = PHIFirewall(locales=["en_GB"])
    out = fw.scan("NINO AB 12 34 56 C")
    assert any(f.phi_type == "UK_NINO" for f in out.findings)


def test_uk_nino_placeholder_prefix_rejected() -> None:
    """QQ is the official invalid placeholder prefix and must not match."""
    fw = PHIFirewall(locales=["en_GB"])
    out = fw.scan("NINO QQ 12 34 56 C")
    assert not any(f.phi_type == "UK_NINO" for f in out.findings)


def test_iban_mod97_validated() -> None:
    fw = PHIFirewall(locales=["de_DE"])
    good = fw.scan("IBAN DE89370400440532013000")
    assert any(f.phi_type == "IBAN" for f in good.findings)
    bad = "IBAN DE89370400440532013001"  # mod-97 fails
    assert fw.scan(bad).redacted == bad


def test_de_phone() -> None:
    fw = PHIFirewall(locales=["de_DE"])
    out = fw.scan("Tel +49 30 123456")
    assert any(f.phi_type == "DE_PHONE" for f in out.findings)


def test_ca_sin_luhn_validated() -> None:
    fw = PHIFirewall(locales=["en_CA"])
    good = fw.scan("SIN 046-454-286")
    assert any(f.phi_type == "CA_SIN" for f in good.findings)
    bad = "SIN 046-454-287"
    assert fw.scan(bad).redacted == bad


def test_locales_do_not_disable_us_core() -> None:
    fw = PHIFirewall(locales=["en_GB"])
    out = fw.scan("SSN 123-45-6789")
    assert any(f.phi_type == "SSN" for f in out.findings)


def test_locales_via_policy() -> None:
    guard = ClinicSentry(policy={"phi_firewall": {"locales": ["en_US", "en_GB"]}}, framework="test")
    out = guard.firewall.scan("NHS number 943 476 5919")
    assert any(f.phi_type == "NHS_NUMBER" for f in out.findings)


def test_unknown_locale_rejected_at_load() -> None:
    with pytest.raises(PolicyError, match="locales"):
        load_policy({"phi_firewall": {"locales": ["fr_XX"]}})


def test_supported_locales_listing() -> None:
    assert {"en_US", "en_GB", "de_DE", "en_CA"} <= set(supported_locales())
