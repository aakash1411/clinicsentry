"""Test helpers for teams validating their own policies.

Everything here uses synthetic identifiers only. ``assert_redacted`` raises
``AssertionError`` with a useful message, so it works under pytest or plain
``assert``-style harnesses without a pytest dependency.

Example::

    from clinicsentry.testing import synthetic_phi, assert_redacted

    assert_redacted(guard, synthetic_phi("ssn"), expect="SSN")
"""

from __future__ import annotations

from typing import Any

__all__ = ["synthetic_phi", "synthetic_note", "assert_redacted", "assert_not_redacted"]

# Synthetic sample values per detector label, keyed by locale.
_SAMPLES: dict[str, dict[str, str]] = {
    "en_US": {
        "ssn": "SSN: 123-45-6789",
        "email": "reach me at jane.doe@example.com",
        "phone": "call (555) 123-4567",
        "fax": "fax: 555-123-9876",
        "mrn": "MRN: 12345678",
        "npi": "NPI: 1234567890",
        "dea": "DEA: AB1234567",
        "date": "seen on 2026-03-01",
        "zip": "zip 94110-1234",
        "url": "see https://example.com/visit/1",
        "ip_address": "from 203.0.113.7",
        "device_id": "pump serial SN NG1234567A",
        "udi": "UDI (01)00844588003288(21)XYZ98765",
        "account": "account number: 12345678",
        "member_id": "member id: XYZ1234567",
        "vin": "vehicle 1HGCM82633A004352",
    },
    "en_GB": {
        # 943-476-5919 satisfies the NHS mod-11 check.
        "nhs_number": "NHS number 943 476 5919",
        "uk_nino": "NINO AB 12 34 56 C",
    },
    "en_CA": {
        # 046-454-286 satisfies Luhn.
        "ca_sin": "SIN 046-454-286",
    },
    "de_DE": {
        "de_phone": "Tel +49 30 123456",
        "iban": "IBAN DE89370400440532013000",
    },
}


def synthetic_phi(kind: str, locale: str = "en_US") -> str:
    """Return a synthetic text snippet containing one identifier of ``kind``."""
    try:
        samples = _SAMPLES[locale]
    except KeyError:
        raise ValueError(f"unknown locale {locale!r}; available: {sorted(_SAMPLES)}") from None
    try:
        return samples[kind.lower()]
    except KeyError:
        raise ValueError(
            f"unknown kind {kind!r} for {locale}; available: {sorted(samples)}"
        ) from None


def synthetic_note(locale: str = "en_US") -> str:
    """Return one note containing every sample identifier for ``locale``."""
    return " ".join(_SAMPLES.get(locale, _SAMPLES["en_US"]).values())


def _firewall_of(scanner: Any) -> Any:
    """Accept a ClinicSentry, a PHIFirewall, or anything with .scan()."""
    return getattr(scanner, "firewall", scanner)


def assert_redacted(scanner: Any, text: str, expect: str | None = None) -> None:
    """Assert that scanning ``text`` detects (and by default redacts) PHI.

    Args:
        scanner: a ``ClinicSentry`` or ``PHIFirewall``.
        text: input to scan.
        expect: optionally require a specific PHI type among the findings.
    """
    result = _firewall_of(scanner).scan(text, origin_agent="testing")
    if not result.has_phi:
        raise AssertionError(f"expected PHI to be detected in {text!r}, found none")
    if expect is not None:
        types = {f.phi_type for f in result.findings} | {t.phi_type for t in result.tags}
        if expect.upper() not in types:
            raise AssertionError(
                f"expected a {expect.upper()} finding in {text!r}; got {sorted(types)}"
            )


def assert_not_redacted(scanner: Any, text: str) -> None:
    """Assert that scanning ``text`` leaves it byte-identical (no findings)."""
    result = _firewall_of(scanner).scan(text, origin_agent="testing")
    if result.redacted != text:
        raise AssertionError(
            f"expected {text!r} to pass through unchanged; got {result.redacted!r}"
        )
    if result.has_phi:
        types = sorted({f.phi_type for f in result.findings})
        raise AssertionError(f"expected no findings in {text!r}; got {types}")
