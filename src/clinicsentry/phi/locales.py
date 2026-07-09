"""Locale detector packs (non-US identifier formats).

Enable via policy::

    phi_firewall:
      locales: [en_GB, de_DE]

High-collision numeric formats carry checksum validators (NHS mod-11, IBAN
mod-97, SIN Luhn) so a random digit run of the right shape is not redacted.
"""

from __future__ import annotations

import re

from clinicsentry.phi.detectors import PatternSpec

__all__ = ["locale_specs", "supported_locales"]


def _nhs_checksum(value: str) -> bool:
    """NHS number mod-11 check (weights 10..2; check digit 11-rem, 11→0, 10→invalid)."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 10:
        return False
    total = sum(d * (10 - i) for i, d in enumerate(digits[:9]))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == digits[9]


def _iban_checksum(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    s = value.replace(" ", "").upper()
    if len(s) < 15:
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def _luhn(value: str) -> bool:
    """Luhn check over the digits of ``value``."""
    digits = [int(c) for c in value if c.isdigit()]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_IBAN = PatternSpec(
    "IBAN",
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    0.97,
    validator=_iban_checksum,
)

_LOCALE_PACKS: dict[str, list[PatternSpec]] = {
    # Core US patterns are always available; en_US is accepted as a no-op so
    # configs can be explicit about their locale list.
    "en_US": [],
    "en_GB": [
        PatternSpec(
            "NHS_NUMBER",
            re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b"),
            0.97,
            validator=_nhs_checksum,
        ),
        PatternSpec(
            "UK_NINO",
            re.compile(
                r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z]"
                r"\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"
            ),
            0.95,
        ),
        _IBAN,
    ],
    "de_DE": [
        PatternSpec(
            "DE_PHONE",
            # No leading \b: there is no word boundary between a space and "+".
            re.compile(
                r"(?:\+49|0049)[ \-/]?(?:\(0\)[ \-/]?)?\d{2,5}[ \-/]?\d{3,}(?:[ \-/]?\d+)?\b"
            ),
            0.90,
        ),
        _IBAN,
    ],
    "en_CA": [
        # Separators required: an unseparated 9-digit run is too collision-prone
        # even with Luhn.
        PatternSpec(
            "CA_SIN",
            re.compile(r"\b\d{3}[ -]\d{3}[ -]\d{3}\b"),
            0.90,
            validator=_luhn,
        ),
        _IBAN,
    ],
}


def supported_locales() -> list[str]:
    """Return the locale identifiers this build ships packs for."""
    return sorted(_LOCALE_PACKS)


def locale_specs(locale: str) -> list[PatternSpec]:
    """Return the detector specs for ``locale``.

    Raises:
        ValueError: for an unknown locale identifier.
    """
    try:
        return list(_LOCALE_PACKS[locale])
    except KeyError:
        raise ValueError(
            f"unsupported locale {locale!r}; supported: {supported_locales()}"
        ) from None
