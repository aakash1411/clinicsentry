"""Adversarial robustness suite for the PHI detection stack.

Each test encodes one evasion technique and checks that the detection pipeline
(the same :class:`AdversarialDetector` + :class:`EncodedPHIDetector` stack the
:class:`PHIFirewall` runs in production) recovers the embedded PHI.
"""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from clinicsentry.phi.adversarial import (
    AdversarialDetector,
    AdversarialNormalizer,
    EncodedPHIDetector,
)
from clinicsentry.phi.detectors import RegexDetector
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.phi.pipeline import DetectorPipeline


@pytest.fixture
def detector() -> DetectorPipeline:
    """Production-equivalent stack: normalizing + encoded-token detectors."""
    regex = RegexDetector()
    return DetectorPipeline(
        detectors=[AdversarialDetector(inner=regex), EncodedPHIDetector(inner=regex)]
    )


@pytest.fixture
def raw_detector() -> RegexDetector:
    """Plain regex detector (no normalization) — used as comparison baseline."""
    return RegexDetector()


# ---------------------------------------------------------------------------
# Homoglyph / unicode confusable attacks
# ---------------------------------------------------------------------------


def test_cyrillic_homoglyph_in_email_is_caught(detector: DetectorPipeline) -> None:
    text = "Contact: jane.doe@\u0435xample.com"  # Cyrillic 'е'
    hits = detector.detect(text)
    assert any(h.phi_type == "EMAIL" for h in hits)


def test_zero_width_in_email_is_caught(detector: DetectorPipeline) -> None:
    text = "Contact: jane\u200b.doe@example.com"
    hits = detector.detect(text)
    assert any(h.phi_type == "EMAIL" for h in hits)


def test_zero_width_in_ssn_is_caught(detector: DetectorPipeline) -> None:
    text = "SSN: 123\u200b-45-6789"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


def test_mathematical_digits_in_ssn_are_caught(detector: DetectorPipeline) -> None:
    """Mathematical bold digits should be normalized via NFKC / homoglyph map."""
    text = "SSN: \U0001d7e3\U0001d7e4\U0001d7e5-\U0001d7e6\U0001d7e7-\U0001d7e8\U0001d7e9\U0001d7ea\U0001d7eb"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


def test_full_width_ascii_email_is_caught(detector: DetectorPipeline) -> None:
    """Full-width ASCII (U+FF01..) is NFKC-normalized to plain ASCII."""
    text = "Email: ｊａｎｅ＠example.com"
    hits = detector.detect(text)
    assert any(h.phi_type == "EMAIL" for h in hits)


def test_bom_at_start_does_not_break_detection(detector: DetectorPipeline) -> None:
    text = "\ufeffSSN: 123-45-6789"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


def test_word_joiner_inside_phone_is_caught(detector: DetectorPipeline) -> None:
    text = "Phone: 555\u2060-123-4567"
    hits = detector.detect(text)
    assert any(h.phi_type == "PHONE" for h in hits)


def test_unaltered_text_still_detects(detector: DetectorPipeline) -> None:
    """Regression: the normalizer must not damage straight ASCII."""
    text = "SSN: 123-45-6789, email: jane@example.com, phone: 555-123-4567"
    hits = detector.detect(text)
    types = {h.phi_type for h in hits}
    assert {"SSN", "EMAIL", "PHONE"}.issubset(types)


# ---------------------------------------------------------------------------
# Normalizer unit-level checks
# ---------------------------------------------------------------------------


def test_normalizer_strips_all_known_invisibles() -> None:
    norm = AdversarialNormalizer()
    raw = "a\u200bb\u200cc\u200dd\ufeffe\u2060f"
    assert norm.normalize(raw) == "abcdef"


def test_normalizer_canonicalizes_cyrillic() -> None:
    norm = AdversarialNormalizer()
    raw = "p\u0430ssw\u043frd"  # Cyrillic а and Cyrillic р
    cleaned = norm.normalize(raw)
    assert "\u0430" not in cleaned
    assert "\u043e" not in cleaned


def test_normalizer_is_idempotent() -> None:
    """Normalizing twice yields the same string."""
    norm = AdversarialNormalizer()
    raw = "SSN: 123\u200b-45-6789"
    once = norm.normalize(raw)
    twice = norm.normalize(once)
    assert once == twice


# ---------------------------------------------------------------------------
# Format-evasion attacks
# ---------------------------------------------------------------------------


def test_phone_with_dots_is_caught(detector: DetectorPipeline) -> None:
    """Existing regex already supports dots."""
    text = "Phone: 555.123.4567"
    hits = detector.detect(text)
    assert any(h.phi_type == "PHONE" for h in hits)


def test_ssn_with_spaces_is_caught(detector: DetectorPipeline) -> None:
    text = "SSN: 123 45 6789"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


# ---------------------------------------------------------------------------
# Encoding attacks
# ---------------------------------------------------------------------------


def test_base64_encoded_ssn_caught(detector: DetectorPipeline) -> None:
    encoded = base64.b64encode(b"123-45-6789").decode()
    hits = detector.detect(f"data: {encoded}")
    assert any(h.phi_type == "SSN" for h in hits)


def test_urlencoded_email_caught(detector: DetectorPipeline) -> None:
    enc = urllib.parse.quote("jane@example.com", safe="")
    hits = detector.detect(f"u={enc}")
    assert any(h.phi_type == "EMAIL" for h in hits)


def test_base64_token_is_redacted_in_full(detector: DetectorPipeline) -> None:
    """The hit must span the whole encoded token, not the decoded offsets."""
    encoded = base64.b64encode(b"SSN: 123-45-6789").decode()
    text = f"payload={encoded}"
    hits = detector.detect(text)
    ssn_hits = [h for h in hits if h.phi_type == "SSN"]
    assert ssn_hits
    assert text[ssn_hits[0].start : ssn_hits[0].end] == encoded


# ---------------------------------------------------------------------------
# Context-manipulation attacks
# ---------------------------------------------------------------------------


def test_phi_inside_json_string(detector: DetectorPipeline) -> None:
    text = '{"contact": "jane@example.com", "ssn": "123-45-6789"}'
    hits = detector.detect(text)
    types = {h.phi_type for h in hits}
    assert "EMAIL" in types
    assert "SSN" in types


def test_phi_inside_markdown_code_block(detector: DetectorPipeline) -> None:
    text = "```\nSSN=123-45-6789\n```"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


def test_phi_split_across_lines_is_caught_per_line(detector: DetectorPipeline) -> None:
    text = "Line 1\nSSN: 123-45-6789\nLine 3"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


def test_phi_in_concatenated_string(detector: DetectorPipeline) -> None:
    text = "x" * 200 + " SSN: 123-45-6789 " + "y" * 200
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


# ---------------------------------------------------------------------------
# Adversarial detector vs. baseline regex (regression baseline)
# ---------------------------------------------------------------------------


def test_normalizer_recovers_what_baseline_misses(
    detector: DetectorPipeline, raw_detector: RegexDetector
) -> None:
    """The whole point: AdversarialDetector should strictly improve recall."""
    text = "SSN: 1\u200b23-45-6789, em\u0430il: jane@\u0435xample.com"
    baseline_hits = raw_detector.detect(text)
    adv_hits = detector.detect(text)
    baseline_types = {h.phi_type for h in baseline_hits}
    adv_types = {h.phi_type for h in adv_hits}
    assert adv_types >= baseline_types
    # And at minimum we recover SSN + EMAIL after normalization.
    assert {"SSN", "EMAIL"}.issubset(adv_types)


# ---------------------------------------------------------------------------
# Multiple-attack composition
# ---------------------------------------------------------------------------


def test_multiple_phi_categories_all_recovered(detector: DetectorPipeline) -> None:
    text = (
        "Patient SSN 1\u200b23-45-6789, "
        "phone (555) 123-4567, "
        "email jane@\u0435xample.com, "
        "MRN: AB-1234567, "
        "DEA: AB1234567"
    )
    hits = detector.detect(text)
    types = {h.phi_type for h in hits}
    # SSN/PHONE/EMAIL must all survive; MRN/DEA are bonus.
    assert {"SSN", "PHONE", "EMAIL"}.issubset(types)


def test_chained_invisibles_dont_crash(detector: DetectorPipeline) -> None:
    """Pathological invisible-heavy input."""
    inv = "\u200b\u200c\u200d\ufeff\u2060" * 100
    text = f"{inv}SSN: 123-45-6789{inv}"
    hits = detector.detect(text)
    assert any(h.phi_type == "SSN" for h in hits)


# ---------------------------------------------------------------------------
# Firewall-level regression: adversarial PHI must be REDACTED, not just found.
# These pin the production scan path (guard.firewall.scan) — prior to the
# offset-mapping normalizer, obfuscated PHI passed through unredacted.
# ---------------------------------------------------------------------------


@pytest.fixture
def firewall() -> PHIFirewall:
    return PHIFirewall()


def test_firewall_redacts_zero_width_ssn(firewall: PHIFirewall) -> None:
    result = firewall.scan("SSN: 123​-45-6789", origin_agent="t")
    assert "6789" not in str(result.redacted)
    assert any(t.phi_type == "SSN" for t in result.tags)


def test_firewall_redacts_homoglyph_email(firewall: PHIFirewall) -> None:
    result = firewall.scan("Contact: jane.doe@еxample.com", origin_agent="t")
    assert "jane.doe" not in str(result.redacted)
    assert any(t.phi_type == "EMAIL" for t in result.tags)


def test_firewall_redacts_percent_encoded_email(firewall: PHIFirewall) -> None:
    enc = urllib.parse.quote("jane@example.com", safe="")
    result = firewall.scan(f"u={enc}", origin_agent="t")
    assert enc not in str(result.redacted)
    assert any(t.phi_type == "EMAIL" for t in result.tags)


def test_firewall_redacts_base64_ssn(firewall: PHIFirewall) -> None:
    encoded = base64.b64encode(b"SSN: 123-45-6789").decode()
    result = firewall.scan(f"data: {encoded}", origin_agent="t")
    assert encoded not in str(result.redacted)
    assert any(t.phi_type == "SSN" for t in result.tags)


def test_firewall_decode_encoded_opt_out() -> None:
    fw = PHIFirewall(decode_encoded=False)
    encoded = base64.b64encode(b"SSN: 123-45-6789").decode()
    result = fw.scan(f"data: {encoded}", origin_agent="t")
    assert not any(t.phi_type == "SSN" for t in result.tags)


def test_firewall_redaction_spans_cover_invisibles(firewall: PHIFirewall) -> None:
    """No fragment of the obfuscated SSN may survive redaction."""
    text = "id 1​2​3-4​5-6​7​8​9 end"
    result = firewall.scan(text, origin_agent="t")
    redacted = str(result.redacted)
    assert "123" not in redacted.replace("​", "")
    assert "789" not in redacted.replace("​", "")
    assert redacted.startswith("id ")
    assert redacted.endswith(" end")
