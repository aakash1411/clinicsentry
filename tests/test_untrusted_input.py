"""Stress tests for untrusted public input: ReDoS, oversized and hostile payloads.

A public security library must stay O(n)-ish on adversarially-constructed
inputs — catastrophic regex backtracking or unbounded decode work on the scan
hot path is a denial-of-service vector. Each test asserts a generous wall-time
bound (CI machines are slow; the point is catching super-linear blowups, not
micro-benchmarks).
"""

from __future__ import annotations

import time

import pytest

from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.detectors import RegexDetector
from clinicsentry.phi.firewall import PHIFirewall

WALL_LIMIT_S = 2.0


def _timed_scan(fw: PHIFirewall, payload: object) -> float:
    start = time.perf_counter()
    fw.scan(payload, origin_agent="stress")
    return time.perf_counter() - start


@pytest.fixture(scope="module")
def fw() -> PHIFirewall:
    return PHIFirewall()


# ---------------------------------------------------------------------------
# ReDoS probes against every shipped pattern's worst-case neighborhood
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        # EMAIL: long run of local-part chars with no @, then dots
        "a" * 50_000,
        "a" * 20_000 + "@" + "b." * 10_000,
        "@" * 10_000,
        # PHONE/SSN/DATE: digit-and-separator soup
        ("123-45-678 " * 5_000),
        ("12/34/56 " * 5_000),
        "9" * 50_000,
        # URL: no terminating whitespace
        "https://" + "x" * 50_000,
        # base64-ish: alphabet run just below/above validity
        "A" * 49_999,  # not % 4
        "A" * 48_000,  # valid length, decodes to junk
        # percent-escape soup
        "%41" * 15_000,
        "%" * 50_000,
        # invisible-character flood
        "​" * 50_000 + "SSN 123-45-6789",
        # homoglyph flood
        "а" * 50_000,
    ],
)
def test_hostile_strings_complete_within_bound(fw: PHIFirewall, hostile: str) -> None:
    assert _timed_scan(fw, hostile) < WALL_LIMIT_S


def test_regex_detector_alone_is_linear_ish(fw: PHIFirewall) -> None:
    """Doubling input size must not blow up runtime super-linearly."""
    det = RegexDetector()
    base = ("Patient note " + "a" * 200 + " SSN 123-45-6789 ") * 50

    def run(text: str) -> float:
        start = time.perf_counter()
        det.detect(text)
        return time.perf_counter() - start

    t1 = run(base)
    t2 = run(base * 4)
    # Allow generous noise: 4x input should stay under ~16x time.
    assert t2 < max(t1 * 16, 0.5)


# ---------------------------------------------------------------------------
# Oversized / deeply hostile structured payloads
# ---------------------------------------------------------------------------


def test_wide_payload_completes(fw: PHIFirewall) -> None:
    payload = {f"k{i}": f"value {i}" for i in range(20_000)}
    assert _timed_scan(fw, payload) < WALL_LIMIT_S


def test_many_small_messages_completes(fw: PHIFirewall) -> None:
    msgs = [{"role": "user", "content": f"note {i} jane{i}@example.com"} for i in range(5_000)]
    assert _timed_scan(fw, msgs) < WALL_LIMIT_S


def test_megabyte_note_completes_and_redacts(fw: PHIFirewall) -> None:
    note = ("Lorem ipsum dolor sit amet. " * 10_000) + "SSN: 123-45-6789"
    start = time.perf_counter()
    result = fw.scan(note, origin_agent="stress")
    assert time.perf_counter() - start < WALL_LIMIT_S
    assert "123-45-6789" not in str(result.redacted)


def test_guard_full_pipeline_under_hostile_load() -> None:
    """End-to-end: hostile inputs through guard scan + evaluate + end_session."""
    with ClinicSentry(framework="stress") as guard:
        guard.firewall.scan("%41" * 5_000, origin_agent="stress")
        guard.firewall.scan(["​" * 1_000 + "x"] * 100, origin_agent="stress")
        guard.evaluate_action("nope", reasoning_text="Confidence: 99%")
    ok, errors = guard.verify_audit_chain()
    assert ok, errors
