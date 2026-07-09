"""B4 + B7 + B8: async/batch scanning, AUDIT_ONLY shadow mode, metric hooks."""

from __future__ import annotations

from clinicsentry.guard import ClinicSentry
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.phi.redaction import RedactionMode

# --- B4: async + batch ----------------------------------------------------------


async def test_ascan_matches_sync_scan() -> None:
    fw = PHIFirewall()
    sync = fw.scan("SSN 123-45-6789")
    result = await fw.ascan("SSN 123-45-6789")
    assert result.redacted == sync.redacted


def test_scan_batch_is_index_aligned() -> None:
    fw = PHIFirewall()
    results = fw.scan_batch(["SSN 123-45-6789", "clean", {"n": "jane@example.com"}])
    assert "[REDACTED:SSN]" in str(results[0].redacted)
    assert results[1].redacted == "clean"
    assert "[REDACTED:EMAIL]" in str(results[2].redacted["n"])


# --- B7: AUDIT_ONLY shadow mode ---------------------------------------------------


def test_audit_only_passes_text_through_but_records_findings() -> None:
    guard = ClinicSentry(policy={"phi_firewall": {"mode": "AUDIT_ONLY"}}, framework="shadow")
    scan = guard.firewall.scan({"note": "SSN 123-45-6789"})
    assert scan.redacted == {"note": "SSN 123-45-6789"}
    assert scan.has_phi
    assert scan.findings[0].action == "AUDIT_ONLY"
    assert scan.findings[0].replacement is None
    # tags still flow into propagation for the audit trail
    assert any(t.phi_type == "SSN" for t in guard.propagation.tags.values())


def test_audit_only_per_type_override() -> None:
    fw = PHIFirewall(overrides={"PHONE": RedactionMode.AUDIT_ONLY})
    out = fw.scan("call 555-123-4567, SSN 123-45-6789")
    assert "555-123-4567" in str(out.redacted)  # shadow for PHONE
    assert "123-45-6789" not in str(out.redacted)  # SSN still redacted


# --- B8: metric hooks --------------------------------------------------------------


def test_metrics_emitted_for_scan_and_redactions() -> None:
    seen: list[tuple[str, float, dict[str, str]]] = []
    fw = PHIFirewall(on_metric=lambda n, v, t: seen.append((n, v, t)))
    fw.scan("SSN 123-45-6789")
    names = [n for n, _, _ in seen]
    assert "clinicsentry.scan.latency_ms" in names
    assert ("clinicsentry.phi.redactions", 1.0, {"type": "SSN"}) in seen
    assert any(n == "clinicsentry.scan.path" and t == {"path": "fast"} for n, _, t in seen)


def test_metrics_report_normalized_path_for_adversarial_input() -> None:
    seen: list[dict[str, str]] = []
    fw = PHIFirewall(
        on_metric=lambda n, v, t: seen.append(t) if n == "clinicsentry.scan.path" else None
    )
    fw.scan("SSN: 123​-45-6789")
    assert {"path": "normalized"} in seen


def test_metric_callback_errors_never_break_scan() -> None:
    def boom(name: str, value: float, tags: dict[str, str]) -> None:
        raise RuntimeError("sink down")

    fw = PHIFirewall(on_metric=boom)
    out = fw.scan("SSN 123-45-6789")
    assert "[REDACTED:SSN]" in str(out.redacted)


def test_guard_forwards_metric_hook() -> None:
    seen: list[str] = []
    guard = ClinicSentry(framework="t", on_metric=lambda n, v, t: seen.append(n))
    guard.firewall.scan("SSN 123-45-6789")
    assert "clinicsentry.scan.latency_ms" in seen
