"""PDF rendering for :class:`RegulatoryReport` via WeasyPrint.

The generated PDF is laid out as four sections matching the FDA TPLC /
IEC 62304 expected structure:

1. Cover page (intended use, software version, session id, generation date).
2. Session summary + event-type counts.
3. PHI handling summary + propagation paths.
4. Compliance attestation table.

WeasyPrint is an optional dependency: ``pip install 'clinicsentry[pdf]'``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from clinicsentry.types import RegulatoryReport

__all__ = ["render_report_html", "render_report_pdf"]


_BASE_CSS = """
@page { size: A4; margin: 2cm 1.8cm; }
body { font-family: 'Inter', 'Helvetica Neue', sans-serif; font-size: 10pt; color: #1f2937; }
h1 { font-size: 22pt; margin-bottom: 0.2em; color: #111827; }
h2 { font-size: 14pt; margin-top: 1.4em; color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.2em; }
table { width: 100%; border-collapse: collapse; margin-top: 0.6em; font-size: 9.5pt; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #e5e7eb; }
th { background: #f3f4f6; }
.attest-pass { color: #065f46; font-weight: 600; }
.attest-fail { color: #991b1b; font-weight: 600; }
.cover { text-align: center; margin-top: 4cm; }
.meta { color: #6b7280; font-size: 9pt; }
"""


def render_report_html(report: RegulatoryReport) -> str:
    """Render a :class:`RegulatoryReport` as standalone HTML."""
    meta = report.report_metadata
    summary = report.session_summary
    phi = report.phi_handling_summary
    attest = report.compliance_attestation

    rows_summary = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in [
            ("Session ID", meta.get("session_id", "")),
            ("Framework", meta.get("framework", "")),
            ("Intended use", meta.get("intended_use", "")),
            ("Software version", meta.get("software_version", "")),
            ("Policy version", meta.get("policy_version", "")),
            ("Generated", meta.get("generated_at", "")),
            ("Total events", summary.get("total_events", 0)),
            ("Duration (s)", summary.get("duration_seconds", 0)),
        ]
    )

    attest_rows: list[str] = []
    for k, v in attest.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            satisfied = bool(v.get("satisfied"))
            severity = str(v.get("severity", ""))
            reason = str(v.get("reason", ""))
        else:
            satisfied = bool(v)
            severity = ""
            reason = ""
        cls = "attest-pass" if satisfied else "attest-fail"
        label = "PASS" if satisfied else "FAIL"
        attest_rows.append(
            f"<tr><td>{k}</td><td>{severity}</td>"
            f"<td class='{cls}'>{label}</td><td>{reason}</td></tr>"
        )
    rows_attest = "".join(attest_rows)

    rows_phi = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in [
            ("PHI detected", phi.get("phi_detected_count", 0)),
            ("PHI redacted", phi.get("phi_redacted_count", 0)),
            ("Minimum-necessary enforced", phi.get("minimum_necessary_enforced", False)),
        ]
    )

    iec_section = ""
    if report.iec62304_section is not None:
        rows_iec = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in report.iec62304_section.items()
        )
        iec_section = f"<h2>IEC 62304 Section</h2><table>{rows_iec}</table>"

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>ClinicSentry Regulatory Report</title>
<style>{_BASE_CSS}</style></head><body>
<section class='cover'>
  <h1>ClinicSentry Regulatory Report</h1>
  <p class='meta'>Generated {datetime.now(UTC).isoformat()}</p>
</section>
<h2>Session Summary</h2><table>{rows_summary}</table>
<h2>PHI Handling</h2><table>{rows_phi}</table>
<h2>Compliance Attestation</h2><table>{rows_attest}</table>
{iec_section}
</body></html>"""


def render_report_pdf(report: RegulatoryReport, output_path: str | Path) -> Path:
    """Render ``report`` to a PDF at ``output_path``.

    Raises:
        ImportError: if weasyprint is not installed.
    """
    try:  # pragma: no cover - optional dep
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "PDF rendering requires WeasyPrint. Install: `pip install 'clinicsentry[pdf]'`."
        ) from exc

    html = render_report_html(report)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(str(out))
    return out
