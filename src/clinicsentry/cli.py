"""``clinicsentry`` command-line interface.

Subcommands:

- ``demo`` — run the worked example end-to-end.
- ``verify <audit>`` — verify the hash chain of an audit log file.
- ``report <audit> --session <id>`` — emit a :class:`RegulatoryReport`.
- ``scan <text>`` — one-shot PHI scan, JSON output.
- ``policy-validate <policy.yaml>`` — validate a policy YAML against the schema.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from clinicsentry.audit.backend import FileAuditBackend, SqliteAuditBackend
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.report import build_report
from clinicsentry.phi.firewall import PHIFirewall
from clinicsentry.policy import load_policy

__all__ = ["main", "build_parser"]


def _cmd_demo(args: argparse.Namespace) -> int:
    """Run the worked example.

    With ``--audit-path`` the demo runs a self-contained synthetic session that
    persists audit events to the given SQLite file. This is the path used by
    the ``dashboard`` service in ``deploy/compose/docker-compose.yml`` to seed
    the shared volume so the dashboard has something to display on first run.
    """
    if args.audit_path:
        return _seed_demo_session(Path(args.audit_path))
    examples = Path(__file__).resolve().parents[2] / "examples" / "clinical_summarizer.py"
    if not examples.exists():
        print(f"Worked example not found at {examples}", file=sys.stderr)
        return 1
    code = compile(examples.read_text(), str(examples), "exec")
    exec(code, {"__name__": "__main__", "__file__": str(examples)})  # noqa: S102  # nosec B102 - runs the repo's own bundled example, not external input
    return 0


def _seed_demo_session(audit_path: Path) -> int:
    """Run a tiny synthetic session that writes audit events to ``audit_path``.

    The session is intentionally minimal: scan a PHI-bearing payload, take one
    informational action, end the session. This is enough to make the
    dashboard non-empty on first compose startup. Idempotent: re-running
    appends a new session rather than overwriting prior events.
    """
    from clinicsentry import ClinicalRiskTier, ClinicSentry
    from clinicsentry.audit.backend import SqliteAuditBackend

    audit_path.parent.mkdir(parents=True, exist_ok=True)
    backend = SqliteAuditBackend(str(audit_path))
    # Explicit key so `clinicsentry verify --secret <hex>` works afterwards.
    demo_key = os.urandom(32)
    guard = ClinicSentry(framework="compose-demo", audit_backend=backend, secret_key=demo_key)

    @guard.register_action(
        tier=ClinicalRiskTier.INFORMATIONAL,
        description="Summarize a visit note (compose demo).",
        required_fields={"note"},
    )
    def summarize(payload: dict[str, str]) -> str:
        return f"Summary of note ({len(payload.get('note', ''))} chars)."

    payload = {
        "note": "Patient John Doe (MRN: 12345678) seen 2025-04-12. Contact: john.doe@example.com.",
        "ssn": "123-45-6789",
    }
    guard.firewall.scan(payload, origin_agent="compose-demo")
    summarize(payload)
    guard.evaluate_action(
        "summarize",
        output_text="brief summary",
        reasoning_text="Confidence: 92%",
        provided_fields={"note"},
    )
    guard.end_session(intended_use="compose-demo seed session")
    print(f"Seeded demo session to {audit_path} (session_id={guard.session_id})")
    print(f"HMAC key (needed for `clinicsentry verify --secret`): {demo_key.hex()}")
    return 0


def _resolve_backend_from_path(path: Path) -> FileAuditBackend | SqliteAuditBackend:
    """Pick the right audit backend by file extension."""
    if path.suffix in {".sqlite", ".db", ".sqlite3"}:
        return SqliteAuditBackend(str(path))
    return FileAuditBackend(str(path))


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify the hash chain in an audit file."""
    path = Path(args.audit)
    if not path.exists():
        print(f"Audit file not found: {path}", file=sys.stderr)
        return 1

    backend = _resolve_backend_from_path(path)
    # AuditChain.verify needs the secret_key used at sign time.
    secret_key = bytes.fromhex(args.secret) if args.secret else b""
    if not secret_key:
        print(
            "warning: --secret not provided; HMAC verification will fail. "
            "Hash chain link verification will still run.",
            file=sys.stderr,
        )

    sessions = sorted(backend.list_sessions())
    if not sessions:
        print("No sessions in audit log.", file=sys.stderr)
        return 1

    failures = 0
    for session_id in sessions:
        chain = AuditChain(
            session_id=session_id, secret_key=secret_key or b"x" * 32, backend=backend
        )
        ok, errors = chain.verify()
        status = "OK" if ok else "FAIL"
        print(f"[{status}] session {session_id}")
        for err in errors:
            print(f"    - {err}")
        if not ok:
            failures += 1
    return 0 if failures == 0 else 2


def _render_compliance_summary(attestation: dict[str, object]) -> str:
    """Render a compact, human-readable compliance summary.

    Skips ``_summary`` and any other underscore-prefixed bookkeeping keys.
    Groups rules by framework and lists failing blockers with their reasons.
    """
    lines: list[str] = []
    summary = attestation.get("_summary")
    if isinstance(summary, dict):
        evaluated = summary.get("rules_evaluated", 0)
        satisfied = summary.get("rules_satisfied", 0)
        failed_blocker = summary.get("rules_failed_blocker", 0)
        lines.append(
            f"Compliance: {satisfied}/{evaluated} rules satisfied, "
            f"{failed_blocker} blocker failure(s)"
        )
    by_framework: dict[str, list[tuple[str, dict[str, object]]]] = {}
    for rule_id, entry in attestation.items():
        if rule_id.startswith("_") or not isinstance(entry, dict):
            continue
        fw = str(entry.get("framework", "other"))
        by_framework.setdefault(fw, []).append((rule_id, entry))
    for fw in sorted(by_framework):
        rows = by_framework[fw]
        passed = sum(1 for _, e in rows if e.get("satisfied"))
        lines.append(f"  {fw}: {passed}/{len(rows)}")
    failures = [
        (rid, e)
        for rid, e in attestation.items()
        if isinstance(e, dict) and not e.get("satisfied", True) and e.get("severity") == "blocker"
    ]
    if failures:
        lines.append("Failed blockers:")
        for rid, e in failures:
            reason = e.get("reason", "")
            lines.append(f"  - {rid}: {reason}")
    return "\n".join(lines)


def _cmd_report(args: argparse.Namespace) -> int:
    """Emit a regulatory report for a session.

    With ``--format json`` (default) the full machine-readable report is
    printed. With ``--format summary`` a compact, human-readable compliance
    summary is printed instead — useful for shell pipelines and dashboards.
    """
    path = Path(args.audit)
    backend = _resolve_backend_from_path(path)
    events = list(backend.read_session(args.session))
    if not events:
        print(f"No events for session {args.session}", file=sys.stderr)
        return 1
    secret_key = bytes.fromhex(args.secret) if args.secret else None
    report = build_report(
        session_id=args.session,
        events=events,
        framework="cli",
        intended_use=args.intended_use,
        policy_version="cli",
        phi_tags={},
        propagation_edges={},
        iec62304=None,
        secret_key=secret_key,
    )
    if args.format == "summary":
        print(_render_compliance_summary(report.compliance_attestation))
    else:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """One-shot PHI scan on a chunk of text."""
    firewall = PHIFirewall()
    result = firewall.scan(args.text, origin_agent="cli")
    out = {
        "redacted": result.redacted,
        "tags": [
            {
                "tag_id": t.tag_id,
                "phi_type": t.phi_type,
                "source": t.source,
                "confidence": t.confidence,
                "redacted_value": t.redacted_value,
            }
            for t in result.tags
        ],
    }
    print(json.dumps(out, indent=2))
    return 0


def _cmd_policy_validate(args: argparse.Namespace) -> int:
    """Load and validate a policy YAML; print the resolved config."""
    from dataclasses import asdict

    try:
        cfg = load_policy(args.policy)
    except Exception as e:  # noqa: BLE001 - report any error to stderr
        print(f"Policy invalid: {e}", file=sys.stderr)
        return 1
    payload = asdict(cfg)
    print(json.dumps(payload, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ``argparse`` parser."""
    parser = argparse.ArgumentParser(
        prog="clinicsentry",
        description="ClinicSentry CLI — compliance middleware utilities.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help="Run the worked example end-to-end.")
    p_demo.add_argument(
        "--audit-path",
        default="",
        help="If set, run a self-contained demo that persists audit events "
        "to this SQLite file. Used by the compose dashboard service to seed "
        "the shared volume on first run.",
    )
    p_demo.set_defaults(func=_cmd_demo)

    p_verify = sub.add_parser("verify", help="Verify a JSONL/SQLite audit chain.")
    p_verify.add_argument("audit", help="Path to JSONL or SQLite audit log.")
    p_verify.add_argument("--secret", default="", help="HMAC key as hex string.")
    p_verify.set_defaults(func=_cmd_verify)

    p_report = sub.add_parser("report", help="Emit a regulatory report.")
    p_report.add_argument("audit", help="Path to JSONL or SQLite audit log.")
    p_report.add_argument("--session", required=True, help="Session id to report on.")
    p_report.add_argument("--intended-use", default="", help="Free-text intended-use string.")
    p_report.add_argument(
        "--format",
        choices=["json", "summary"],
        default="json",
        help="Output format. 'json' for full machine-readable report; "
        "'summary' for a compact compliance summary.",
    )
    p_report.add_argument(
        "--secret",
        default="",
        help="HMAC key as hex string. Required for the chain-integrity rule "
        "to pass; otherwise the corresponding attestation rule will fail.",
    )
    p_report.set_defaults(func=_cmd_report)

    p_scan = sub.add_parser("scan", help="One-shot PHI scan on raw text.")
    p_scan.add_argument("text", help="Text to scan.")
    p_scan.set_defaults(func=_cmd_scan)

    p_pv = sub.add_parser("policy-validate", help="Validate a policy YAML file.")
    p_pv.add_argument("policy", help="Path to policy.yaml.")
    p_pv.set_defaults(func=_cmd_policy_validate)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entrypoint for ``python -m clinicsentry`` and the ``clinicsentry`` script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
