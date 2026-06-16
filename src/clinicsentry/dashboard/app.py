"""FastAPI app factory for the ClinicSentry dashboard.

The five pages are returned as HTML strings with embedded HTMX directives so
no client-side build step is required. PHI is never rendered to the browser:
templates show ``tag_id`` and category counts only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clinicsentry.audit.backend import AuditBackend, FileAuditBackend, SqliteAuditBackend
from clinicsentry.audit.chain import AuditChain
from clinicsentry.audit.report import build_report
from clinicsentry.policy import load_policy

__all__ = ["create_app"]


def _html(body: str, *, title: str = "ClinicSentry Dashboard") -> str:
    """Wrap a body fragment in a minimal HTML shell with HTMX and Tailwind CDN."""
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>{title}</title>
<script src='https://unpkg.com/htmx.org@2.0.0'></script>
<script src='https://cdn.tailwindcss.com'></script>
<script src='https://unpkg.com/cytoscape@3.30.0/dist/cytoscape.min.js'></script>
</head>
<body class='bg-gray-50 text-gray-800 font-sans'>
<header class='bg-white border-b shadow-sm px-6 py-3'>
  <a href='/' class='text-xl font-semibold text-blue-600'>ClinicSentry</a>
  <nav class='inline-block ml-8 text-sm text-gray-600 space-x-4'>
    <a href='/' class='hover:underline'>Sessions</a>
    <a href='/policy' class='hover:underline'>Policy</a>
  </nav>
</header>
<main class='p-6 max-w-6xl mx-auto'>{body}</main>
</body></html>"""


def _resolve_backend(path: str | Path) -> AuditBackend:
    """Pick a backend by file extension."""
    p = Path(path)
    if p.suffix in {".sqlite", ".db", ".sqlite3"}:
        return SqliteAuditBackend(str(p))
    return FileAuditBackend(str(p))


def create_app(
    *,
    audit_path: str | Path = "./clinicsentry_audit.sqlite",
    policy_path: str | Path | None = None,
) -> Any:
    """Construct a FastAPI app bound to ``audit_path``.

    Args:
        audit_path: path to the JSONL or SQLite audit log.
        policy_path: optional path to a policy.yaml for the editor page.

    Returns:
        A ``FastAPI`` instance (typed as ``Any`` so import is optional).

    Raises:
        ImportError: if FastAPI is not installed.
    """
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Dashboard requires FastAPI. Install: `pip install 'clinicsentry[dashboard]'`."
        ) from exc

    app: Any = FastAPI(title="ClinicSentry Dashboard")
    backend = _resolve_backend(audit_path)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        """Recent sessions overview."""
        rows = []
        for sid in backend.list_sessions()[:50]:
            events = list(backend.read_session(sid))
            rows.append(
                f"<tr class='hover:bg-blue-50'>"
                f"<td class='p-2'><a class='text-blue-600 underline' href='/session/{sid}'>{sid[:8]}…</a></td>"
                f"<td class='p-2'>{len(events)}</td>"
                f"<td class='p-2'><a href='/propagation/{sid}' class='text-blue-600 underline'>graph</a></td>"
                f"<td class='p-2'><a href='/compliance/{sid}' class='text-blue-600 underline'>attestation</a></td>"
                f"</tr>"
            )
        body = (
            "<h1 class='text-2xl font-semibold mb-4'>Sessions</h1>"
            "<table class='w-full text-sm bg-white shadow rounded'>"
            "<thead class='bg-gray-100'><tr>"
            "<th class='text-left p-2'>Session</th><th class='text-left p-2'>Events</th>"
            "<th class='text-left p-2'>Propagation</th><th class='text-left p-2'>Compliance</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=4 class=p-3>No sessions.</td></tr>'}</tbody></table>"
        )
        return _html(body)

    @app.get("/session/{session_id}", response_class=HTMLResponse)
    def session(session_id: str) -> str:
        """Audit log explorer."""
        events = list(backend.read_session(session_id))
        if not events:
            raise HTTPException(status_code=404, detail="session not found")
        rows = "".join(
            f"<tr><td class='p-2'>{e.sequence_number}</td>"
            f"<td class='p-2'>{e.event_type.value}</td>"
            f"<td class='p-2'>{e.agent_id}</td>"
            f"<td class='p-2'>{e.risk_tier.value if e.risk_tier else ''}</td>"
            f"<td class='p-2'>{e.confidence_score if e.confidence_score is not None else ''}</td>"
            f"<td class='p-2'>{len(e.phi_tags_detected)}</td></tr>"
            for e in events
        )
        body = (
            f"<h1 class='text-2xl font-semibold mb-2'>Session {session_id[:8]}…</h1>"
            f"<p class='text-sm text-gray-600 mb-4'>{len(events)} events</p>"
            "<table class='w-full text-sm bg-white shadow rounded'>"
            "<thead class='bg-gray-100'><tr>"
            "<th class='text-left p-2'>Seq</th><th class='text-left p-2'>Type</th>"
            "<th class='text-left p-2'>Agent</th><th class='text-left p-2'>Tier</th>"
            "<th class='text-left p-2'>Confidence</th><th class='text-left p-2'>PHI tags</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
        return _html(body)

    @app.get("/propagation/{session_id}", response_class=HTMLResponse)
    def propagation(session_id: str) -> str:
        """Render the PHI propagation graph via Cytoscape.js."""
        events = list(backend.read_session(session_id))
        # Build edges from inter-agent / a2a messages.
        edge_pairs: list[tuple[str, str]] = []
        agents: set[str] = set()
        for e in events:
            if e.event_type.value in {"inter_agent_message", "a2a_message"}:
                src = e.agent_id
                dst_obj = (
                    e.redacted_output.get("to") if isinstance(e.redacted_output, dict) else None
                )
                if isinstance(dst_obj, str):
                    agents.update([src, dst_obj])
                    edge_pairs.append((src, dst_obj))
        nodes_json = ",".join(f'{{"data": {{"id": "{a}"}}}}' for a in agents)
        edges_json = ",".join(
            f'{{"data": {{"source": "{src}", "target": "{dst}"}}}}' for src, dst in edge_pairs
        )
        body = (
            f"<h1 class='text-2xl font-semibold mb-4'>Propagation graph — {session_id[:8]}…</h1>"
            "<div id='cy' style='width:100%;height:560px;background:white' class='shadow rounded'></div>"
            "<script>"
            "cytoscape({container: document.getElementById('cy'),"
            f"elements: [{nodes_json},{edges_json}],"
            "style: [{selector: 'node', style: {label: 'data(id)', 'background-color': '#3b82f6'}},"
            "{selector: 'edge', style: {'curve-style': 'bezier', 'target-arrow-shape': 'triangle'}}],"
            "layout: {name: 'breadthfirst'} });"
            "</script>"
        )
        return _html(body)

    @app.get("/policy", response_class=HTMLResponse)
    def policy_editor() -> str:
        """Policy YAML editor with HTMX live-validation."""
        body = (
            "<h1 class='text-2xl font-semibold mb-4'>Policy</h1>"
            "<form hx-post='/policy/validate' hx-target='#result' hx-swap='innerHTML' class='space-y-3'>"
            "<textarea name='yaml' rows='20' class='w-full font-mono text-sm bg-white p-3 shadow rounded'></textarea>"
            "<button class='bg-blue-600 text-white px-4 py-2 rounded' type='submit'>Validate</button>"
            "</form>"
            "<div id='result' class='mt-4'></div>"
        )
        return _html(body)

    @app.post("/policy/validate", response_class=JSONResponse)
    def policy_validate(yaml: str = "") -> dict[str, Any]:
        """Validate posted YAML and return structured result."""
        from dataclasses import asdict

        try:
            cfg = load_policy(yaml)
        except Exception as exc:  # noqa: BLE001 — surface any parse error
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "resolved": asdict(cfg)}

    @app.get("/compliance/{session_id}", response_class=HTMLResponse)
    def compliance(session_id: str) -> str:
        """Render the compliance attestation table for a session."""
        events = list(backend.read_session(session_id))
        report = build_report(
            session_id=session_id,
            events=events,
            framework="dashboard",
            policy_version="dashboard",
            phi_tags={},
            propagation_edges={},
        )
        rule_rows: list[str] = []
        for k, v in report.compliance_attestation.items():
            if k.startswith("_"):
                continue
            if isinstance(v, dict):
                satisfied = bool(v.get("satisfied"))
                reason = str(v.get("reason", ""))
                severity = str(v.get("severity", ""))
            else:
                satisfied = bool(v)
                reason = ""
                severity = ""
            color = "text-green-700" if satisfied else "text-red-700"
            label = "PASS" if satisfied else "FAIL"
            rule_rows.append(
                f"<tr><td class='p-2 font-mono'>{k}</td>"
                f"<td class='p-2'>{severity}</td>"
                f"<td class='p-2 {color}'>{label}</td>"
                f"<td class='p-2 text-gray-600'>{reason}</td></tr>"
            )
        rows = "".join(rule_rows)
        body = (
            f"<h1 class='text-2xl font-semibold mb-4'>Compliance — {session_id[:8]}…</h1>"
            "<table class='w-full text-sm bg-white shadow rounded'>"
            "<thead class='bg-gray-100'><tr>"
            "<th class='text-left p-2'>Rule</th>"
            "<th class='text-left p-2'>Severity</th>"
            "<th class='text-left p-2'>Status</th>"
            "<th class='text-left p-2'>Reason</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
        return _html(body)

    @app.get("/healthz/chain", response_class=JSONResponse)
    def healthz_chain(session_id: str | None = None) -> dict[str, Any]:
        """Verify the chain integrity for the latest (or given) session."""
        sessions = backend.list_sessions()
        if not sessions:
            return {"ok": True, "checked": 0}
        target = session_id or sessions[-1]
        chain = AuditChain(session_id=target, secret_key=b"x" * 32, backend=backend)
        ok, errors = chain.verify()
        return {"ok": ok, "errors": errors, "session_id": target}

    return app
