"""ClinicSentry web dashboard (FastAPI + HTMX).

Capped at 5 pages and ~3,000 LOC per the Phase 3F scope.

Pages:

- ``/`` — recent sessions overview.
- ``/session/<id>`` — audit log explorer.
- ``/propagation/<id>`` — PHI propagation graph viewer (Cytoscape.js).
- ``/policy`` — policy editor with live YAML validation.
- ``/compliance/<id>`` — attestation viewer with pass/fail per rule.

Run with:

    pip install 'clinicsentry[dashboard]'
    uvicorn clinicsentry.dashboard.app:app --port 8080
"""

from clinicsentry.dashboard.app import create_app

__all__ = ["create_app"]
