"""Integration tests for :class:`PostgresAuditBackend` using testcontainers.

These tests start a real Postgres container, run the backend's DDL, and
exercise append-only triggers, idempotent upsert, session listing, and
field-roundtrip preservation.

Requirements:

- Docker daemon running locally (or compatible runtime).
- ``pip install 'clinicsentry[postgres]' testcontainers[postgres] psycopg[binary]``.

The whole module is skipped automatically when the optional deps are not
installed, so the standard test suite stays green on a minimal venv.
"""

from __future__ import annotations

import pytest

try:
    import sqlalchemy  # noqa: F401
    from sqlalchemy import text
    from testcontainers.postgres import PostgresContainer

    _MISSING: str | None = None
    try:
        import psycopg  # noqa: F401

        _DRIVER = "psycopg"
    except ImportError:
        try:
            import psycopg2  # noqa: F401

            _DRIVER = "psycopg2"
        except ImportError:
            _MISSING = "no psycopg / psycopg2 driver installed"
            _DRIVER = ""
except ImportError as exc:
    _MISSING = str(exc)
    _DRIVER = ""

from tests._docker_guard import docker_daemon_reachable

pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        _MISSING is not None, reason=f"postgres integration deps missing: {_MISSING}"
    ),
    pytest.mark.skipif(not docker_daemon_reachable(), reason="docker daemon not reachable"),
]


from clinicsentry.audit.postgres import PostgresAuditBackend  # noqa: E402
from clinicsentry.types import (  # noqa: E402
    AuditEvent,
    AuditEventType,
    ClinicalRiskTier,
)


@pytest.fixture(scope="module")
def pg_dsn() -> str:
    """Spin up a Postgres container and yield a SQLAlchemy DSN."""
    with PostgresContainer("postgres:16-alpine") as container:
        raw = container.get_connection_url()
        # testcontainers returns a psycopg2-flavored URL; normalize.
        if _DRIVER == "psycopg":
            raw = raw.replace("postgresql+psycopg2://", "postgresql+psycopg://")
        yield raw


@pytest.fixture
def backend(pg_dsn: str) -> PostgresAuditBackend:
    """Fresh backend per test (table is shared but events are scoped by session_id)."""
    return PostgresAuditBackend(dsn=pg_dsn)


def _make_event(session_id: str, seq: int, **overrides) -> AuditEvent:
    base = {
        "event_type": AuditEventType.AGENT_LLM_CALL,
        "session_id": session_id,
        "sequence_number": seq,
        "agent_id": "agent-x",
        "agent_framework": "test",
        "input_hash": f"in-{seq}",
        "output_hash": f"out-{seq}",
        "signature": f"sig-{seq}",
        "prev_event_hash": f"prev-{seq - 1}" if seq > 0 else "",
    }
    base.update(overrides)
    return AuditEvent(**base)


# ---------------------------------------------------------------------------
# Schema and basic CRUD
# ---------------------------------------------------------------------------


def test_postgres_backend_creates_schema(backend: PostgresAuditBackend) -> None:
    """The backend's __init__ should leave the audit_events table present."""
    with backend._engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname='public' AND tablename='audit_events'"
            )
        ).fetchall()
        assert rows


def test_postgres_backend_append_and_read(backend: PostgresAuditBackend) -> None:
    session = "s-append-read"
    for i in range(5):
        backend.append(_make_event(session, seq=i))
    read = list(backend.read_session(session))
    assert len(read) == 5
    assert [e.sequence_number for e in read] == [0, 1, 2, 3, 4]
    assert all(e.signature.startswith("sig-") for e in read)


def test_postgres_backend_upsert_idempotent(backend: PostgresAuditBackend) -> None:
    session = "s-idempotent"
    event = _make_event(session, seq=0)
    backend.append(event)
    backend.append(event)  # same event_id
    assert sum(1 for _ in backend.read_session(session)) == 1


def test_postgres_backend_list_sessions(backend: PostgresAuditBackend) -> None:
    for sid in ("alpha", "beta", "gamma"):
        backend.append(_make_event(sid, seq=0))
    listed = set(backend.list_sessions())
    assert {"alpha", "beta", "gamma"}.issubset(listed)


# ---------------------------------------------------------------------------
# Append-only trigger
# ---------------------------------------------------------------------------


def test_postgres_backend_trigger_rejects_update(backend: PostgresAuditBackend) -> None:
    session = "s-update-reject"
    backend.append(_make_event(session, seq=0))
    with (
        pytest.raises(Exception, match="append-only"),  # noqa: PT011
        backend._engine.begin() as conn,
    ):
        conn.execute(
            text("UPDATE audit_events SET sequence_number=999 WHERE session_id=:sid"),
            {"sid": session},
        )


def test_postgres_backend_trigger_rejects_delete(backend: PostgresAuditBackend) -> None:
    session = "s-delete-reject"
    backend.append(_make_event(session, seq=0))
    with (
        pytest.raises(Exception, match="append-only"),  # noqa: PT011
        backend._engine.begin() as conn,
    ):
        conn.execute(
            text("DELETE FROM audit_events WHERE session_id=:sid"),
            {"sid": session},
        )


# ---------------------------------------------------------------------------
# Field roundtrip
# ---------------------------------------------------------------------------


def test_postgres_backend_rehydrate_preserves_all_fields(
    backend: PostgresAuditBackend,
) -> None:
    session = "s-roundtrip"
    original = _make_event(
        session,
        seq=0,
        event_type=AuditEventType.TOOL_CALL,
        risk_tier=ClinicalRiskTier.INTERVENTIONAL,
        confidence_score=0.85,
        escalation_decision={"action": "block", "tier": "interventional"},
        phi_tags_detected=["tag-a", "tag-b"],
        redacted_input={"tool_name": "pump_set"},
    )
    backend.append(original)
    [read] = list(backend.read_session(session))
    assert read.event_type == AuditEventType.TOOL_CALL
    assert read.risk_tier == ClinicalRiskTier.INTERVENTIONAL
    assert read.confidence_score == pytest.approx(0.85)
    assert read.escalation_decision == {"action": "block", "tier": "interventional"}
    assert read.phi_tags_detected == ["tag-a", "tag-b"]
    assert read.redacted_input == {"tool_name": "pump_set"}
