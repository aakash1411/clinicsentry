"""Alembic-managed schema integration test.

Spins up a real Postgres via testcontainers, runs
:func:`clinicsentry.audit.migrations.upgrade_head` against a fresh database,
asserts the ``audit_events`` table + append-only trigger materialized, and
proves the :class:`PostgresAuditBackend` works with ``bootstrap_schema=False``
once Alembic owns the schema.

Skipped when alembic / testcontainers / a Postgres driver isn't installed.
"""

from __future__ import annotations

import pytest

try:
    import alembic  # noqa: F401
    import sqlalchemy
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
    pytest.mark.skipif(_MISSING is not None, reason=f"deps missing: {_MISSING}"),
    pytest.mark.skipif(not docker_daemon_reachable(), reason="docker daemon not reachable"),
]


from clinicsentry.audit.migrations import upgrade_head  # noqa: E402
from clinicsentry.audit.postgres import PostgresAuditBackend  # noqa: E402
from clinicsentry.types import AuditEvent, AuditEventType  # noqa: E402


@pytest.fixture(scope="module")
def pg_dsn() -> str:
    """Spin up a fresh Postgres container; yield a normalized SQLAlchemy DSN."""
    with PostgresContainer("postgres:16-alpine") as container:
        raw = container.get_connection_url()
        if _DRIVER == "psycopg":
            raw = raw.replace("postgresql+psycopg2://", "postgresql+psycopg://")
        yield raw


def test_alembic_upgrade_creates_table_and_trigger(pg_dsn: str) -> None:
    """``upgrade_head`` must materialize the schema in an empty database."""
    upgrade_head(pg_dsn)
    engine = sqlalchemy.create_engine(pg_dsn, future=True)
    with engine.connect() as conn:
        tables = conn.execute(
            text(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname='public' AND tablename='audit_events'"
            )
        ).fetchall()
        assert tables, "alembic upgrade did not create audit_events"
        triggers = conn.execute(
            text(
                "SELECT trigger_name FROM information_schema.triggers "
                "WHERE event_object_table = 'audit_events'"
            )
        ).fetchall()
        assert triggers, "append-only trigger missing after upgrade"


def test_backend_without_bootstrap_uses_alembic_schema(pg_dsn: str) -> None:
    """With Alembic-managed schema, the backend must work with bootstrap_schema=False."""
    upgrade_head(pg_dsn)
    backend = PostgresAuditBackend(pg_dsn, bootstrap_schema=False)
    backend.append(
        AuditEvent(
            event_type=AuditEventType.AGENT_LLM_CALL,
            session_id="alembic-test",
            sequence_number=1,
            agent_id="t",
            agent_framework="t",
            signature="sig",
        )
    )
    events = list(backend.read_session("alembic-test"))
    assert len(events) == 1
    assert events[0].agent_id == "t"


def test_alembic_upgrade_is_idempotent(pg_dsn: str) -> None:
    """Re-running upgrade_head against an up-to-date DB is a no-op."""
    upgrade_head(pg_dsn)
    upgrade_head(pg_dsn)  # second call must not raise.
