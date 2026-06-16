"""PostgreSQL audit backend with append-only semantics.

Schema:

```sql
CREATE TABLE audit_events (
    event_id        TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    sequence_number BIGINT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    payload         JSONB NOT NULL,
    UNIQUE (session_id, sequence_number)
);

-- Append-only: no UPDATE or DELETE for application roles.
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;

-- Row-level security: every session is owned by exactly one tenant.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (session_id LIKE current_setting('app.tenant_prefix', true) || '%');
```

This backend connects via :mod:`sqlalchemy` and is loaded lazily so the package
remains importable without ``sqlalchemy`` installed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from clinicsentry.audit.backend import AuditBackend
from clinicsentry.types import AuditEvent, AuditEventType, ClinicalRiskTier

__all__ = ["PostgresAuditBackend", "DDL_STATEMENTS"]


DDL_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        event_id        TEXT PRIMARY KEY,
        session_id      TEXT NOT NULL,
        sequence_number BIGINT NOT NULL,
        timestamp       TIMESTAMPTZ NOT NULL,
        payload         JSONB NOT NULL,
        UNIQUE (session_id, sequence_number)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events (session_id, sequence_number)",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events (timestamp)",
    """
    CREATE OR REPLACE FUNCTION audit_events_reject_modification()
    RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_events is append-only';
    END;
    $$ LANGUAGE plpgsql
    """,
    """
    DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events
    """,
    """
    CREATE TRIGGER audit_events_no_update
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_reject_modification()
    """,
]


class PostgresAuditBackend(AuditBackend):
    """SQLAlchemy-backed PostgreSQL audit store with append-only triggers."""

    def __init__(
        self,
        dsn: str,
        *,
        schema: str | None = None,
        bootstrap_schema: bool = True,
    ) -> None:
        """Connect to ``dsn`` (e.g. ``postgresql+psycopg://user:pw@host/db``).

        Args:
            dsn: SQLAlchemy DSN string.
            schema: optional schema name; defaults to ``public``.
            bootstrap_schema: when True (default), the inline DDL in
                :data:`DDL_STATEMENTS` is applied on construction. Production
                deployments managed by Alembic should pass ``False`` and call
                :func:`clinicsentry.audit.migrations.upgrade_head` separately.
        """
        try:  # pragma: no cover - optional dep
            from sqlalchemy import create_engine
            from sqlalchemy.engine import Engine
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "PostgresAuditBackend requires sqlalchemy. "
                "Install: `pip install 'clinicsentry[postgres]'`."
            ) from exc

        self._engine: Engine = create_engine(dsn, future=True)
        self._schema = schema
        if bootstrap_schema:
            self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Create the table and triggers if absent."""
        from sqlalchemy import text

        with self._engine.begin() as conn:
            for stmt in DDL_STATEMENTS:
                conn.execute(text(stmt))

    def append(self, event: AuditEvent) -> None:
        """Insert a single event row (idempotent on primary key collision)."""
        from sqlalchemy import text

        payload = json.dumps(event.to_dict(), default=str)
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO audit_events "
                    "(event_id, session_id, sequence_number, timestamp, payload) "
                    "VALUES (:eid, :sid, :seq, :ts, CAST(:payload AS JSONB)) "
                    "ON CONFLICT (event_id) DO NOTHING"
                ),
                {
                    "eid": event.event_id,
                    "sid": event.session_id,
                    "seq": event.sequence_number,
                    "ts": event.timestamp,
                    "payload": payload,
                },
            )

    def read_session(self, session_id: str) -> Iterator[AuditEvent]:
        """Return events for ``session_id`` ordered by sequence number."""
        from sqlalchemy import text

        with self._engine.connect() as conn:
            result = conn.execute(
                text(
                    "SELECT payload FROM audit_events "
                    "WHERE session_id = :sid ORDER BY sequence_number"
                ),
                {"sid": session_id},
            )
            for (raw,) in result:
                payload = raw if isinstance(raw, dict) else json.loads(raw)
                yield _rehydrate(payload)

    def _iter_session_ids(self) -> Iterator[str]:
        """Yield distinct session ids in the table."""
        from sqlalchemy import text

        with self._engine.connect() as conn:
            result = conn.execute(text("SELECT DISTINCT session_id FROM audit_events"))
            for (sid,) in result:
                yield sid

    def close(self) -> None:
        """Dispose of the engine's connection pool."""
        self._engine.dispose()


def _rehydrate(payload: dict[str, Any]) -> AuditEvent:
    """Rehydrate a stored row into an :class:`AuditEvent`."""
    risk = payload.get("risk_tier")
    return AuditEvent(
        event_id=payload["event_id"],
        session_id=payload["session_id"],
        sequence_number=int(payload["sequence_number"]),
        timestamp=datetime.fromisoformat(payload["timestamp"]),
        event_type=AuditEventType(payload["event_type"]),
        agent_id=payload.get("agent_id", "unknown"),
        agent_framework=payload.get("agent_framework", "unknown"),
        input_hash=payload.get("input_hash", ""),
        output_hash=payload.get("output_hash", ""),
        redacted_input=payload.get("redacted_input", {}) or {},
        redacted_output=payload.get("redacted_output", {}) or {},
        phi_tags_detected=list(payload.get("phi_tags_detected", []) or []),
        risk_tier=ClinicalRiskTier(risk) if risk else None,
        confidence_score=payload.get("confidence_score"),
        escalation_decision=payload.get("escalation_decision"),
        prev_event_hash=payload.get("prev_event_hash", ""),
        signature=payload.get("signature", ""),
    )
