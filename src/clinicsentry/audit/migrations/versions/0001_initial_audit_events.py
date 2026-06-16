"""Initial audit_events schema with append-only trigger.

Revision ID: 0001
Revises:
Create Date: 2026-05-10
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the audit_events table, indexes, and append-only trigger.

    Mirrors :data:`clinicsentry.audit.postgres.DDL_STATEMENTS`. Idempotent —
    safe to re-run against a database that may already have part of the
    schema.
    """
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id        TEXT PRIMARY KEY,
            session_id      TEXT NOT NULL,
            sequence_number BIGINT NOT NULL,
            timestamp       TIMESTAMPTZ NOT NULL,
            payload         JSONB NOT NULL,
            UNIQUE (session_id, sequence_number)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_events_session "
        "ON audit_events (session_id, sequence_number)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events (timestamp)")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_events_reject_modification()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute(
        """
        CREATE TRIGGER audit_events_no_update
            BEFORE UPDATE OR DELETE ON audit_events
            FOR EACH ROW EXECUTE FUNCTION audit_events_reject_modification()
        """
    )


def downgrade() -> None:
    """Drop the audit_events schema. Destructive — only for dev / test."""
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_reject_modification()")
    op.execute("DROP TABLE IF EXISTS audit_events")
