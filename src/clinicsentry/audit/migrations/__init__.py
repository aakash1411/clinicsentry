r"""Alembic migrations for the Postgres audit backend.

Run from the repo root:

```bash
alembic -c src/clinicsentry/audit/migrations/alembic.ini \
    -x dsn=postgresql+psycopg://user:pw@host/db \
    upgrade head
```

Or programmatically via :func:`clinicsentry.audit.migrations.runner.upgrade_head`.
"""

from clinicsentry.audit.migrations.runner import upgrade_head

__all__ = ["upgrade_head"]
