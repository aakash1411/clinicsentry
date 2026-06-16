"""Alembic env: resolves the DSN from ``-x dsn=...`` or ``CLINICSENTRY_DSN``."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

# Resolve the DSN in this priority order:
# 1. Alembic ``-x dsn=...`` command-line override.
# 2. ``CLINICSENTRY_DSN`` environment variable.
# 3. ``sqlalchemy.url`` in alembic.ini (empty by default).
x_args = context.get_x_argument(as_dictionary=True)
dsn = (
    x_args.get("dsn")
    or os.environ.get("CLINICSENTRY_DSN")
    or config.get_main_option("sqlalchemy.url")
)
if dsn:
    config.set_main_option("sqlalchemy.url", dsn)


def run_migrations_offline() -> None:
    """Generate SQL without a live connection (for review / diff workflows)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the resolved DSN."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
