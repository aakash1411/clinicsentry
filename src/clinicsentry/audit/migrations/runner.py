"""Programmatic Alembic upgrade helper.

Lets tests + the dev compose stack run migrations without shelling out:

```python
from clinicsentry.audit.migrations import upgrade_head
upgrade_head("postgresql+psycopg://user:pw@host/db")
```
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["upgrade_head", "alembic_config_path"]


def alembic_config_path() -> Path:
    """Return the path to the bundled ``alembic.ini``."""
    return Path(__file__).parent / "alembic.ini"


def upgrade_head(dsn: str) -> None:
    """Run ``alembic upgrade head`` against ``dsn``.

    Args:
        dsn: SQLAlchemy DSN, e.g. ``postgresql+psycopg://u:p@h/db``.

    Raises:
        ImportError: if alembic is not installed (it's in the ``postgres`` extra).
    """
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "alembic not installed. Install with `pip install 'clinicsentry[postgres]'`."
        ) from exc

    cfg = Config(str(alembic_config_path()))
    cfg.set_main_option("script_location", str(Path(__file__).parent))
    cfg.set_main_option("sqlalchemy.url", dsn)
    command.upgrade(cfg, "head")
