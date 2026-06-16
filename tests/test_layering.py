"""Enforce ADR-0001 module-boundary rules via AST inspection.

The four feature modules (`phi/`, `escalation/`, `audit/`, `meddevice/`) MUST
NOT import each other. `guard.py` is the only place cross-module wiring is
permitted. Adapters import `guard` and `types` only.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "clinicsentry"

FEATURE_MODULES = {"phi", "escalation", "audit", "meddevice"}


def _imports(path: Path) -> set[str]:
    """Return every module dotted-name imported by ``path``."""
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _module_of(path: Path) -> str:
    """Return the top-level feature subpackage of ``path`` ('phi', etc.) or ''."""
    rel = path.relative_to(SRC)
    parts = rel.parts
    if len(parts) >= 2 and parts[0] in FEATURE_MODULES:
        return parts[0]
    return ""


def test_feature_modules_do_not_import_each_other() -> None:
    """ADR-0001: feature modules must not depend on each other."""
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        mine = _module_of(path)
        if not mine:
            continue
        for imported in _imports(path):
            if not imported.startswith("clinicsentry."):
                continue
            tail = imported.removeprefix("clinicsentry.").split(".")[0]
            if tail in FEATURE_MODULES and tail != mine:
                offenders.append(f"{path.relative_to(SRC)} imports {imported}")
    if offenders:
        pytest.fail("Module-boundary violations (ADR-0001):\n  " + "\n  ".join(offenders))


def test_adapters_do_not_import_feature_modules_directly() -> None:
    """ADR-0002: adapters use only guard + types."""
    offenders: list[str] = []
    for path in (SRC / "adapters").rglob("*.py"):
        for imported in _imports(path):
            if not imported.startswith("clinicsentry."):
                continue
            tail = imported.removeprefix("clinicsentry.").split(".")[0]
            if tail in FEATURE_MODULES:
                offenders.append(f"{path.relative_to(SRC)} imports {imported}")
    if offenders:
        pytest.fail("Adapter-boundary violations (ADR-0002):\n  " + "\n  ".join(offenders))


def test_every_public_module_declares_all() -> None:
    """Every public .py module under src/clinicsentry declares ``__all__``.

    Alembic migration scripts (``audit/migrations/env.py`` and
    ``audit/migrations/versions/*``) are excluded — they're framework-managed
    entry points with a fixed shape that doesn't accept a public surface.
    """
    missing: list[str] = []
    for path in SRC.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        rel = path.relative_to(SRC).as_posix()
        if rel.startswith("audit/migrations/versions/"):
            continue
        if rel == "audit/migrations/env.py":
            continue
        text = path.read_text()
        if "__all__" not in text:
            missing.append(rel)
    if missing:
        pytest.fail("Modules missing __all__:\n  " + "\n  ".join(missing))
