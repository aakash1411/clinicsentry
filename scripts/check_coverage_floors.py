"""Enforce per-module coverage floors from ``[tool.clinicsentry.coverage_floors]``.

Reads a ``coverage json`` report and fails when any file group (glob relative to
the repository root) is below its declared line+branch percentage. Globs that
match no measured file are reported and skipped, so floors can be declared for
modules before they exist.

Usage: ``python scripts/check_coverage_floors.py coverage.json``
"""

from __future__ import annotations

import fnmatch
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def load_floors(pyproject: Path) -> dict[str, float]:
    """Return the ``glob -> floor %`` table declared in ``pyproject``."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    floors = data.get("tool", {}).get("clinicsentry", {}).get("coverage_floors", {})
    return {str(k): float(v) for k, v in floors.items()}


def group_percent(files: dict[str, Any], pattern: str) -> float | None:
    """Aggregate line+branch coverage of files matching ``pattern``; None if none match."""
    covered = total = 0
    for name, info in files.items():
        if not fnmatch.fnmatch(name.replace("\\", "/"), pattern):
            continue
        s = info["summary"]
        covered += s["covered_lines"] + s.get("covered_branches", 0)
        total += s["num_statements"] + s.get("num_branches", 0)
    if total == 0:
        return None
    return 100.0 * covered / total


def check(report: dict[str, Any], floors: dict[str, float]) -> list[str]:
    """Print one line per floor and return the patterns that fall below it."""
    failures: list[str] = []
    for pattern, floor in sorted(floors.items()):
        pct = group_percent(report["files"], pattern)
        if pct is None:
            print(f"skip  {pattern}: no measured files")
            continue
        ok = pct >= floor
        print(f"{'ok  ' if ok else 'FAIL'}  {pattern}: {pct:.1f}% (floor {floor:g}%)")
        if not ok:
            failures.append(pattern)
    return failures


def main(argv: list[str]) -> int:
    """CLI entry point; exit 1 when any floor is violated."""
    report_path = Path(argv[1]) if len(argv) > 1 else ROOT / "coverage.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return 1 if check(report, load_floors(ROOT / "pyproject.toml")) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
