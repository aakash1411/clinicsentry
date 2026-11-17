"""The per-module coverage floor checker used by CI."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_coverage_floors.py"


@pytest.fixture(scope="module")
def floors_mod() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_coverage_floors", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _file(lines: int, covered: int, branches: int = 0, cov_branches: int = 0) -> dict:
    return {
        "summary": {
            "num_statements": lines,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": cov_branches,
        }
    }


REPORT = {
    "files": {
        "src/pkg/authz/a.py": _file(10, 10, 4, 4),
        "src/pkg/authz/b.py": _file(10, 5, 0, 0),
        "src/pkg/other.py": _file(10, 9),
    }
}


def test_group_percent_aggregates_lines_and_branches(floors_mod: ModuleType) -> None:
    assert floors_mod.group_percent(REPORT["files"], "src/pkg/authz/*") == pytest.approx(
        100 * 19 / 24
    )
    assert floors_mod.group_percent(REPORT["files"], "src/pkg/missing/*") is None


def test_check_reports_failures_and_skips(floors_mod: ModuleType) -> None:
    floors = {"src/pkg/authz/*": 90, "src/pkg/other.py": 90, "src/pkg/new/*": 90}
    assert floors_mod.check(REPORT, floors) == ["src/pkg/authz/*"]


def test_pyproject_floors_are_declared(floors_mod: ModuleType) -> None:
    floors = floors_mod.load_floors(SCRIPT.parent.parent / "pyproject.toml")
    assert floors["src/clinicsentry/authz/*"] >= 90


def test_main_exit_codes(
    floors_mod: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(REPORT))
    monkeypatch.setattr(floors_mod, "load_floors", lambda _p: {"src/pkg/other.py": 85})
    assert floors_mod.main(["x", str(path)]) == 0
    monkeypatch.setattr(floors_mod, "load_floors", lambda _p: {"src/pkg/other.py": 95})
    assert floors_mod.main(["x", str(path)]) == 1
