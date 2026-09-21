# AGENTS.md

Entry point for coding agents working in this repository. Human-facing
rationale lives in `CONTRIBUTING.md`, `CONVENTIONS.md`, `STATUS.md` and
`docs/adr/`; this file is the operational checklist.

## Layout

- `src/clinicsentry/` — the package (`phi/`, `escalation/`, `audit/`,
  `meddevice/` are independent; `guard.py` composes them — ADR-0001).
  `cli.py` provides the `clinicsentry` console script.
- `tests/` — pytest suite; `tests/adapters/` holds per-SDK integration tests.
- `docs/adr/` — Architecture Decision Records (`README.md` has the index).
- `docs/` + `mkdocs.yml` — MkDocs Material site.
- `.github/workflows/ci.yml` — the authoritative list of CI gates.

## Setup

Python **3.11+** is required (`requires-python = ">=3.11"`); CI runs 3.11,
3.12 and 3.13. If the system `python3` is older, use a pyenv/uv-managed 3.11.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,all]'     # ~30 s; pulls spaCy, presidio, hl7apy, pydicom
pre-commit install
```

Optional extras are opt-in. `[all]` does **not** include `postgres`,
`signing`, `s3`, `hsm`, `cloud-kms`, `docs` or any adapter SDK, so with the
install above `pytest` skips the alembic, boto3, sqlalchemy, pkcs11 and
adapter tests (29 skips in a 454-test run). Install the extra you are
touching, e.g. `pip install -e '.[dev,langgraph]'` or
`pip install -e '.[dev,postgres]' 'psycopg[binary]>=3.1'`.

## Gates to run before opening a PR

These are exactly what `ci.yml` runs (all from the repo root, venv active):

```bash
ruff format --check .
ruff check .
mypy                                   # config in pyproject: strict, files=src/clinicsentry
pytest -q                              # ~15 s; 425 passed, 29 skipped on a [dev,all] venv
pytest --cov=clinicsentry --cov-report=term -q   # fail_under = 75 in pyproject
bandit -r src/clinicsentry -ll -ii
```

Additional gates that also run in CI:

- Docs workflow: `ruff check --select D --extend-ignore D203,D213,D104,D105,D107 src/clinicsentry`
  and `mkdocs build --strict` (needs `pip install -e '.[docs]'`).
- Import safety: every module under `clinicsentry.*` (except `dashboard`
  and `cli`) must import with only the core deps installed (`pip install -e .`).
- Postgres backend: `pytest tests/test_postgres_integration.py -q` with
  `[dev,postgres]` + `psycopg[binary]` installed and a Docker daemon.
- Adapter SDKs: `pytest tests/adapters/test_<sdk>_integration.py -q` with the
  matching extra installed; each file self-skips when its SDK is missing.

Quick manual smoke test of the CLI: `clinicsentry scan "SSN 123-45-6789"`
should print JSON with `"redacted": "SSN [REDACTED:SSN]"`.

## Gotchas hit in practice

- **ruff version drift.** `pyproject.toml` pins only `ruff>=0.4`, so
  `pip install -e '.[dev]'` (and CI) resolve to the current release, while
  `.pre-commit-config.yaml` pins `ruff-pre-commit v0.4.10`. The two disagree:
  - Current ruff (0.16.x at the time of writing) also formats Python code
    blocks inside `.md` files, so `ruff format --check .` fails on `README.md`
    and `docs/api-stability.md` even though every `.py` file is clean.
    `ruff format --check --exclude '*.md' .` isolates the Python result.
  - `pre-commit run --all-files` (ruff 0.4.10) auto-rewrites ~10 unrelated
    files (`PT001`/`PT023` fixture-parens style, two reformatted files) and
    leaves 5 `UP038` errors that need `--unsafe-fixes`. If you only touched
    non-Python files this does not fire; if you touched Python, expect the
    hook to modify files and re-stage deliberately — do not commit its drive-by
    changes to files outside your scope.
- **Docker-gated tests.** `tests/test_postgres_integration.py` skips when no
  Docker socket is reachable (`tests/_docker_guard.py`), but if the daemon
  *is* reachable and `postgres:16-alpine` cannot be pulled (e.g. Docker Hub
  `429 Too Many Requests`) the module **errors** rather than skipping.
  Pre-pull the image or deselect the file.
- `mkdocs build` writes `site/` at the repo root, which is not in
  `.gitignore` — delete it before committing.
- `pytest` uses `--strict-markers`; new markers must be added to
  `[tool.pytest.ini_options].markers` (`unit`, `integration`, `adapter`,
  `slow`, `regulatory`, `property`, `mutation_target` — ADR-0010).
- Coverage: `pyproject.toml` enforces `fail_under = 75` on the core modules
  (heavy/optional modules are in the `omit` list); `CONTRIBUTING.md` and the
  PR template ask for ≥ 85 % on new work. A `[dev,all]` run sits at ~87 %.

## Change rules (from CONTRIBUTING.md / CONVENTIONS.md)

- Branches: `feat/<desc>`, `fix/<desc>`, `docs/<desc>`; never push to `main`.
- Conventional Commits: `feat(escalation): ...`, `fix(audit): ...`,
  `docs(adr): ...`, `test(meddevice): ...`, `refactor(phi): ...`,
  `chore(deps): ...`, `perf(firewall): ...`.
- Every PR follows `.github/pull_request_template.md`: reference the ADR it
  implements (or add one via `docs/adr/0000-template.md` — ADRs are never
  deleted, only superseded), and add an entry under `## [Unreleased]` in
  `CHANGELOG.md` (Keep a Changelog format).
- Code: `mypy --strict` clean, Google-style docstrings on public symbols
  (ruff `D` rules), every public module declares `__all__`, exceptions
  descend from `ClinicSentryError` with stable `code` attributes (ADR-0008),
  and exception messages must never contain PHI.
- Security posture is fail-closed. Any new PHI detector must be wired into
  `PHIFirewall.scan` and covered by a firewall-level test that asserts on the
  redacted *output payload*, not just on tag presence (ADR-0016).
- No LLM calls on the hot path; stay within the budgets in
  `src/clinicsentry/performance.py`.
