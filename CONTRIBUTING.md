# Contributing to ClinicSentry

Thanks for considering a contribution. ClinicSentry is research-grade compliance middleware; contributions must meet the quality bar appropriate to that scope.

## Quick Start

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,all]'
pre-commit install
pytest -q
```

## Branching

Git-flow:

- `main` — protected; released code only. Every commit on `main` is a tagged release or a hotfix.
- `develop` — protected integration branch; feature and bugfix PRs target it.
- `feature/<short-desc>` — new features, branched from `develop`.
- `bugfix/<short-desc>` — non-urgent fixes, branched from `develop`.
- `release/vX.Y.Z` — release preparation (version bump, CHANGELOG date), branched from `develop`, merged into `main`.
- `hotfix/<short-desc>` — urgent fixes, branched from `main`, merged into `main` and `develop`.
- `docs/<short-desc>` — documentation only.

Commit subjects describe the change (e.g. "Add PHI detection benchmark harness"), not a roadmap phase.

## Releasing

1. Branch `release/vX.Y.Z` from `develop`; bump `version` in `pyproject.toml`; date the CHANGELOG section.
2. Open a PR to `main`; merge once CI is green.
3. Tag the merge commit `vX.Y.Z` on `main` and push the tag. `release.yml` verifies the tag matches `pyproject.toml`, builds, smoke-tests, generates and signs the SBOM, and creates the GitHub release.
4. Merge `main` back into `develop`.

## Pull Requests

Every PR MUST:

1. Reference the ADR it implements or amend an existing one if architecture changes.
2. Keep test coverage ≥ 85% (CI enforces).
3. Pass `ruff check`, `ruff format --check`, `mypy --strict`, `pytest`.
4. Update `CHANGELOG.md` under the `## [Unreleased]` heading.
5. Update `CHANGELOG.md` if it advances a feature.

PR template (auto-populated by `.github/pull_request_template.md`):

```markdown
## Summary
What and why (one paragraph).

## ADR reference
ADR-NNNN (link).

## Changes
- Bullet list of concrete changes.

## Testing
- `pytest -q tests/test_<module>.py`
- Manual verification steps (if applicable).

## Risk / Compliance
Any HIPAA / FDA / IEC 62304 implications? Reference the rule.
```

## Conventional Commits

```
feat(escalation): add historical-consistency signal
fix(audit): correct sequence number assignment on backend swap
docs(adr): add ADR-0016 for KMS support
test(meddevice): cover emergency stop with active session
refactor(phi): extract pseudonym derivation to helper
chore(deps): bump cryptography to 42.0
perf(firewall): cache compiled regex patterns
```

## Code of Conduct

We follow the Contributor Covenant v2.1. Report violations to security@clinicsentry.example (replace with real contact before launch).

## License

By contributing, you agree your contribution is licensed under Apache-2.0, the project's license.
