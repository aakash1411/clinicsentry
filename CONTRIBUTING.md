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

- `main` — protected, always green, deployable.
- `feat/<short-desc>` — feature branches.
- `fix/<short-desc>` — bug fixes.
- `docs/<short-desc>` — documentation only.

`main` cannot be pushed to directly. Every change goes through a PR with at least one review.

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
