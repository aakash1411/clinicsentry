## Summary

What and why (one paragraph).

## ADR reference

ADR-NNNN (link to `docs/adr/`).

## Changes

- Bullet list of concrete changes.

## Testing

- `pytest -q tests/test_<module>.py`
- Manual verification steps (if applicable).

## Risk / Compliance

Any HIPAA / FDA / IEC 62304 implications? Reference the rule.

## Checklist

- [ ] Tests added / updated.
- [ ] Coverage ≥ 85%.
- [ ] `ruff check`, `ruff format --check`, `mypy --strict` clean.
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`.
- [ ] `CHANGELOG.md` updated if this advances a feature.
- [ ] Any breaking change documented in PR title with `[breaking]`.
