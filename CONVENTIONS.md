# Conventions

The authoritative, rationale-bearing versions of these rules live in
`docs/adr/`. This file is the quick-reference card.

## Code

- Python ≥ 3.11, `mypy --strict` clean, `ruff check` + `ruff format` clean.
- Module boundaries and allowed import directions: ADR-0001 (`phi`,
  `escalation`, `audit`, `meddevice` do not import each other; `guard.py`
  composes them).
- Async at the adapter edges, sync in module internals: ADR-0009.
- Every public module declares `__all__`.
- Exceptions descend from `ClinicSentryError` with stable `code` attributes:
  ADR-0008. Exception messages MUST NOT contain PHI.

## Security posture

- Fail closed: unparseable config, unregistered actions, undeclared dose
  parameters, and over-deep payloads are rejected, not passed through.
- Detection improvements must be wired into `PHIFirewall.scan` and covered by
  a firewall-level test — a detector that passes its own tests but isn't in
  the production path is a vulnerability (see ADR-0016 history).
- Hot path adds no LLM calls and stays within the latency budgets in
  `performance.py`.

## Tests

- Conventions and markers: ADR-0010 (`unit`, `integration`, `adapter`, `slow`,
  `regulatory`, `property`, `mutation_target`).
- Tests asserting redaction must assert on the *output payload*, not just tag
  presence.
- Optional-dependency tests skip cleanly when the dependency is absent.

## Releases

- SemVer; CHANGELOG follows Keep a Changelog.
