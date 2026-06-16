# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.3.0] — 2026-06-12

### Added

- **Adversarial normalization wired into the production scan path**
  (ADR-0016). `PHIFirewall.scan` now catches and *redacts* homoglyph,
  zero-width, full-width, percent-encoded, and base64-encoded PHI via an
  offset-preserving normalizer (`normalize_with_map`) that maps hits back to
  exact spans of the original text. Previously these evasions passed through
  unredacted. Plain-ASCII inputs keep a no-normalization fast path
  (scan p95 ≈ 0.7 ms on 3 KB notes; ≈ 1.2 ms adversarial).
- `EncodedPHIDetector`: opportunistic base64-token decoding; a token whose
  decoded form contains PHI is redacted in full. Opt out with
  `phi_firewall.decode_encoded: false`.
- SSN detection accepts space separators (`123 45 6789`).
- `scan()` now covers tuples, sets, frozensets, dict **keys**, and
  UTF-8-decodable bytes; payloads nested beyond `phi_firewall.max_depth`
  (default 64) fail closed with `[REDACTED:MAX_DEPTH_EXCEEDED]` instead of
  raising `RecursionError`.
- `AuditChain.verify` detects sequence gaps and **tail truncation** (deleting
  the last N events previously left a "valid" chain); `emit` is thread-safe —
  concurrent emitters produce a gapless, verifiable chain.
- `ClinicSentry` is a context manager: `with ClinicSentry(...) as guard:`
  guarantees `SESSION_END` (and a PHI-free `MODULE_ERROR` event on exception);
  `end_session` is idempotent; new `close()` releases backend resources.
- **Strict policy loading**: unknown keys, invalid enum values, out-of-range
  thresholds, inverted dose ranges, and malformed YAML raise `PolicyError`
  naming the offending field (a typo'd block previously disabled enforcement
  silently). `CLINICSENTRY_<SECTION>_<KEY>` environment overrides per
  ADR-0012 are now implemented (`load_policy(..., apply_env=False)` opts out).
- New policy keys: `phi_firewall.decode_encoded`, `phi_firewall.max_depth`,
  `escalation.on_unregistered_action`, `meddevice_mode.strict_dose_ranges`.

### Changed

- **Fail-closed defaults** (breaking for permissive flows):
  - Unregistered actions now **escalate** regardless of confidence
    (`escalation.on_unregistered_action: tier_default` restores old scoring).
  - With dose ranges configured, an undeclared parameter is rejected
    (`meddevice_mode.strict_dose_ranges: false` restores pass-through).
  - Non-finite dose values (NaN, ±inf) always fail validation.
- `rate_limit_per_hour` is now a true **rolling 1-hour window** (monotonic
  clock) instead of a never-resetting per-session counter.
- Overlapping detection hits merge to their **span union** so a losing hit can
  never leave a PHI fragment visible.
- `EscalationRouter.decide` no longer mutates the caller's
  `ConfidenceInputs`; `ConfidenceScorer` validates weights at construction.
- The three adversarial xfail tests (spaced SSN, base64, URL-encoding) are now
  hard assertions.

## [0.2.0] — 2026-05-10

### Added

- **Alembic migrations** for the Postgres audit backend (`src/clinicsentry/audit/migrations/`)
  with `0001_initial_audit_events.py` mirroring the inline DDL plus an
  append-only trigger.
- `PostgresAuditBackend(..., bootstrap_schema=False)` opt-out for
  Alembic-managed deployments. Default behaviour is unchanged.
- `clinicsentry.audit.migrations.upgrade_head(dsn)` programmatic helper used
  by tests and the dev compose stack.
- **Cloud KMS providers** (`src/clinicsentry/meddevice/cloud_kms.py`):
  `AWSKMSKeyProvider`, `GCPKMSKeyProvider`, `AzureKeyVaultKeyProvider`. All
  conform to the existing `KeyProvider` protocol. Optional dep group
  `clinicsentry[cloud-kms]`.
- LocalStack-backed AWS KMS integration test (`tests/test_cloud_kms_aws.py`);
  fake-client-based GCP + Azure tests (`tests/test_cloud_kms_mocked.py`).
  All cloud SDKs are loaded lazily — no real cloud calls.
- **CLI compliance summary**: `clinicsentry report --format summary` prints
  a compact per-framework / failed-blocker view of the DSL output.
- **CLI demo seed**: `clinicsentry demo --audit-path` writes a self-contained
  session to SQLite. Wired into the dashboard compose service so the
  dashboard has data on first run.
- Package-data verification in CI: rules YAML in wheel + sdist, plus
  `py.typed` marker.
- CI matrix expanded: Postgres testcontainers, adapter-SDK fan-out, heavy-deps
  manual job, mutation testing manual job.
- Mutation testing across the four novelty modules: aggregate **96.6%**.

### Changed

- `PostgresAuditBackend.__init__` gained `bootstrap_schema: bool = True`
  (back-compat default).
- `RegulatoryReport.compliance_attestation` widened from `dict[str, bool]` to
  `dict[str, Any]` to carry the rich rule-result envelope from the DSL engine
  introduced in 4a.
- `mutmut` pinned to `>=2.5,<3.0` to dodge the 3.x macOS regression.
- `py.typed` marker shipped in the wheel; downstream consumers can now type-
  check against the package without an `Any` ceiling.

### Fixed

- IDE schema lint false-positive on `.github/workflows/docs.yml` removed by
  dropping the now-unnecessary `hashFiles` conditional.

## [0.1.0] (initial preview)

### Added

- 15 architectural decision records (`docs/adr/0001`–`0015`).
- `__all__` declarations on every public module.
- `CONVENTIONS.md`, `STATUS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `RESPONSIBLE_USE.md`.
- GitHub Actions CI: ruff, mypy, pytest with coverage gate, license scan, import-safety check.
- Pre-commit configuration (`.pre-commit-config.yaml`).
- `clinicsentry` CLI with `demo`, `verify`, `report`, `scan`, `policy-validate` subcommands.
- Apache-2.0 `LICENSE`.

### Changed

- Pinned developer dependencies (`ruff`, `mypy`, `pre-commit`, `pytest-cov`, `mutmut`).

## [0.1.0] — 2025-01-15

### Added

- Initial scaffold of four modules: PHI Firewall, Escalation Router, Audit Trail, MedDevice Mode.
- Regex + Presidio PHI detectors with FHIR/HL7/DICOM structural parsers.
- Linear hash-chain audit with HMAC signing and 3 backends (in-memory, JSONL file, SQLite).
- Composite confidence scorer with 4 signals.
- IEC 62304 Class A/B/C registration-time enforcement.
- `AgentFrameworkAdapter` ABC, `GenericAdapter`, `LangGraphAdapter`.
- Policy YAML loader and `ClinicSentry` facade.
- 22 unit + integration tests.
- Worked example: `examples/clinical_summarizer.py`.
- 1,288-line README spec; 441-line implementation report.

[Unreleased]: https://github.com/aakash1411/clinicsentry/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/aakash1411/clinicsentry/releases/tag/v0.3.0
[0.2.0]: https://github.com/aakash1411/clinicsentry/releases/tag/v0.2.0
[0.1.0]: https://github.com/aakash1411/clinicsentry/releases/tag/v0.1.0
