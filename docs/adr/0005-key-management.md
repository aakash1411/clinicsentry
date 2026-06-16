# ADR-0005: Key Management Protocol

- **Status:** accepted
- **Date:** 2025-01-15

## Context

The audit chain's HMAC key and the clinician-authorization signing key are the two cryptographic secrets whose compromise would invalidate ClinicSentry's safety claims. We need a single protocol that supports both research deployments (software keys) and production deployments (HSM-backed) without two code paths.

## Decision

We will define a `KeyProvider` abstract base class with three implementations shipped in v1:

1. **`SoftwareKeyProvider`** — keys held in-process; default for tests and research use.
2. **`EnvKeyProvider`** — keys read from environment variables (base64-encoded); for container deployments.
3. **`PKCS11KeyProvider`** — keys held in an HSM (SoftHSMv2 for CI, vendor HSM for production), accessed via `python-pkcs11`. Optional dep `clinicsentry[hsm]`.

All providers expose `sign(data: bytes) -> bytes` and `verify(data: bytes, sig: bytes) -> bool`. Key rotation is handled by `KeyProvider.current_key_id() -> str` written into every `AuditEvent`; verification looks up by key id.

The default in `ClinicSentry.__init__` remains software keys with a clear `RESPONSIBLE_USE.md` warning that production deployments MUST switch.

## Consequences

- **Positive:** uniform API; no production / research code split; HSM upgrade is a config change.
- **Negative:** PKCS#11 is a notoriously painful API. We accept this rather than invent our own.
- **Neutral:** Cloud KMS providers (AWS KMS, GCP KMS, Azure Key Vault) become straightforward additions as further `KeyProvider` subclasses.

## Alternatives Considered

- **Hardcode software keys for v1:** rejected — would force a breaking change to add HSM later.
- **Tink as the abstraction:** rejected — too heavy a dependency for our narrow needs.

## References

- ADR-0003 (chain semantics), ADR-0014 (threat model).
- NIST SP 800-57 Part 1 Rev. 5.
