# ADR-0016: Adversarial Normalization in the Production Scan Path

- **Status:** accepted
- **Date:** 2026-06-12
- **Authors:** ClinicSentry Contributors
- **Deciders:** maintainers

## Context

The adversarial module (homoglyph mapping, invisible-character stripping, NFKC)
existed as a standalone `AdversarialDetector`, but the `PHIFirewall` scan path
ran only the raw regex detector. Obfuscated PHI — an SSN with a zero-width
space, an email with a Cyrillic homoglyph, a percent-encoded address — passed
through `guard.firewall.scan()` **unredacted**. The blocker was offsets: hits
found in normalized text point at normalized positions, and splicing those
spans into the original string corrupts the redaction or, worse, leaves PHI
fragments behind.

A second gap: `scan()` only walked strings, dicts, and lists. Tuples, sets,
dict *keys*, UTF-8 bytes, and pathologically deep nesting all bypassed
detection entirely — and a detector that raises `RecursionError` fails open if
the host catches exceptions broadly.

## Decision

- **Offset-preserving normalization.** `normalize_with_map` records, for every
  normalized character, the half-open span of the original string it came from.
  Stages: invisible stripping, homoglyph mapping, per-character NFKC, and
  printable `%XX` percent-decoding. Hits are mapped back via span union — the
  mapped span covers every original character that contributed to the match,
  including stripped invisibles, so redaction of the original text removes the
  full obfuscated region. Over-covering is fail-safe; under-covering is a leak.
- **Fast path stays fast.** Plain-ASCII text without `%` is canonical by
  construction; the firewall skips normalization there (`str.isascii()` is
  C-speed). The normalizer is a single O(n) Python pass reserved for inputs
  that need it.
- **Opportunistic encoded-token scanning.** `EncodedPHIDetector` decodes
  base64-shaped tokens (≥12 alphabet chars, length ≡ 0 mod 4, ≤4 KB) that
  round-trip to printable UTF-8 and scans the plaintext. A hit redacts the
  *entire encoded token*. Policy key `phi_firewall.decode_encoded` (default
  `true`) opts out.
- **Whole-payload coverage.** `scan()` recurses into tuples, sets, frozensets,
  and dict keys; UTF-8-decodable bytes are scanned as text and re-encoded.
  Nesting beyond `phi_firewall.max_depth` (default 64) returns
  `[REDACTED:MAX_DEPTH_EXCEEDED]` — fail closed, never `RecursionError`.
- **Overlap merging is span-union.** When two hits overlap, the winner keeps
  its metadata but the merged span covers both, so a losing hit can never leave
  a visible fragment.

## Consequences

- **Positive:** the documented evasions in the adversarial benchmark
  (homoglyph, zero-width, full-width, percent-encoding, base64, spaced SSNs)
  are now caught *and redacted* on the production path; the former xfail tests
  are hard assertions. Scan p95 stays ~1 ms on note-sized adversarial inputs.
- **Negative:** per-character NFKC misses multi-character compositions
  (combining accents); acceptable because HIPAA identifiers are ASCII-shaped.
  Base64 scanning can over-redact an opaque token that coincidentally decodes
  to PHI-shaped text — fail-safe by design.
- **Neutral:** pseudonyms for obfuscated values derive from the *original*
  (obfuscated) slice, so the same value obfuscated two different ways yields
  two pseudonyms. Tracked as future work if linkage matters.

## Alternatives Considered

- **Run detectors on normalized text and redact the normalized form** —
  rejected: the caller receives a silently rewritten payload, breaking
  hash-based audit references to the original input.
- **Second regex pass over the raw text to "fix up" offsets** — rejected:
  quadratic in pathological inputs and still wrong when lengths change
  (percent-decoding, NFKC expansions).
- **Full decode-tree exploration (nested base64, gzip, hex)** — rejected for
  the hot path; single-level base64 covers the observed evasion class at
  negligible cost. Deeper decoding belongs in an offline batch scanner.

## References

- ADR-0007 (composition operator), ADR-0014 (threat model scope),
  ADR-0015 (redaction mode selection).
- UTS #39 (Unicode security mechanisms, confusables).
