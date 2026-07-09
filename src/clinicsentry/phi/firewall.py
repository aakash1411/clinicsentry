"""PHI Firewall — coordinates detectors, parsers, redaction, propagation.

This is the central entry point of Module 1. It accepts heterogenous payloads
(strings, JSON-like dicts that may be FHIR resources, HL7 v2 strings, pydicom
Datasets, lists/tuples/sets, UTF-8 bytes) and returns a redacted version plus
structured findings and `PHITag`s.

Detection on strings is adversarial-aware: input is normalized (invisible
characters stripped, homoglyphs mapped, NFKC, percent-escapes decoded) with an
offset map so redaction is applied to exact spans of the *original* text.
Base64-looking tokens are opportunistically decoded and scanned; a token whose
decoded form contains PHI is redacted in full.

Configuration surface (see docs/policy.md): per-type allowlists for public
non-PHI values, detector selection and locale packs, config- or code-defined
custom detectors, field-path scoping, AUDIT_ONLY shadow mode, a cloud NER
backend, and metric callbacks. Reversible tokenization, streaming redaction,
and async/batch scanning are exposed as methods.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import hashlib
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from clinicsentry.phi.adversarial import AdversarialDetector, EncodedPHIDetector
from clinicsentry.phi.detectors import (
    Hit,
    PresidioDetector,
    RegexDetector,
    merge_hits,
    resolve_specs,
)
from clinicsentry.phi.parsers import (
    dicom_phi_pairs,
    fhir_phi_paths,
    hl7_phi_segments,
)
from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.phi.redaction import (
    RedactionMode,
    replacement_for,
    shape_preserving,
)
from clinicsentry.phi.streaming import DEFAULT_HOLDBACK, StreamRedactor
from clinicsentry.types import PHITag

__all__ = [
    "PHIFinding",
    "PHIScanResult",
    "PHIFirewall",
    "TokenizeResult",
    "MetricHook",
]

# Payloads nested deeper than this are redacted wholesale rather than walked —
# unbounded recursion is an evasion / denial-of-service vector, and silently
# passing the payload through would fail open.
DEFAULT_MAX_SCAN_DEPTH = 64

MetricHook = Callable[[str, float, dict[str, str]], None]

_ALLOW_NORM = re.compile(r"[^a-z0-9]")


def _normalize_allow(value: str) -> str:
    """Canonical form for allowlist comparison: lowercase alphanumerics only."""
    return _ALLOW_NORM.sub("", value.lower())


@dataclass
class PHIFinding:
    """One detected identifier: what, where, and what was done about it.

    ``replacement`` is None when the text was left unchanged (AUDIT_ONLY).
    """

    phi_type: str
    start: int
    end: int
    confidence: float
    field_path: str
    action: str
    replacement: str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "phi_type": self.phi_type,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "field_path": self.field_path,
            "action": self.action,
            "replacement": self.replacement,
        }


@dataclass
class PHIScanResult:
    """Outcome of a single firewall scan call."""

    redacted: Any
    tags: list[PHITag] = field(default_factory=list)
    raw_hits: list[Hit] = field(default_factory=list)
    findings: list[PHIFinding] = field(default_factory=list)

    @property
    def has_phi(self) -> bool:
        """True if anything was detected (regardless of redaction mode)."""
        return bool(self.findings) or bool(self.tags)

    @property
    def by_type(self) -> dict[str, int]:
        """Finding counts keyed by PHI type."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.phi_type] = counts.get(f.phi_type, 0) + 1
        return counts


@dataclass
class TokenizeResult:
    """Reversible-tokenization output; ``detokenize`` restores originals."""

    redacted: Any
    mapping: dict[str, str]
    findings: list[PHIFinding] = field(default_factory=list)

    @property
    def text(self) -> str:
        """The tokenized payload as a string (convenience for string payloads)."""
        return self.redacted if isinstance(self.redacted, str) else str(self.redacted)

    def detokenize(self, text: str) -> str:
        """Replace every token in ``text`` with its original value."""
        for token in sorted(self.mapping, key=len, reverse=True):
            text = text.replace(token, self.mapping[token])
        return text


class PHIFirewall:
    """High-level facade over PHI detection + redaction + propagation tracking."""

    def __init__(
        self,
        mode: RedactionMode = RedactionMode.REDACT,
        overrides: dict[str, RedactionMode] | None = None,
        use_presidio: bool = False,
        session_salt: str = "session",
        propagation: PropagationGraph | None = None,
        decode_encoded: bool = True,
        max_depth: int = DEFAULT_MAX_SCAN_DEPTH,
        allowlist: dict[str, Sequence[str]] | None = None,
        detectors: Sequence[str] | None = None,
        locales: Sequence[str] = (),
        custom_detectors: Sequence[Any] = (),
        skip_fields: Sequence[str] = (),
        always_redact_fields: Sequence[str] = (),
        detector_backend: str | None = None,
        on_metric: MetricHook | None = None,
    ) -> None:
        """Construct a firewall instance.

        Args:
            mode: default redaction strategy (AUDIT_ONLY = detect, don't mutate).
            overrides: per PHI-type strategy override.
            use_presidio: enable presidio if installed.
            session_salt: pseudonymization salt; should be per-session.
            propagation: shared propagation graph (defaults to a fresh one).
            decode_encoded: scan base64-decodable tokens for embedded PHI.
            max_depth: nesting depth beyond which payloads are redacted whole.
            allowlist: per-type literal values exempt from redaction
                (normalized: case and separators ignored).
            detectors: exact detector labels to enable (default: core set).
            locales: locale packs to add (e.g. ``["en_GB"]``).
            custom_detectors: objects with ``detect(text) -> [Hit]`` — from
                ``register_detector`` or ``custom_detectors`` policy entries.
            skip_fields: dotted field-path globs to leave unscanned.
            always_redact_fields: dotted field-path globs redacted wholesale.
            detector_backend: optional cloud NER backend name.
            on_metric: callback ``(name, value, tags)`` for counters/timers.
        """
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        self.mode = mode
        self.overrides = dict(overrides or {})
        self.session_salt = session_salt
        self.decode_encoded = decode_encoded
        self.max_depth = max_depth
        self.on_metric = on_metric
        self._skip_fields = list(skip_fields)
        self._always_redact_fields = list(always_redact_fields)
        self._allowlist: dict[str, set[str]] = {
            str(k).upper(): {_normalize_allow(str(v)) for v in vals}
            for k, vals in (allowlist or {}).items()
        }
        self._custom = list(custom_detectors)
        for det in self._custom:
            det_mode = getattr(det, "mode", None)
            if det_mode:
                self.overrides.setdefault(
                    str(getattr(det, "label", "")).upper(), RedactionMode(det_mode)
                )
        self._regex = RegexDetector(specs=resolve_specs(detectors, locales))
        self._adversarial = AdversarialDetector(inner=self._regex)
        self._encoded = EncodedPHIDetector(inner=self._regex) if decode_encoded else None
        self._presidio = PresidioDetector() if use_presidio else None
        self._cloud: Any = None
        if detector_backend:
            from clinicsentry.phi.cloud import build_cloud_detector

            self._cloud = build_cloud_detector(
                detector_backend,
                on_error=lambda exc: self._metric(
                    "clinicsentry.detector.error", 1.0, {"backend": detector_backend}
                ),
            )
        self.propagation = propagation or PropagationGraph()

    # ------------------------------------------------------------------
    # Public scan API
    # ------------------------------------------------------------------

    def scan(self, payload: Any, *, origin_agent: str = "unknown") -> PHIScanResult:
        """Scan an arbitrary payload, returning redacted form + findings + tags."""
        started = time.perf_counter()
        result = self._scan(payload, origin_agent=origin_agent, depth=0, path="")
        self._metric("clinicsentry.scan.latency_ms", (time.perf_counter() - started) * 1000.0, {})
        for f in result.findings:
            self._metric("clinicsentry.phi.redactions", 1.0, {"type": f.phi_type})
        return result

    async def ascan(self, payload: Any, *, origin_agent: str = "unknown") -> PHIScanResult:
        """Async wrapper around :meth:`scan` (runs in a worker thread)."""
        return await asyncio.to_thread(self.scan, payload, origin_agent=origin_agent)

    def scan_batch(
        self, payloads: Sequence[Any], *, origin_agent: str = "unknown"
    ) -> list[PHIScanResult]:
        """Scan multiple payloads; results are index-aligned with the input."""
        return [self.scan(p, origin_agent=origin_agent) for p in payloads]

    def tokenize(
        self,
        payload: Any,
        *,
        origin_agent: str = "unknown",
        format_preserving: bool = False,
    ) -> TokenizeResult:
        """Replace detected PHI with reversible tokens.

        Tokens are deterministic per ``(session_salt, type, value)`` so equal
        values tokenize identically within a session. With
        ``format_preserving=True`` the replacement keeps the original shape
        (digits→digits, letters→letters) — pseudonymization, not encryption.
        """
        mapping: dict[str, str] = {}

        def replacer(hit: Hit) -> str:
            if format_preserving:
                token = shape_preserving(hit.value, self.session_salt)
            else:
                digest = hashlib.sha256(
                    f"{self.session_salt}|{hit.phi_type}|{hit.value}".encode()
                ).hexdigest()[:8]
                token = f"<{hit.phi_type}_{digest}>"
            mapping[token] = hit.value
            return token

        result = self._scan(payload, origin_agent=origin_agent, depth=0, path="", replacer=replacer)
        return TokenizeResult(redacted=result.redacted, mapping=mapping, findings=result.findings)

    def stream_redactor(
        self, *, origin_agent: str = "stream", holdback: int = DEFAULT_HOLDBACK
    ) -> StreamRedactor:
        """Return a stateful redactor for chunked LLM output (see B6 docs)."""

        def detect(text: str) -> list[Hit]:
            return self._filter_allowlist(self._string_hits(text))

        def redact(text: str, hits: list[Hit]) -> str:
            for hit in sorted(hits, key=lambda h: h.start, reverse=True):
                eff = self.overrides.get(hit.phi_type, self.mode)
                repl = replacement_for(hit.value, hit.phi_type, eff, self.session_salt)
                if repl is not None:
                    text = text[: hit.start] + repl + text[hit.end :]
            return text

        def on_hits(hits: list[Hit]) -> None:
            for h in hits:
                self._make_tag(
                    phi_type=h.phi_type,
                    source=h.source,
                    confidence=h.confidence,
                    redacted_value=f"[{h.phi_type}]",
                    origin_agent=origin_agent,
                )
                self._metric("clinicsentry.phi.redactions", 1.0, {"type": h.phi_type})

        return StreamRedactor(detect=detect, redact=redact, on_hits=on_hits, holdback=holdback)

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _scan(
        self,
        payload: Any,
        *,
        origin_agent: str,
        depth: int,
        path: str,
        replacer: Callable[[Hit], str] | None = None,
    ) -> PHIScanResult:
        """Depth-tracked recursive scan dispatcher."""
        if path:
            if self._matches(path, self._always_redact_fields):
                tag = self._make_tag(
                    phi_type="FIELD_POLICY",
                    source=f"firewall:always_redact:{path}",
                    confidence=1.0,
                    redacted_value="[REDACTED:FIELD]",
                    origin_agent=origin_agent,
                )
                finding = PHIFinding(
                    phi_type="FIELD_POLICY",
                    start=0,
                    end=0,
                    confidence=1.0,
                    field_path=path,
                    action="ALWAYS_REDACT",
                    replacement="[REDACTED:FIELD]",
                )
                return PHIScanResult(redacted="[REDACTED:FIELD]", tags=[tag], findings=[finding])
            if self._matches(path, self._skip_fields):
                return PHIScanResult(redacted=payload)
        if payload is None or isinstance(payload, (bool, int, float)):
            return PHIScanResult(redacted=payload)
        if depth >= self.max_depth:
            tag = self._make_tag(
                phi_type="SCAN_DEPTH_EXCEEDED",
                source=f"firewall:max_depth={self.max_depth}",
                confidence=1.0,
                redacted_value="[REDACTED:MAX_DEPTH_EXCEEDED]",
                origin_agent=origin_agent,
            )
            finding = PHIFinding(
                phi_type="SCAN_DEPTH_EXCEEDED",
                start=0,
                end=0,
                confidence=1.0,
                field_path=path,
                action="MAX_DEPTH",
                replacement="[REDACTED:MAX_DEPTH_EXCEEDED]",
            )
            return PHIScanResult(
                redacted="[REDACTED:MAX_DEPTH_EXCEEDED]", tags=[tag], findings=[finding]
            )
        if isinstance(payload, str):
            return self._scan_string(
                payload, origin_agent=origin_agent, path=path, replacer=replacer
            )
        if isinstance(payload, (bytes, bytearray)):
            return self._scan_bytes(
                payload, origin_agent=origin_agent, path=path, replacer=replacer
            )
        if isinstance(payload, dict):
            return self._scan_dict(
                payload, origin_agent=origin_agent, depth=depth, path=path, replacer=replacer
            )
        if isinstance(payload, (list, tuple)):
            scans = [
                self._scan(
                    item,
                    origin_agent=origin_agent,
                    depth=depth + 1,
                    path=self._child_path(path, str(i)),
                    replacer=replacer,
                )
                for i, item in enumerate(payload)
            ]
            redacted: Any = [s.redacted for s in scans]
            if isinstance(payload, tuple):
                redacted = tuple(redacted)
            return self._combine(scans, redacted)
        if isinstance(payload, (set, frozenset)):
            scans = [
                self._scan(
                    item,
                    origin_agent=origin_agent,
                    depth=depth + 1,
                    path=path,
                    replacer=replacer,
                )
                for item in payload
            ]
            members = {s.redacted for s in scans}
            return self._combine(
                scans, frozenset(members) if isinstance(payload, frozenset) else members
            )
        # pydicom Dataset detection
        dicom_pairs = dicom_phi_pairs(payload)
        if dicom_pairs:
            tags = [
                self._make_tag(
                    phi_type=name.upper() if isinstance(name, str) else "DICOM",
                    source=f"dicom:{name}",
                    confidence=0.99,
                    redacted_value=f"[REDACTED:{name}]",
                    origin_agent=origin_agent,
                )
                for name, _ in dicom_pairs
            ]
            return PHIScanResult(redacted="[REDACTED:DICOM_DATASET]", tags=tags)
        return PHIScanResult(redacted=payload)

    @staticmethod
    def _child_path(path: str, segment: str) -> str:
        return f"{path}.{segment}" if path else segment

    @staticmethod
    def _matches(path: str, patterns: Sequence[str]) -> bool:
        return any(fnmatch.fnmatchcase(path, pat) for pat in patterns)

    @staticmethod
    def _combine(scans: Sequence[PHIScanResult], redacted: Any) -> PHIScanResult:
        return PHIScanResult(
            redacted=redacted,
            tags=[t for s in scans for t in s.tags],
            raw_hits=[h for s in scans for h in s.raw_hits],
            findings=[f for s in scans for f in s.findings],
        )

    # ------------------------------------------------------------------
    # Internal: strings
    # ------------------------------------------------------------------

    def _string_hits(self, text: str) -> list[Hit]:
        """All detection layers for one string, merged and deduped."""
        hl7_hits: list[Hit] = []
        if text.startswith("MSH|") or "\rPID|" in text or "\nPID|" in text:
            for ref, value in hl7_phi_segments(text):
                if not value:
                    continue
                # Redact every occurrence of the field value — the first match
                # is not necessarily the PID field itself.
                idx = text.find(value)
                while idx >= 0:
                    hl7_hits.append(
                        Hit(
                            phi_type=f"HL7_{ref}",
                            start=idx,
                            end=idx + len(value),
                            value=value,
                            confidence=0.99,
                            source=f"hl7:{ref}",
                        )
                    )
                    idx = text.find(value, idx + len(value))
        # Fast path: plain ASCII with no percent-escapes is already canonical,
        # so the offset-mapping normalizer would be an identity transform.
        if text.isascii() and "%" not in text:
            base_hits = self._regex.detect(text)
            self._metric("clinicsentry.scan.path", 1.0, {"path": "fast"})
        else:
            base_hits = self._adversarial.detect(text)
            self._metric("clinicsentry.scan.path", 1.0, {"path": "normalized"})
        encoded_hits = self._encoded.detect(text) if self._encoded else []
        presidio_hits = self._presidio.detect(text) if self._presidio else []
        custom_hits: list[Hit] = []
        for det in self._custom:
            custom_hits.extend(det.detect(text))
        cloud_hits: list[Hit] = self._cloud.detect(text) if self._cloud else []
        return merge_hits(base_hits, encoded_hits, presidio_hits, hl7_hits, custom_hits, cloud_hits)

    def _filter_allowlist(self, hits: Iterable[Hit]) -> list[Hit]:
        """Drop hits whose normalized value is allow-listed for their type."""
        if not self._allowlist:
            return list(hits)
        kept: list[Hit] = []
        for h in hits:
            allowed = self._allowlist.get(h.phi_type.upper())
            if allowed and _normalize_allow(h.value) in allowed:
                self._metric("clinicsentry.phi.allowlisted", 1.0, {"type": h.phi_type})
                continue
            kept.append(h)
        return kept

    def _scan_string(
        self,
        text: str,
        *,
        origin_agent: str,
        path: str = "",
        replacer: Callable[[Hit], str] | None = None,
    ) -> PHIScanResult:
        """Scan a free-text string; HL7 parsing kicks in when it looks like HL7."""
        hits = self._filter_allowlist(self._string_hits(text))
        findings: list[PHIFinding] = []
        new_text = text
        for hit in sorted(hits, key=lambda h: h.start, reverse=True):
            if replacer is not None:
                repl: str | None = replacer(hit)
                action = "TOKENIZE"
            else:
                eff = self.overrides.get(hit.phi_type, self.mode)
                repl = replacement_for(hit.value, hit.phi_type, eff, self.session_salt)
                action = eff.value
            if repl is not None:
                new_text = new_text[: hit.start] + repl + new_text[hit.end :]
            findings.append(
                PHIFinding(
                    phi_type=hit.phi_type,
                    start=hit.start,
                    end=hit.end,
                    confidence=hit.confidence,
                    field_path=path,
                    action=action,
                    replacement=repl,
                )
            )
        findings.reverse()
        tags = [
            self._make_tag(
                phi_type=h.phi_type,
                source=h.source,
                confidence=h.confidence,
                redacted_value=f"[{h.phi_type}]",
                origin_agent=origin_agent,
            )
            for h in hits
        ]
        return PHIScanResult(redacted=new_text, tags=tags, raw_hits=hits, findings=findings)

    # ------------------------------------------------------------------
    # Internal: bytes
    # ------------------------------------------------------------------

    def _scan_bytes(
        self,
        payload: bytes | bytearray,
        *,
        origin_agent: str,
        path: str = "",
        replacer: Callable[[Hit], str] | None = None,
    ) -> PHIScanResult:
        """Scan UTF-8-decodable bytes as text; opaque binary passes through."""
        try:
            decoded = bytes(payload).decode("utf-8")
        except UnicodeDecodeError:
            return PHIScanResult(redacted=payload)
        sub = self._scan_string(decoded, origin_agent=origin_agent, path=path, replacer=replacer)
        if not sub.tags:
            return PHIScanResult(redacted=payload)
        return PHIScanResult(
            redacted=str(sub.redacted).encode("utf-8"),
            tags=sub.tags,
            raw_hits=sub.raw_hits,
            findings=sub.findings,
        )

    # ------------------------------------------------------------------
    # Internal: dicts (FHIR-aware)
    # ------------------------------------------------------------------

    def _scan_dict(
        self,
        data: dict[str, Any],
        *,
        origin_agent: str,
        depth: int,
        path: str = "",
        replacer: Callable[[Hit], str] | None = None,
    ) -> PHIScanResult:
        """Walk a dict; if it is a FHIR resource, treat schema PHI fields specially."""
        tags: list[PHITag] = []
        findings: list[PHIFinding] = []
        raw_hits: list[Hit] = []
        out: dict[Any, Any] = {}
        fhir_paths = {p for p, _ in fhir_phi_paths(data)} if "resourceType" in data else set()
        for key, value in data.items():
            out_key = key
            child = self._child_path(path, str(key))
            if isinstance(key, str):
                key_scan = self._scan_string(key, origin_agent=origin_agent, path=child)
                if key_scan.tags:
                    tags.extend(key_scan.tags)
                    findings.extend(key_scan.findings)
                    out_key = str(key_scan.redacted)
                    while out_key in out:  # avoid clobbering on redaction collisions
                        out_key += "_"
            full_path = f"{data.get('resourceType', '')}.{key}".strip(".") if fhir_paths else None
            if full_path and any(
                p == full_path or p.startswith(full_path + ".") or p.startswith(full_path + "[")
                for p in fhir_paths
            ):
                tags.append(
                    self._make_tag(
                        phi_type=f"FHIR_{key.upper()}",
                        source=f"fhir:{full_path}",
                        confidence=0.99,
                        redacted_value=f"[REDACTED:{key}]",
                        origin_agent=origin_agent,
                    )
                )
                findings.append(
                    PHIFinding(
                        phi_type=f"FHIR_{key.upper()}",
                        start=0,
                        end=0,
                        confidence=0.99,
                        field_path=child,
                        action=RedactionMode.REDACT.value,
                        replacement=f"[REDACTED:{key}]",
                    )
                )
                out[out_key] = f"[REDACTED:{key}]"
                continue
            sub = self._scan(
                value, origin_agent=origin_agent, depth=depth + 1, path=child, replacer=replacer
            )
            out[out_key] = sub.redacted
            tags.extend(sub.tags)
            findings.extend(sub.findings)
            raw_hits.extend(sub.raw_hits)
        return PHIScanResult(redacted=out, tags=tags, raw_hits=raw_hits, findings=findings)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _metric(self, name: str, value: float, metric_tags: dict[str, str]) -> None:
        if self.on_metric is None:
            return
        # Metric sinks must never break a scan.
        with contextlib.suppress(Exception):
            self.on_metric(name, value, metric_tags)

    def _make_tag(
        self,
        *,
        phi_type: str,
        source: str,
        confidence: float,
        redacted_value: str,
        origin_agent: str,
    ) -> PHITag:
        tag = PHITag(
            phi_type=phi_type,
            source=source,
            confidence=confidence,
            redacted_value=redacted_value,
            origin_agent=origin_agent,
            propagation_path=[origin_agent],
        )
        self.propagation.register(tag)
        return tag
