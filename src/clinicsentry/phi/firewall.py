"""PHI Firewall — coordinates detectors, parsers, redaction, propagation.

This is the central entry point of Module 1. It accepts heterogenous payloads
(strings, JSON-like dicts that may be FHIR resources, HL7 v2 strings, pydicom
Datasets, lists/tuples/sets, UTF-8 bytes) and returns a redacted version plus
a list of `PHITag`s.

Detection on strings is adversarial-aware: input is normalized (invisible
characters stripped, homoglyphs mapped, NFKC, percent-escapes decoded) with an
offset map so redaction is applied to exact spans of the *original* text.
Base64-looking tokens are opportunistically decoded and scanned; a token whose
decoded form contains PHI is redacted in full.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from clinicsentry.phi.adversarial import AdversarialDetector, EncodedPHIDetector
from clinicsentry.phi.detectors import (
    Hit,
    PresidioDetector,
    RegexDetector,
    merge_hits,
)
from clinicsentry.phi.parsers import (
    dicom_phi_pairs,
    fhir_phi_paths,
    hl7_phi_segments,
)
from clinicsentry.phi.propagation import PropagationGraph
from clinicsentry.phi.redaction import RedactionMode, RedactionResult, apply_redaction
from clinicsentry.types import PHITag

__all__ = [
    "PHIScanResult",
    "PHIFirewall",
]

# Payloads nested deeper than this are redacted wholesale rather than walked —
# unbounded recursion is an evasion / denial-of-service vector, and silently
# passing the payload through would fail open.
DEFAULT_MAX_SCAN_DEPTH = 64


@dataclass
class PHIScanResult:
    """Outcome of a single firewall scan call."""

    redacted: Any
    tags: list[PHITag] = field(default_factory=list)
    raw_hits: list[Hit] = field(default_factory=list)


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
    ) -> None:
        """Construct a firewall instance.

        Args:
            mode: default redaction strategy.
            overrides: per PHI-type strategy override.
            use_presidio: enable presidio if installed.
            session_salt: pseudonymization salt; should be per-session.
            propagation: shared propagation graph (defaults to a fresh one).
            decode_encoded: scan base64-decodable tokens for embedded PHI.
            max_depth: nesting depth beyond which payloads are redacted whole.
        """
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        self.mode = mode
        self.overrides = overrides or {}
        self.session_salt = session_salt
        self.decode_encoded = decode_encoded
        self.max_depth = max_depth
        self._regex = RegexDetector()
        self._adversarial = AdversarialDetector(inner=self._regex)
        self._encoded = EncodedPHIDetector(inner=self._regex) if decode_encoded else None
        self._presidio = PresidioDetector() if use_presidio else None
        self.propagation = propagation or PropagationGraph()

    # ------------------------------------------------------------------
    # Public scan API
    # ------------------------------------------------------------------

    def scan(self, payload: Any, *, origin_agent: str = "unknown") -> PHIScanResult:
        """Scan an arbitrary payload, returning redacted form + PHI tags."""
        return self._scan(payload, origin_agent=origin_agent, depth=0)

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _scan(self, payload: Any, *, origin_agent: str, depth: int) -> PHIScanResult:
        """Depth-tracked recursive scan dispatcher."""
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
            return PHIScanResult(redacted="[REDACTED:MAX_DEPTH_EXCEEDED]", tags=[tag])
        if isinstance(payload, str):
            return self._scan_string(payload, origin_agent=origin_agent)
        if isinstance(payload, (bytes, bytearray)):
            return self._scan_bytes(payload, origin_agent=origin_agent)
        if isinstance(payload, dict):
            return self._scan_dict(payload, origin_agent=origin_agent, depth=depth)
        if isinstance(payload, (list, tuple)):
            scans = [
                self._scan(item, origin_agent=origin_agent, depth=depth + 1) for item in payload
            ]
            redacted: Any = [s.redacted for s in scans]
            if isinstance(payload, tuple):
                redacted = tuple(redacted)
            return PHIScanResult(
                redacted=redacted,
                tags=[t for s in scans for t in s.tags],
                raw_hits=[h for s in scans for h in s.raw_hits],
            )
        if isinstance(payload, (set, frozenset)):
            scans = [
                self._scan(item, origin_agent=origin_agent, depth=depth + 1) for item in payload
            ]
            members = {s.redacted for s in scans}
            return PHIScanResult(
                redacted=frozenset(members) if isinstance(payload, frozenset) else members,
                tags=[t for s in scans for t in s.tags],
                raw_hits=[h for s in scans for h in s.raw_hits],
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

    # ------------------------------------------------------------------
    # Internal: strings
    # ------------------------------------------------------------------

    def _scan_string(self, text: str, *, origin_agent: str) -> PHIScanResult:
        """Scan a free-text string. Falls back to HL7 parsing when it looks like HL7."""
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
        else:
            base_hits = self._adversarial.detect(text)
        encoded_hits = self._encoded.detect(text) if self._encoded else []
        presidio_hits = self._presidio.detect(text) if self._presidio else []
        hits = merge_hits(base_hits, encoded_hits, presidio_hits, hl7_hits)
        result: RedactionResult = apply_redaction(
            text,
            hits,
            mode=self.mode,
            overrides=self.overrides,
            session_salt=self.session_salt,
        )
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
        return PHIScanResult(redacted=result.text, tags=tags, raw_hits=hits)

    # ------------------------------------------------------------------
    # Internal: bytes
    # ------------------------------------------------------------------

    def _scan_bytes(self, payload: bytes | bytearray, *, origin_agent: str) -> PHIScanResult:
        """Scan UTF-8-decodable bytes as text; opaque binary passes through."""
        try:
            decoded = bytes(payload).decode("utf-8")
        except UnicodeDecodeError:
            return PHIScanResult(redacted=payload)
        sub = self._scan_string(decoded, origin_agent=origin_agent)
        if not sub.tags:
            return PHIScanResult(redacted=payload)
        return PHIScanResult(
            redacted=str(sub.redacted).encode("utf-8"),
            tags=sub.tags,
            raw_hits=sub.raw_hits,
        )

    # ------------------------------------------------------------------
    # Internal: dicts (FHIR-aware)
    # ------------------------------------------------------------------

    def _scan_dict(self, data: dict[str, Any], *, origin_agent: str, depth: int) -> PHIScanResult:
        """Walk a dict; if it is a FHIR resource, treat schema PHI fields specially."""
        tags: list[PHITag] = []
        out: dict[Any, Any] = {}
        fhir_paths = {p for p, _ in fhir_phi_paths(data)} if "resourceType" in data else set()
        for key, value in data.items():
            out_key = key
            if isinstance(key, str):
                key_scan = self._scan_string(key, origin_agent=origin_agent)
                if key_scan.tags:
                    tags.extend(key_scan.tags)
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
                out[out_key] = f"[REDACTED:{key}]"
                continue
            sub = self._scan(value, origin_agent=origin_agent, depth=depth + 1)
            out[out_key] = sub.redacted
            tags.extend(sub.tags)
        return PHIScanResult(redacted=out, tags=tags)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
