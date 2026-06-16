"""Adversarial PHI detection (homoglyph, invisible-character, and encoding evasions).

These transformations are common evasions: substituting Cyrillic 'е' for ASCII
'e' in an email, zero-width characters within an SSN, replacing digits with
look-alikes (``O`` for ``0``), or percent-encoding an email address. Models
trained on clean text miss these; this module normalizes the input *before*
a downstream regex / NER stage.

Normalization is offset-preserving: :func:`normalize_with_map` returns, for
every character of the normalized output, the span of the original string it
was derived from. Hits found in normalized space are mapped back to exact
spans in the original text, so redaction applied to the original string covers
the full obfuscated region (including any stripped invisible characters).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from clinicsentry.phi.detectors import Hit

__all__ = [
    "AdversarialNormalizer",
    "AdversarialDetector",
    "EncodedPHIDetector",
    "NormalizedText",
    "normalize_with_map",
]


# Common homoglyph → ASCII map. Extend as new attacks surface.
_HOMOGLYPHS: dict[str, str] = {
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic e
    "о": "o",  # Cyrillic o
    "р": "p",  # Cyrillic er
    "с": "c",  # Cyrillic es
    "у": "y",  # Cyrillic u
    "х": "x",  # Cyrillic kha
    "𝟢": "0",  # mathematical zero
    "𝟣": "1",
    "𝟤": "2",
    "𝟥": "3",
    "𝟦": "4",
    "𝟧": "5",
    "𝟨": "6",
    "𝟩": "7",
    "𝟪": "8",
    "𝟫": "9",
}

# Zero-width and other invisible characters.
_INVISIBLES = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}

_HEX_DIGITS = set("0123456789abcdefABCDEF")


@dataclass
class NormalizedText:
    """Normalized string plus a per-character map back to original spans.

    ``spans[i]`` is the ``(start, end)`` half-open span of the original string
    that produced normalized character ``i``.
    """

    text: str
    spans: list[tuple[int, int]]

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a normalized-space span back to the covering original span."""
        if not self.spans or start >= end:
            return (0, 0)
        end = min(end, len(self.spans))
        return (self.spans[start][0], self.spans[end - 1][1])


def _percent_decode_char(text: str, i: int) -> str | None:
    """Return the decoded character for a ``%XX`` triplet at ``i``, else None."""
    if text[i] != "%" or i + 2 >= len(text):
        return None
    hi, lo = text[i + 1], text[i + 2]
    if hi not in _HEX_DIGITS or lo not in _HEX_DIGITS:
        return None
    code = int(hi + lo, 16)
    # Only decode printable single-byte characters; multi-byte UTF-8
    # sequences are decoded byte-wise which is sufficient for ASCII PHI.
    if code < 0x20 or code > 0x7E:
        return None
    return chr(code)


def normalize_with_map(text: str, *, percent_decode: bool = True) -> NormalizedText:
    """Normalize adversarial input while recording original character spans.

    Stages (single pass): strip invisibles, map homoglyphs, NFKC-normalize each
    character, and (optionally) decode printable ``%XX`` percent-escapes.
    """
    out: list[str] = []
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _INVISIBLES:
            i += 1
            continue
        if percent_decode and ch == "%":
            decoded = _percent_decode_char(text, i)
            if decoded is not None:
                out.append(decoded)
                spans.append((i, i + 3))
                i += 3
                continue
        ch = _HOMOGLYPHS.get(ch, ch)
        normalized = unicodedata.normalize("NFKC", ch)
        for sub in normalized:
            out.append(sub)
            spans.append((i, i + 1))
        i += 1
    return NormalizedText(text="".join(out), spans=spans)


@dataclass
class AdversarialNormalizer:
    """Normalize adversarial unicode into a canonical ASCII form."""

    percent_decode: bool = False

    def normalize(self, text: str) -> str:
        """Strip invisibles, apply homoglyph map, NFKC-normalize."""
        return normalize_with_map(text, percent_decode=self.percent_decode).text


@dataclass
class AdversarialDetector:
    """Normalize, then forward to an inner detector with exact span mapping.

    Hits returned by the inner detector (which sees the normalized text) are
    mapped back to spans in the *original* string via the normalization offset
    map. The mapped span covers every original character that contributed to
    the match — including stripped invisibles — so redaction of the original
    text removes the full obfuscated region.
    """

    inner: Any
    percent_decode: bool = True

    def detect(self, text: str) -> list[Hit]:
        """Detect on the normalized text and map hits back to original spans."""
        normalized = normalize_with_map(text, percent_decode=self.percent_decode)
        inner_hits: list[Hit] = self.inner.detect(normalized.text)
        if normalized.text == text:
            return inner_hits
        mapped: list[Hit] = []
        for h in inner_hits:
            start, end = normalized.original_span(h.start, h.end)
            mapped.append(
                Hit(
                    phi_type=h.phi_type,
                    start=start,
                    end=end,
                    value=text[start:end],
                    confidence=h.confidence,
                    source=f"{h.source}+normalized",
                )
            )
        return mapped


# Candidate base64 tokens: runs of base64 alphabet with optional padding long
# enough to encode ≥9 bytes (the shortest PHI identifiers, e.g. an SSN).
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
# Hard cap on decode work per token — base64 PHI payloads are short.
_B64_MAX_TOKEN_LEN = 4096


@dataclass
class EncodedPHIDetector:
    """Opportunistically decode base64-looking tokens and scan their contents.

    A token that decodes to printable UTF-8 containing PHI yields a hit
    spanning the *entire encoded token* in the original text, so redaction
    removes the whole carrier. Over-redacting an opaque token that happens to
    decode to PHI-shaped text is fail-safe; under-redacting is not.
    """

    inner: Any

    def detect(self, text: str) -> list[Hit]:
        """Return hits for encoded tokens whose decoded form contains PHI."""
        if len(text) < 12:
            return []
        hits: list[Hit] = []
        for m in _B64_TOKEN.finditer(text):
            token = m.group(0)
            if len(token) % 4 != 0 or len(token) > _B64_MAX_TOKEN_LEN:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if not decoded or not decoded.isprintable():
                continue
            for h in self.inner.detect(decoded):
                hits.append(
                    Hit(
                        phi_type=h.phi_type,
                        start=m.start(),
                        end=m.end(),
                        value=token,
                        confidence=min(h.confidence, 0.95),
                        source=f"{h.source}+base64",
                    )
                )
        return hits
