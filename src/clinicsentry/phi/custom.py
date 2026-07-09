r"""Custom detector extension points (stable public API).

Two ways to add a domain-specific detector:

Code — decorate a span generator and hand it to the guard/firewall::

    from clinicsentry import register_detector

    @register_detector(label="PUMP_SERIAL")
    def pump_serial(text: str):
        for m in re.finditer(r"\\b(?:SN|serial)[\\s:#-]*([A-Z0-9]{6,})\\b", text, re.I):
            yield m.start(), m.end(), 0.95

    guard = ClinicSentry(detectors=[pump_serial])

Config — a pure-regex detector in policy YAML::

    phi_firewall:
      custom_detectors:
        - label: PUMP_SERIAL
          pattern: '\\b(?:SN|serial)[\\s:#-]*[A-Z0-9]{6,}\\b'
          flags: [IGNORECASE]
          mode: REDACT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from clinicsentry.phi.detectors import Hit

__all__ = ["CustomDetector", "CustomRegexDetector", "register_detector"]

SpanGenerator = Callable[[str], Iterable[tuple[int, int, float]]]

_FLAG_NAMES: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII,
}


@dataclass
class CustomDetector:
    """A user-supplied detector wrapping a span-generator callable.

    Instances duck-type the ``Detector`` protocol (``detect(text) -> [Hit]``)
    and remain callable as the original function.
    """

    label: str
    fn: SpanGenerator
    mode: str | None = None
    default_confidence: float = 0.95

    def __call__(self, text: str) -> Iterable[tuple[int, int, float]]:
        """Invoke the wrapped span generator directly."""
        return self.fn(text)

    def detect(self, text: str) -> list[Hit]:
        """Run the span generator and wrap spans as hits."""
        hits: list[Hit] = []
        for span in self.fn(text):
            start, end = int(span[0]), int(span[1])
            conf = float(span[2]) if len(span) > 2 else self.default_confidence
            if not 0 <= start < end <= len(text):
                continue
            hits.append(
                Hit(
                    phi_type=self.label,
                    start=start,
                    end=end,
                    value=text[start:end],
                    confidence=conf,
                    source=f"custom:{self.label}",
                )
            )
        return hits


def register_detector(
    label: str,
    mode: str | None = None,
    confidence: float = 0.95,
) -> Callable[[SpanGenerator], CustomDetector]:
    """Decorate a span generator into a detector usable by the firewall.

    The generator receives the text and yields ``(start, end)`` or
    ``(start, end, confidence)`` spans. ``mode`` optionally sets the redaction
    strategy for this label (equivalent to a per-type override).
    """
    if not label or not label.replace("_", "").isalnum():
        raise ValueError(f"invalid detector label {label!r}")

    def decorate(fn: SpanGenerator) -> CustomDetector:
        return CustomDetector(label=label.upper(), fn=fn, mode=mode, default_confidence=confidence)

    return decorate


@dataclass
class CustomRegexDetector:
    """Config-defined regex detector (see ``phi_firewall.custom_detectors``)."""

    label: str
    pattern: re.Pattern[str]
    confidence: float = 0.9
    mode: str | None = None
    group: int = 0
    _source: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self._source = f"custom:{self.label}"

    @classmethod
    def from_config(cls, entry: dict[str, object]) -> CustomRegexDetector:
        """Build from a validated policy mapping; raises ValueError on bad input."""
        label = str(entry.get("label", "")).upper()
        if not label or not label.replace("_", "").isalnum():
            raise ValueError(f"invalid custom detector label {entry.get('label')!r}")
        raw_flags = entry.get("flags") or []
        if not isinstance(raw_flags, list):
            raise ValueError(f"custom detector {label}: flags must be a list")
        flags = re.RegexFlag(0)
        for name in raw_flags:
            try:
                flags |= _FLAG_NAMES[str(name).upper()]
            except KeyError:
                raise ValueError(
                    f"custom detector {label}: unknown flag {name!r}; "
                    f"allowed: {sorted(_FLAG_NAMES)}"
                ) from None
        try:
            pattern = re.compile(str(entry.get("pattern", "")), flags)
        except re.error as exc:
            raise ValueError(f"custom detector {label}: invalid pattern: {exc}") from exc
        confidence = float(entry.get("confidence", 0.9))  # type: ignore[arg-type]
        if not 0.0 < confidence <= 1.0:
            raise ValueError(f"custom detector {label}: confidence must be in (0, 1]")
        mode = entry.get("mode")
        return cls(
            label=label,
            pattern=pattern,
            confidence=confidence,
            mode=str(mode) if mode is not None else None,
        )

    def detect(self, text: str) -> list[Hit]:
        """Return hits for every pattern match."""
        if not text:
            return []
        return [
            Hit(
                phi_type=self.label,
                start=m.start(self.group),
                end=m.end(self.group),
                value=m.group(self.group),
                confidence=self.confidence,
                source=self._source,
            )
            for m in self.pattern.finditer(text)
        ]


def build_custom_detectors(entries: Sequence[dict[str, object]]) -> list[CustomRegexDetector]:
    """Compile a list of config entries into detectors (used by the policy loader)."""
    return [CustomRegexDetector.from_config(e) for e in entries]


__all__ += ["build_custom_detectors", "SpanGenerator"]
