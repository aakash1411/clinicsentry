"""PHI detection benchmark: recall, leakage and precision against gold spans.

Scores any detector, ``PHIFirewall`` or span callable against annotated text in
JSONL or BRAT standoff format (the format most public de-identification
corpora ship in or convert to, e.g. i2b2/n2c2 2014 and PhysioNet deid).

Labels on both sides are normalised to the 18 HIPAA Safe Harbor categories of
45 CFR §164.514(b)(2) before typed scoring. The headline metric is *leakage*:
a gold identifier counts as protected only if every character of it is covered
by some detection, of any type, because that is what decides whether PHI
leaves the boundary after redaction.

Reports contain counts and rates only, never document text or span values.
"""

from __future__ import annotations

import json
import statistics
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

__all__ = [
    "HIPAA_CATEGORIES",
    "BenchmarkDocument",
    "BenchmarkReport",
    "CategoryScore",
    "GoldSpan",
    "SpanPredictor",
    "bundled_synthetic_dataset",
    "evaluate_phi",
    "load_brat",
    "load_dataset",
    "load_jsonl",
    "normalize_label",
]

HIPAA_CATEGORIES: tuple[str, ...] = (
    "NAME",
    "GEOGRAPHIC",
    "DATE",
    "PHONE",
    "FAX",
    "EMAIL",
    "SSN",
    "MRN",
    "HEALTH_PLAN",
    "ACCOUNT",
    "LICENSE",
    "VEHICLE",
    "DEVICE",
    "URL",
    "IP_ADDRESS",
    "BIOMETRIC",
    "PHOTO",
    "OTHER_ID",
)

# Detector labels (ClinicSentry, Presidio, Comprehend Medical, LLM prompt) and
# common corpus labels (i2b2/n2c2 2014, PhysioNet deid) -> Safe Harbor category.
# Labels mapped to None are not Safe Harbor identifiers and are ignored.
_DEFAULT_LABEL_MAP: dict[str, str | None] = {
    # names
    "NAME": "NAME",
    "PERSON": "NAME",
    "PATIENT": "NAME",
    "DOCTOR": "NAME",
    "USERNAME": "NAME",
    "HCW": "NAME",
    "RELATIVE": "NAME",
    # geography / facilities
    "GEOGRAPHIC": "GEOGRAPHIC",
    "ADDRESS": "GEOGRAPHIC",
    "LOCATION": "GEOGRAPHIC",
    "LOCATION_OTHER": "GEOGRAPHIC",
    "GPE": "GEOGRAPHIC",
    "STREET": "GEOGRAPHIC",
    "CITY": "GEOGRAPHIC",
    "ZIP": "GEOGRAPHIC",
    "HOSPITAL": "GEOGRAPHIC",
    "FACILITY": "GEOGRAPHIC",
    "ROOM": "GEOGRAPHIC",
    "DEPARTMENT": "GEOGRAPHIC",
    "STATE": None,
    "COUNTRY": None,
    "ORGANIZATION": None,
    "PROFESSION": None,
    # dates
    "DATE": "DATE",
    "DATE_TIME": "DATE",
    "AGE": "DATE",
    # contact
    "PHONE": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "PHONE_OR_FAX": "PHONE",
    "DE_PHONE": "PHONE",
    "FAX": "FAX",
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "URL": "URL",
    "IP_ADDRESS": "IP_ADDRESS",
    "IPADDR": "IP_ADDRESS",
    # identifiers
    "SSN": "SSN",
    "US_SSN": "SSN",
    "ID": "OTHER_ID",
    "IDNUM": "OTHER_ID",
    "MRN": "MRN",
    "MEDICALRECORD": "MRN",
    "MEMBER_ID": "HEALTH_PLAN",
    "HEALTHPLAN": "HEALTH_PLAN",
    "ACCOUNT": "ACCOUNT",
    "IBAN": "ACCOUNT",
    "LICENSE": "LICENSE",
    "DEA": "LICENSE",
    "NPI": "LICENSE",
    "VIN": "VEHICLE",
    "VEHICLE": "VEHICLE",
    "DEVICE": "DEVICE",
    "DEVICE_ID": "DEVICE",
    "UDI": "DEVICE",
    "BIOID": "BIOMETRIC",
    "NHS_NUMBER": "OTHER_ID",
    "UK_NINO": "OTHER_ID",
    "CA_SIN": "OTHER_ID",
}

SpanPredictor = Callable[[str], Iterable[tuple[str, int, int]]]


def normalize_label(label: str, label_map: Mapping[str, str | None] | None = None) -> str | None:
    """Map a detector or corpus label to a Safe Harbor category (None = not PHI).

    ``label_map`` entries take precedence over the built-in table; unknown
    labels are kept upper-cased so they still count toward leakage.
    """
    key = label.strip().upper().replace("-", "_").replace(" ", "_")
    if label_map is not None:
        for raw, mapped in label_map.items():
            if raw.strip().upper().replace("-", "_").replace(" ", "_") == key:
                return mapped.upper() if mapped else None
    return _DEFAULT_LABEL_MAP.get(key, key)


@dataclass(frozen=True)
class GoldSpan:
    """One annotated identifier: ``text[start:end]`` with its corpus label."""

    start: int
    end: int
    label: str


@dataclass
class BenchmarkDocument:
    """A labelled text document."""

    doc_id: str
    text: str
    spans: list[GoldSpan] = field(default_factory=list)


@dataclass
class CategoryScore:
    """Per-category counts; rates are derived properties."""

    gold: int = 0
    protected: int = 0
    strict_hits: int = 0
    overlap_hits: int = 0

    @property
    def leakage_rate(self) -> float:
        """Fraction of gold spans not fully covered by any detection."""
        return 1 - self.protected / self.gold if self.gold else 0.0

    @property
    def strict_recall(self) -> float:
        """Exact boundaries and matching category."""
        return self.strict_hits / self.gold if self.gold else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize counts and rates."""
        return {
            "gold": self.gold,
            "protected": self.protected,
            "leaked": self.gold - self.protected,
            "leakage_rate": round(self.leakage_rate, 4),
            "strict_recall": round(self.strict_recall, 4),
            "overlap_recall": round(self.overlap_hits / self.gold, 4) if self.gold else 0.0,
        }


@dataclass
class BenchmarkReport:
    """Aggregate PHI benchmark result for one detector on one dataset."""

    detector: str
    dataset: str
    documents: int
    gold_spans: int
    protected_spans: int
    gold_chars: int
    covered_chars: int
    predicted_spans: int
    predicted_overlapping_gold: int
    strict_tp: int
    by_category: dict[str, CategoryScore]
    latency_ms: list[float] = field(default_factory=list, repr=False)

    @property
    def span_recall(self) -> float:
        """Gold spans fully covered by any detection (1 - leakage)."""
        return self.protected_spans / self.gold_spans if self.gold_spans else 1.0

    @property
    def leakage_rate(self) -> float:
        """Fraction of gold spans with at least one uncovered character."""
        return 1 - self.span_recall

    @property
    def char_recall(self) -> float:
        """Fraction of gold PHI characters covered by any detection."""
        return self.covered_chars / self.gold_chars if self.gold_chars else 1.0

    @property
    def precision(self) -> float:
        """Detections overlapping some gold span, label-agnostic."""
        if not self.predicted_spans:
            return 1.0
        return self.predicted_overlapping_gold / self.predicted_spans

    @property
    def strict_f1(self) -> float:
        """Typed exact-match F1."""
        if not self.strict_tp:
            return 0.0
        p = self.strict_tp / self.predicted_spans
        r = self.strict_tp / self.gold_spans
        return 2 * p * r / (p + r)

    def _latency(self, q: float) -> float:
        if not self.latency_ms:
            return 0.0
        ordered = sorted(self.latency_ms)
        return ordered[min(int(len(ordered) * q), len(ordered) - 1)]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe summary (no document text or span values)."""
        return {
            "detector": self.detector,
            "dataset": self.dataset,
            "documents": self.documents,
            "gold_spans": self.gold_spans,
            "predicted_spans": self.predicted_spans,
            "span_recall": round(self.span_recall, 4),
            "leakage_rate": round(self.leakage_rate, 4),
            "char_recall": round(self.char_recall, 4),
            "precision": round(self.precision, 4),
            "strict_f1": round(self.strict_f1, 4),
            "latency_ms": {
                "p50": round(statistics.median(self.latency_ms), 3) if self.latency_ms else 0.0,
                "p95": round(self._latency(0.95), 3),
            },
            "by_category": {k: v.to_dict() for k, v in sorted(self.by_category.items())},
        }

    def to_markdown(self) -> str:
        """Render a Markdown summary table."""
        d = self.to_dict()
        lines = [
            f"### PHI benchmark: `{self.detector}` on `{self.dataset}`",
            "",
            f"{self.documents} documents, {self.gold_spans} gold identifiers, "
            f"{self.predicted_spans} detections.",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Span recall (fully redacted) | {d['span_recall']:.2%} |",
            f"| Leakage rate | {d['leakage_rate']:.2%} |",
            f"| Character recall | {d['char_recall']:.2%} |",
            f"| Precision (overlap) | {d['precision']:.2%} |",
            f"| Strict typed F1 | {d['strict_f1']:.2%} |",
            f"| Latency p50 / p95 (ms/doc) | {d['latency_ms']['p50']} / {d['latency_ms']['p95']} |",
            "",
            "| Category | Gold | Leaked | Leakage | Strict recall |",
            "|---|---:|---:|---:|---:|",
        ]
        for name, row in d["by_category"].items():
            lines.append(
                f"| {name} | {row['gold']} | {row['leaked']} | {row['leakage_rate']:.2%} "
                f"| {row['strict_recall']:.2%} |"
            )
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_jsonl(path: str | Path) -> list[BenchmarkDocument]:
    """Load ``{"id", "text", "spans": [{"start", "end", "label"}]}`` lines.

    ``annotations`` / ``phi_type`` are accepted as aliases for ``spans`` /
    ``label``. Spans that fall outside the text raise ``ValueError``.
    """
    docs: list[BenchmarkDocument] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        text = str(row["text"])
        raw_spans = row.get("spans", row.get("annotations", []))
        spans = []
        for s in raw_spans:
            span = GoldSpan(int(s["start"]), int(s["end"]), str(s.get("label", s.get("phi_type"))))
            if not 0 <= span.start < span.end <= len(text):
                raise ValueError(f"{path}:{lineno}: span [{span.start}, {span.end}) out of range")
            spans.append(span)
        docs.append(BenchmarkDocument(str(row.get("id", f"doc-{lineno}")), text, spans))
    return docs


def load_brat(directory: str | Path) -> list[BenchmarkDocument]:
    """Load BRAT standoff pairs (``<id>.txt`` + ``<id>.ann``) from ``directory``.

    Only text-bound ``T`` annotations are read; discontinuous spans
    (``LABEL 0 4;9 12``) become one gold span per fragment.
    """
    docs: list[BenchmarkDocument] = []
    for txt in sorted(Path(directory).glob("*.txt")):
        text = txt.read_text(encoding="utf-8")
        ann = txt.with_suffix(".ann")
        spans: list[GoldSpan] = []
        if ann.exists():
            for line in ann.read_text(encoding="utf-8").splitlines():
                if not line.startswith("T"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                label, _, offsets = parts[1].partition(" ")
                for frag in offsets.split(";"):
                    start_s, _, end_s = frag.strip().partition(" ")
                    start, end = int(start_s), int(end_s)
                    if not 0 <= start < end <= len(text):
                        raise ValueError(f"{ann.name}: span [{start}, {end}) out of range")
                    spans.append(GoldSpan(start, end, label))
        docs.append(BenchmarkDocument(txt.stem, text, spans))
    return docs


def load_dataset(path: str | Path, fmt: str | None = None) -> list[BenchmarkDocument]:
    """Load a dataset, inferring the format (directory = BRAT, file = JSONL)."""
    p = Path(path)
    fmt = fmt or ("brat" if p.is_dir() else "jsonl")
    if fmt == "brat":
        return load_brat(p)
    if fmt == "jsonl":
        return load_jsonl(p)
    raise ValueError(f"unknown dataset format {fmt!r}; supported: brat, jsonl")


def bundled_synthetic_dataset() -> list[BenchmarkDocument]:
    """50 synthetic clinical notes (no real PHI) shipped with the package."""
    ref = resources.files("clinicsentry.benchmarks") / "data" / "synthetic_notes.jsonl"
    with resources.as_file(ref) as path:
        return load_jsonl(path)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _as_predictor(target: Any) -> SpanPredictor:
    if hasattr(target, "scan"):

        def from_firewall(text: str) -> Iterable[tuple[str, int, int]]:
            result = target.scan(text, origin_agent="phi-benchmark")
            return [(f.phi_type, f.start, f.end) for f in result.findings]

        return from_firewall
    if hasattr(target, "detect"):
        return lambda text: [(h.phi_type, h.start, h.end) for h in target.detect(text)]
    if callable(target):
        return target  # type: ignore[no-any-return]
    raise TypeError("target must have scan(), detect(), or be a span callable")


def evaluate_phi(
    target: Any,
    documents: Sequence[BenchmarkDocument],
    *,
    detector_name: str = "detector",
    dataset_name: str = "dataset",
    label_map: Mapping[str, str | None] | None = None,
) -> BenchmarkReport:
    """Score ``target`` (firewall, detector, or ``text -> [(label, start, end)]``)."""
    predict = _as_predictor(target)
    by_cat: dict[str, CategoryScore] = {}
    gold_total = protected = gold_chars = covered_chars = 0
    pred_total = pred_overlap = strict_tp = 0
    latencies: list[float] = []

    for doc in documents:
        t0 = time.perf_counter()
        raw = list(predict(doc.text))
        latencies.append((time.perf_counter() - t0) * 1000)
        preds = [
            (normalize_label(lbl, label_map), int(s), int(e))
            for lbl, s, e in raw
            if int(e) > int(s)
        ]
        golds = [
            (cat, g.start, g.end)
            for g in doc.spans
            if (cat := normalize_label(g.label, label_map)) is not None
        ]
        covered = [False] * len(doc.text)
        for _, s, e in preds:
            for i in range(max(s, 0), min(e, len(covered))):
                covered[i] = True

        pred_total += len(preds)
        pred_overlap += sum(
            1 for _, ps, pe in preds if any(ps < ge and gs < pe for _, gs, ge in golds)
        )
        exact = {(c, s, e) for c, s, e in preds}
        for cat, gs, ge in golds:
            score = by_cat.setdefault(cat, CategoryScore())
            score.gold += 1
            gold_total += 1
            n_cov = sum(covered[gs:ge])
            gold_chars += ge - gs
            covered_chars += n_cov
            if n_cov == ge - gs:
                score.protected += 1
                protected += 1
            if (cat, gs, ge) in exact:
                score.strict_hits += 1
                strict_tp += 1
            if any(c == cat and ps < ge and gs < pe for c, ps, pe in preds):
                score.overlap_hits += 1

    return BenchmarkReport(
        detector=detector_name,
        dataset=dataset_name,
        documents=len(documents),
        gold_spans=gold_total,
        protected_spans=protected,
        gold_chars=gold_chars,
        covered_chars=covered_chars,
        predicted_spans=pred_total,
        predicted_overlapping_gold=pred_overlap,
        strict_tp=strict_tp,
        by_category=by_cat,
        latency_ms=latencies,
    )
