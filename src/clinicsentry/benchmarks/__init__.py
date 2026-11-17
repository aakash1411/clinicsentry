"""Benchmark harnesses for measuring ClinicSentry controls against labelled data."""

from clinicsentry.benchmarks.phi import (
    HIPAA_CATEGORIES,
    BenchmarkDocument,
    BenchmarkReport,
    CategoryScore,
    GoldSpan,
    bundled_synthetic_dataset,
    evaluate_phi,
    load_brat,
    load_dataset,
    load_jsonl,
    normalize_label,
)

__all__ = [
    "HIPAA_CATEGORIES",
    "BenchmarkDocument",
    "BenchmarkReport",
    "CategoryScore",
    "GoldSpan",
    "bundled_synthetic_dataset",
    "evaluate_phi",
    "load_brat",
    "load_dataset",
    "load_jsonl",
    "normalize_label",
]
