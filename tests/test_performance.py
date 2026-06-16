"""Tests for performance utilities: LatencyBudget, scan_cache, timed."""

from __future__ import annotations

import time

from clinicsentry.performance import (
    BUDGETS_MS,
    LatencyBudget,
    scan_cache,
    timed,
)


def test_budgets_ms_includes_total_overhead_target() -> None:
    assert BUDGETS_MS["total"] == 50.0
    assert BUDGETS_MS["firewall.scan"] <= 20.0


def test_latency_budget_p95_zero_when_no_samples() -> None:
    b = LatencyBudget(name="x", budget_ms=10.0)
    assert b.p95() == 0.0


def test_latency_budget_records_and_computes_p95() -> None:
    b = LatencyBudget(name="x", budget_ms=10.0)
    for v in range(100):
        b.record(float(v))
    # p95 of 0..99 is around 94 (95th percentile).
    assert 90 <= b.p95() <= 99


def test_latency_budget_window_caps_history() -> None:
    b = LatencyBudget(name="x", budget_ms=10.0, window_size=10)
    for v in range(100):
        b.record(float(v))
    assert len(b._samples) == 10


def test_scan_cache_avoids_recomputation() -> None:
    calls: list[int] = []

    def scanner(payload: dict) -> dict:
        calls.append(1)
        return {"out": payload.get("v")}

    payload = {"v": "x"}
    scan_cache(scanner, payload)
    scan_cache(scanner, payload)
    scan_cache(scanner, payload)
    assert len(calls) == 1


def test_timed_decorator_records_into_budget() -> None:
    budget = LatencyBudget(name="t", budget_ms=1000.0)

    @timed(budget)
    def slow() -> int:
        time.sleep(0.01)
        return 42

    assert slow() == 42
    assert budget.p95() >= 5.0  # at least 5ms recorded
